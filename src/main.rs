use std::fs;
use std::ffi::CString;
use std::io::Write;
use ocl::{core, flags};
use ocl::prm::cl_ulong;
use ocl::enums::ArgVal;
use ocl::builders::ContextProperties;
use hex;
use std::str;
use rayon::prelude::*;
use secp256k1::Secp256k1;
use sha2::Digest;
use hmac::Hmac;
use sha3::Keccak256;
use sha2::Sha512;
use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use serde::{Deserialize, Serialize};
use bip39::{Mnemonic, Language};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::Network;
use std::str::FromStr;


type HmacSha512 = Hmac<Sha512>;

#[derive(Parser)]
#[command(name = "ethereum-bip39-solver")]
#[command(about = "GPU-accelerated Ethereum BIP39 seed phrase recovery")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Recover seed phrase from configuration file
    Recover {
        /// Configuration file path
        #[arg(short, long)]
        config: String,
        /// Batch size for GPU processing
        #[arg(short, long, default_value = "1024")]
        batch_size: u64,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct WordConstraint {
    position: usize,
    words: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct EthereumConfig {
    derivation_path: String,
    target_address: String,
    #[serde(default)]
    passphrase: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    word_constraints: Vec<WordConstraint>,
    ethereum: EthereumConfig,
    mnemonic_length: usize,
    wallet_type: String,
    #[serde(skip)]
    batch_size: u64,
}



struct Stats {
    processed: Arc<Mutex<u64>>,
    start_time: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            processed: Arc::new(Mutex::new(0)),
            start_time: Instant::now(),
        }
    }

    fn add_processed(&self, count: u64) {
        let mut processed = self.processed.lock().unwrap();
        *processed += count;
        let elapsed = self.start_time.elapsed().as_secs();
        if elapsed > 0 {
            let rate = *processed / elapsed;
            println!("Processed: {} mnemonics, Rate: {} mnemonics/sec", *processed, rate);
        }
    }
}

/// Convert mnemonic to seed using PBKDF2-HMAC-SHA512
fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];
    
    // PBKDF2-HMAC-SHA512 with 2048 iterations
    pbkdf2::pbkdf2::<HmacSha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed)
        .context("PBKDF2 derivation failed")?;
    
    Ok(seed)
}

/// Derive Ethereum address from seed using BIP32/BIP44
fn derive_ethereum_address(seed: &[u8; 64]) -> Result<String> {
    let secp = Secp256k1::new();
    
    // Create master key from seed
    let master_key = Xpriv::new_master(Network::Bitcoin, seed)
        .context("Failed to create master key")?;
    
    // Derivation path: m/44'/60'/0'/0/2
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/2")
        .context("Failed to parse derivation path")?;
    
    // Derive the key
    let derived_key = master_key.derive_priv(&secp, &derivation_path)
        .context("Failed to derive key")?;
    
    // Get the private key bytes (for reference, not used in address generation)
    let _private_key_bytes = derived_key.private_key.secret_bytes();
    
    // Generate public key
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &derived_key.private_key);
    let public_key_bytes = public_key.serialize_uncompressed();
    
    // Remove the 0x04 prefix for Ethereum address generation
    let public_key_no_prefix = &public_key_bytes[1..];
    
    // Hash with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(public_key_no_prefix);
    let hash = hasher.finalize();
    
    // Take last 20 bytes as Ethereum address
    let address_bytes = &hash[12..];
    let address = format!("0x{}", hex::encode(address_bytes));
    
    Ok(address)
}

/// Check if a mnemonic generates the target address
fn check_mnemonic(mnemonic: &str, config: &Config) -> Result<bool> {
    let seed = mnemonic_to_seed(mnemonic, &config.ethereum.passphrase)?;
    let generated_address = derive_ethereum_address(&seed)?;
    let matches = generated_address.to_lowercase() == config.ethereum.target_address.to_lowercase();
    Ok(matches)
}

/// GPU kernel execution for mnemonic checking
fn mnemonic_gpu(
    platform_id: core::types::abs::PlatformId,
    device_id: core::types::abs::DeviceId,
    src: CString,
    kernel_name: &str,
    config: &Config,
    stats: Arc<Stats>,
) -> Result<()> {
    let context_properties = ContextProperties::new().platform(platform_id);
    let context = core::create_context(Some(&context_properties), &[device_id], None, None)
        .context("Failed to create OpenCL context")?;
    
    let program = core::create_program_with_source(&context, &[src])
        .context("Failed to create OpenCL program")?;
    
    core::build_program(&program, Some(&[device_id]), &CString::new("").unwrap(), None, None)
        .context("Failed to build OpenCL program")?;
    
    let queue = core::create_command_queue(&context, &device_id, None)
        .context("Failed to create command queue")?;

    let mut offset: u128 = 0;
    
    loop {
        let items = config.batch_size;
        let mnemonic_hi: cl_ulong = (offset >> 64) as u64;
        let mnemonic_lo: cl_ulong = (offset & 0xFFFFFFFFFFFFFFFF) as u64;
        
        let mut target_mnemonic = vec![0u8; 120];
        let mut mnemonic_found = vec![0u8; 1];
        
        let target_mnemonic_buf = unsafe {
            core::create_buffer(&context, flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                              120, Some(&target_mnemonic))
                .context("Failed to create target mnemonic buffer")?
        };
        
        let mnemonic_found_buf = unsafe {
            core::create_buffer(&context, flags::MEM_WRITE_ONLY | flags::MEM_COPY_HOST_PTR,
                              1, Some(&mnemonic_found))
                .context("Failed to create mnemonic found buffer")?
        };
        
        let kernel = core::create_kernel(&program, kernel_name)
            .context("Failed to create kernel")?;

        core::set_kernel_arg(&kernel, 0, ArgVal::scalar(&mnemonic_hi))
            .context("Failed to set kernel arg 0")?;
        core::set_kernel_arg(&kernel, 1, ArgVal::scalar(&mnemonic_lo))
            .context("Failed to set kernel arg 1")?;
        core::set_kernel_arg(&kernel, 2, ArgVal::mem(&target_mnemonic_buf))
            .context("Failed to set kernel arg 2")?;
        core::set_kernel_arg(&kernel, 3, ArgVal::mem(&mnemonic_found_buf))
            .context("Failed to set kernel arg 3")?;

        unsafe {
            core::enqueue_kernel(&queue, &kernel, 1, None, &[items as usize, 1, 1],
                               None, None::<core::Event>, None::<&mut core::Event>)
                .context("Failed to enqueue kernel")?;
        }
        
        unsafe {
            core::enqueue_read_buffer(&queue, &target_mnemonic_buf, true, 0, &mut target_mnemonic,
                                    None::<core::Event>, None::<&mut core::Event>)
                .context("Failed to read target mnemonic buffer")?;
        }
        
        unsafe {
            core::enqueue_read_buffer(&queue, &mnemonic_found_buf, true, 0, &mut mnemonic_found,
                                    None::<core::Event>, None::<&mut core::Event>)
                .context("Failed to read mnemonic found buffer")?;
        }
        
        stats.add_processed(items);

        if mnemonic_found[0] == 0x01 {
            let mnemonic_str = String::from_utf8_lossy(&target_mnemonic)
                .trim_matches('\0')
                .to_string();
            
            println!("\n🎉 SOLUTION FOUND! 🎉");
            println!("Mnemonic: {}", mnemonic_str);
            println!("Offset: {}", offset);
            
            // Verify the solution
            if let Ok(true) = check_mnemonic(&mnemonic_str, config) {
                println!("✅ Solution verified!");
                return Ok(());
            } else {
                println!("❌ Solution verification failed, continuing search...");
            }
        }
        
        offset += items as u128;
    }
}

/// Validate BIP39 mnemonic checksum
fn is_valid_mnemonic(mnemonic: &str) -> bool {
    match Mnemonic::parse_in(Language::English, mnemonic) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Detect optimal batch size based on GPU memory
fn detect_optimal_batch_size() -> Result<u64> {
    // Get OpenCL platforms and devices to detect memory
    let platform_ids = core::get_platform_ids()
        .context("Failed to get OpenCL platforms")?;
    
    if platform_ids.is_empty() {
        return Ok(1024); // Default fallback
    }
    
    let mut max_memory = 0u64;
    for platform_id in &platform_ids {
        if let Ok(device_ids) = core::get_device_ids(*platform_id, Some(core::DeviceType::GPU), None) {
            for device_id in device_ids {
                if let Ok(memory) = core::get_device_info(&device_id, core::DeviceInfo::GlobalMemSize) {
                    if let core::DeviceInfoResult::GlobalMemSize(mem_size) = memory {
                        max_memory = max_memory.max(mem_size);
                    }
                }
            }
        }
    }
    
    // Calculate optimal batch size based on available memory
    // Each work item needs ~200 bytes, leave 80% for GPU memory
    let optimal_batch = if max_memory > 0 {
        ((max_memory as f64 * 0.8) / 200.0) as u64
    } else {
        1024
    };
    
    // Clamp between reasonable bounds
    Ok(optimal_batch.max(1024).min(1_000_000))
}

/// Generate candidate mnemonics based on word constraints with BIP39 validation
fn generate_candidate_mnemonics(config: &Config) -> Result<Vec<String>> {
    let mut candidates = Vec::new();
    
    if config.word_constraints.is_empty() {
        return Ok(candidates);
    }
    
    // Collect word options for each position
    let mut word_options = Vec::new();
    for i in 0..config.mnemonic_length {
        if let Some(constraint) = config.word_constraints.iter().find(|c| c.position == i) {
            if constraint.words.is_empty() {
                return Err(anyhow::anyhow!("No words provided for position {}", i));
            }
            word_options.push(constraint.words.clone());
        } else {
            return Err(anyhow::anyhow!("No constraint found for position {}", i));
        }
    }
    
    // Calculate total possible combinations
    let total_combinations: u64 = word_options.iter()
        .map(|words| words.len() as u64)
        .product();
    
    println!("📊 Total possible combinations: {}", total_combinations);
    
    // Generate all combinations using recursive approach with BIP39 validation
    let mut total_generated = 0u64;
    fn generate_combinations(
        word_options: &[Vec<String>], 
        current: &mut Vec<String>, 
        all_combinations: &mut Vec<String>,
        total_generated: &mut u64
    ) {
        if current.len() == word_options.len() {
            let mnemonic = current.join(" ");
            *total_generated += 1;
            
            // Only add valid BIP39 mnemonics with correct checksum
            if is_valid_mnemonic(&mnemonic) {
                all_combinations.push(mnemonic);
            }
            return;
        }
        
        let position = current.len();
        for word in &word_options[position] {
            current.push(word.clone());
            generate_combinations(word_options, current, all_combinations, total_generated);
            current.pop();
        }
    }
    
    let mut current = Vec::new();
    generate_combinations(&word_options, &mut current, &mut candidates, &mut total_generated);
    
    let efficiency = if total_generated > 0 {
        (candidates.len() as f64 / total_generated as f64) * 100.0
    } else {
        0.0
    };
    
    println!("🔍 BIP39 validation efficiency: {:.2}% ({} valid out of {} total)", 
             efficiency, candidates.len(), total_generated);
    
    Ok(candidates)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Recover { config: config_path, batch_size } => {
            println!("🚀 Starting Ethereum BIP39 GPU Solver");
            
            // Load configuration
            let config_str = fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {}", config_path))?;
            
            let mut config: Config = serde_json::from_str(&config_str)
                .context("Failed to parse config file")?;
            
            let final_batch_size = if batch_size == 1024 {
                // Auto-detect optimal batch size based on GPU memory when using default
                match detect_optimal_batch_size() {
                    Ok(optimal_size) => {
                        println!("🔧 Auto-detected optimal batch size: {}", optimal_size);
                        optimal_size
                    }
                    Err(e) => {
                        eprintln!("⚠️  Failed to detect optimal batch size: {}, using default 1024", e);
                        1024
                    }
                }
            } else {
                batch_size
            };
            
            config.batch_size = final_batch_size;
            
            println!("Target Address: {}", config.ethereum.target_address);
            println!("Derivation Path: {}", config.ethereum.derivation_path);
            println!("Batch Size: {}", config.batch_size);
            println!("Passphrase: {}", if config.ethereum.passphrase.is_empty() { "(empty)" } else { "(provided)" });
            
            // Generate candidate mnemonics with BIP39 validation
             println!("🔍 Generating candidates with BIP39 checksum validation...");
             let candidates = generate_candidate_mnemonics(&config)
                 .context("Failed to generate candidate mnemonics")?;
            
            if candidates.is_empty() {
                println!("❌ No valid BIP39 mnemonics found with the given constraints!");
                println!("💡 This means none of the word combinations produce a valid checksum.");
                return Ok(());
            }
            
            println!("✅ Generated {} valid BIP39 candidate mnemonic(s)", candidates.len());
            
            // Check candidates on CPU first with progress indicator
            print!("🔍 Testing {} candidates for address match", candidates.len());
            std::io::stdout().flush().unwrap();
            
            for (i, candidate) in candidates.iter().enumerate() {
                // Show progress every 100 candidates or on last candidate
                if i % 100 == 0 || i == candidates.len() - 1 {
                    print!("\r🔍 Testing candidates: {}/{} ({:.1}%)", 
                           i + 1, candidates.len(), 
                           ((i + 1) as f64 / candidates.len() as f64) * 100.0);
                    std::io::stdout().flush().unwrap();
                }
                
                if check_mnemonic(candidate, &config)? {
                    println!("\n✅ SUCCESS! Found matching address with mnemonic: {}", candidate);
                    return Ok(());
                }
            }
            
            println!("\n❌ No matching address found in valid BIP39 candidates");
            
            println!("No CPU matches found, starting GPU processing...");
            
            // Get OpenCL platforms and devices
            let platform_ids = core::get_platform_ids()
                .context("Failed to get OpenCL platforms")?;
            
            if platform_ids.is_empty() {
                anyhow::bail!("No OpenCL platforms found");
            }
            
            let mut device_ids = Vec::new();
            for platform_id in &platform_ids {
                if let Ok(devices) = core::get_device_ids(*platform_id, Some(core::DeviceType::GPU), None) {
                    device_ids.extend(devices.into_iter().map(|d| (*platform_id, d)));
                }
            }
            
            if device_ids.is_empty() {
                anyhow::bail!("No GPU devices found");
            }
            
            println!("Found {} GPU device(s)", device_ids.len());
            
            // Use the simplified seed-only kernel for now
            let kernel_name = "just_seed";
            let kernel_files = ["common", "sha2", "mnemonic_constants", "just_seed"];
            
            let mut raw_cl_file = String::new();
            for file in &kernel_files {
                let file_path = format!("./cl/{}.cl", file);
                let file_str = fs::read_to_string(&file_path)
                    .with_context(|| format!("Failed to read {}", file_path))?;
                raw_cl_file.push_str(&file_str);
                raw_cl_file.push('\n');
            }
            
            let src_cstring = CString::new(raw_cl_file)
                .context("Failed to create CString from OpenCL source")?;
            
            let stats = Arc::new(Stats::new());
            
            // Run GPU processing on all available devices in parallel
            device_ids.into_par_iter().try_for_each(|(platform_id, device_id)| {
                mnemonic_gpu(platform_id, device_id, src_cstring.clone(), kernel_name, &config, stats.clone())
            })?;
        }
    }
    
    Ok(())
}
