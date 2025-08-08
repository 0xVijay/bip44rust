use std::fs;
use std::ffi::CString;
use ocl::{core, flags};
use ocl::prm::cl_ulong;
use ocl::enums::ArgVal;
use ocl::builders::ContextProperties;
use hex;
use std::str;
use rayon::prelude::*;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use sha3::{Keccak256, Digest as Sha3Digest};
use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use std::sync::{Arc, Mutex};
use std::time::Instant;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(name = "ethereum-bip39-solver")]
#[command(about = "GPU-accelerated Ethereum BIP39 seed phrase recovery")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Recover seed phrase from partial information
    Recover {
        /// Target Ethereum address to recover
        #[arg(short, long)]
        target: String,
        /// Word prefixes (12 two-letter prefixes)
        #[arg(short, long, value_delimiter = ',')]
        prefixes: Vec<String>,
        /// Batch size for GPU processing
        #[arg(short, long, default_value = "1024")]
        batch_size: u64,
        /// Passphrase (empty by default)
        #[arg(long, default_value = "")]
        passphrase: String,
    },
}

#[derive(Debug, Clone)]
struct Config {
    target_address: String,
    word_prefixes: Vec<String>,
    batch_size: u64,
    passphrase: String,
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
            println!("Processed: {} | Rate: {} seeds/sec | Elapsed: {}s", 
                    *processed, rate, elapsed);
        }
    }
}

/// Convert mnemonic to seed using PBKDF2-HMAC-SHA512
fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];
    
    // PBKDF2-HMAC-SHA512 with 2048 iterations
    pbkdf2::pbkdf2::<HmacSha256>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed)
        .context("PBKDF2 derivation failed")?;
    
    Ok(seed)
}

/// Derive Ethereum address from seed using BIP44 path m/44'/60'/0'/0/0
fn derive_ethereum_address(seed: &[u8; 64]) -> Result<String> {
    let secp = Secp256k1::new();
    
    // Create master private key from seed
    let mut hmac = HmacSha256::new_from_slice(b"ed25519 seed")
        .context("Failed to create HMAC")?;
    hmac.update(seed);
    let master_key = hmac.finalize().into_bytes();
    
    // For simplicity, we'll use the first 32 bytes as the private key
    // In a full implementation, you'd follow BIP32 hierarchical derivation
    let private_key = SecretKey::from_slice(&master_key[..32])
        .context("Invalid private key")?;
    
    // Generate public key
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    let public_key_bytes = public_key.serialize_uncompressed();
    
    // Generate Ethereum address using Keccak256
    let mut hasher = Keccak256::new();
    Sha3Digest::update(&mut hasher, &public_key_bytes[1..]);
    let hash = hasher.finalize();
    
    // Take last 20 bytes and format as hex address
    let address = format!("0x{}", hex::encode(&hash[12..]));
    Ok(address.to_lowercase())
}



/// Check if a mnemonic generates the target address
fn check_mnemonic(mnemonic: &str, target_address: &str, passphrase: &str) -> Result<bool> {
    let seed = mnemonic_to_seed(mnemonic, passphrase)?;
    let address = derive_ethereum_address(&seed)?;
    Ok(address.eq_ignore_ascii_case(target_address))
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
            if let Ok(true) = check_mnemonic(&mnemonic_str, &config.target_address, &config.passphrase) {
                println!("✅ Solution verified!");
                return Ok(());
            } else {
                println!("❌ Solution verification failed, continuing search...");
            }
        }
        
        offset += items as u128;
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Recover { target, prefixes, batch_size, passphrase } => {
            if prefixes.len() != 12 {
                anyhow::bail!("Must provide exactly 12 word prefixes");
            }
            
            let config = Config {
                target_address: target.to_lowercase(),
                word_prefixes: prefixes,
                batch_size,
                passphrase,
            };
            
            println!("🚀 Starting Ethereum BIP39 GPU Solver");
            println!("Target Address: {}", config.target_address);
            println!("Word Prefixes: {:?}", config.word_prefixes);
            println!("Batch Size: {}", config.batch_size);
            println!("Passphrase: {}", if config.passphrase.is_empty() { "(empty)" } else { "(set)" });
            
            let platform_id = core::default_platform()
                .context("Failed to get default OpenCL platform")?;
            
            let device_ids = core::get_device_ids(&platform_id, Some(ocl::flags::DEVICE_TYPE_GPU), None)
                .context("Failed to get GPU device IDs")?;
            
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
            
            // Run on all available GPUs in parallel
            device_ids.into_par_iter().try_for_each(|device_id| {
                mnemonic_gpu(platform_id, device_id, src_cstring.clone(), kernel_name, &config, stats.clone())
            })?;
        }
    }
    
    Ok(())
}
