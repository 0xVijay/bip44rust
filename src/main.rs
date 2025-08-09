use std::fs;
use std::ffi::CString;
use std::io::Write;
use ocl::{core, flags};
use hex;
use rayon::prelude::*;
use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use serde::{Deserialize, Serialize};
use bip39::Mnemonic;
use secp256k1::Secp256k1;
use sha2::Digest;
use sha3::Keccak256;
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::Network;
use std::str::FromStr;
use toml;

#[cfg(test)]
mod tests;




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
    total_candidates: Arc<Mutex<u64>>,
    start_time: Instant,
    last_update: Arc<Mutex<Instant>>,
}

impl Stats {
    fn new() -> Self {
        Self {
            processed: Arc::new(Mutex::new(0)),
            total_candidates: Arc::new(Mutex::new(0)),
            start_time: Instant::now(),
            last_update: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    fn set_total_candidates(&self, total: u64) {
        let mut total_candidates = self.total_candidates.lock().unwrap();
        *total_candidates = total;
    }

    fn add_processed(&self, count: u64) {
        let mut processed = self.processed.lock().unwrap();
        let mut last_update = self.last_update.lock().unwrap();
        *processed += count;
        
        // Update progress every 2 seconds or every 1M processed for better responsiveness
        let now = Instant::now();
        if now.duration_since(*last_update).as_secs() >= 2 || *processed % 1000000 == 0 {
            let elapsed = self.start_time.elapsed().as_secs();
            let total = *self.total_candidates.lock().unwrap();
            
            if elapsed > 0 && total > 0 {
                let rate = *processed / elapsed;
                let percentage = (*processed as f64 / total as f64) * 100.0;
                let remaining = if *processed < total { total - *processed } else { 0 };
                let eta_seconds = if rate > 0 && remaining > 0 { remaining / rate } else { 0 };
                
                // Use carriage return for single-line progress updates
                print!("\r🔍 GPU Progress: {}/{} ({:.2}%) | Rate: {} combinations/sec | ETA: {}h {}m {}s    ", 
                        *processed, total, percentage, rate,
                        eta_seconds / 3600, (eta_seconds % 3600) / 60, eta_seconds % 60);
                std::io::stdout().flush().unwrap();
            }
            *last_update = now;
        }
    }
}







/// GPU kernel execution for mnemonic checking
fn mnemonic_gpu(
    platform_id: core::types::abs::PlatformId,
    device_id: core::types::abs::DeviceId,
    src: CString,
    kernel_name: &str,
    config: &Config,
    stats: Arc<Stats>,
    _gpu_index: usize,
    candidates: Arc<Vec<String>>,
    found_solution: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use ocl::core::*;
    
    // Create OpenCL context and command queue
    let context_properties = ContextProperties::new().platform(platform_id);
    let context = core::create_context(Some(&context_properties), &[device_id], None, None)
        .context("Failed to create context")?;
    
    let queue = core::create_command_queue(&context, &device_id, None)
        .context("Failed to create command queue")?;
    
    // Build the program
    let program = core::create_program_with_source(&context, &[src])
        .context("Failed to create program")?;
    
    core::build_program(&program, Some(&[device_id]), &CString::new("").unwrap(), None, None)
        .context("Failed to build program")?;
    
    // Create the kernel
    let kernel = core::create_kernel(&program, kernel_name)
        .context("Failed to create kernel")?;
    
    let total_candidates = candidates.len();
    let batch_size = config.batch_size as usize;
    let processing_start = std::time::Instant::now();
    
    // Process candidates in batches
    for batch_start in (0..total_candidates).step_by(batch_size) {
        // Early termination if solution found by another thread
        if found_solution.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        
        let batch_end = std::cmp::min(batch_start + batch_size, total_candidates);
        let current_batch_size = batch_end - batch_start;
        
        // Prepare word indices buffer for this batch
        let mut word_indices_flat = Vec::with_capacity(current_batch_size * 12);
        for i in batch_start..batch_end {
            let candidate = &candidates[i];
            let word_indices = mnemonic_to_word_indices(candidate)?;
            word_indices_flat.extend_from_slice(&word_indices);
        }
        
        // Create OpenCL buffers
        let word_indices_buffer = unsafe {
            core::create_buffer(&context, flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR, 
                word_indices_flat.len(), Some(&word_indices_flat))
                .context("Failed to create word indices buffer")?
        };
        
        let results_buffer = unsafe {
            core::create_buffer(&context, flags::MEM_WRITE_ONLY, current_batch_size, None::<&[u32]>)
                .context("Failed to create results buffer")?
        };
        
        // Parse target address
        let target_address = config.ethereum.target_address.trim_start_matches("0x");
        let target_bytes = hex::decode(target_address)
            .context("Failed to decode target address")?;
        if target_bytes.len() != 20 {
            anyhow::bail!("Invalid Ethereum address length");
        }
        
        let target_buffer = unsafe {
            core::create_buffer(&context, flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR,
                target_bytes.len(), Some(&target_bytes))
                .context("Failed to create target address buffer")?
        };
        
        // Set kernel arguments
        core::set_kernel_arg(&kernel, 0, core::ArgVal::mem(&word_indices_buffer))?;
        core::set_kernel_arg(&kernel, 1, core::ArgVal::mem(&target_buffer))?;
        core::set_kernel_arg(&kernel, 2, core::ArgVal::mem(&results_buffer))?;
        
        // Execute kernel
        let global_work_size = [current_batch_size, 0, 0];
        println!("🔧 GPU {}: Executing kernel with {} work items", _gpu_index, current_batch_size);
        
        let kernel_start = std::time::Instant::now();
        unsafe {
            core::enqueue_kernel::<(), ()>(&queue, &kernel, 1, None, &global_work_size, None, None, None)
                .context("Failed to execute kernel")?
        };
        
        println!("🔧 GPU {}: Kernel execution took {:.2}ms", _gpu_index, kernel_start.elapsed().as_millis());
        
        // Read results
        let mut results = vec![0u32; current_batch_size];
        let read_start = std::time::Instant::now();
        unsafe {
            core::enqueue_read_buffer(&queue, &results_buffer, true, 0, &mut results, None::<()>, None::<()>)
                .context("Failed to read results")?
        };
        
        println!("🔧 GPU {}: Reading results took {:.2}ms", _gpu_index, read_start.elapsed().as_millis());
        println!("🔧 GPU {}: First 10 results: {:?}", _gpu_index, &results[..std::cmp::min(10, results.len())]);
        
        // Check for solutions
        for (i, &result) in results.iter().enumerate() {
            if result == 1 {
                let candidate_index = batch_start + i;
                let candidate_mnemonic = &candidates[candidate_index];
                
                // Verify the solution on CPU
                match check_mnemonic(candidate_mnemonic, &config.ethereum.passphrase, 
                                   &config.ethereum.derivation_path, &config.ethereum.target_address) {
                    Ok(true) => {
                        println!("\n🎉 SOLUTION FOUND! 🎉");
                        println!("Mnemonic: {}", candidate_mnemonic);
                        println!("Position: {} of {}", candidate_index + 1, total_candidates);
                        println!("Target Address: {}", config.ethereum.target_address);
                        println!("✅ Solution verified by both GPU and CPU!");
                        found_solution.store(true, std::sync::atomic::Ordering::Relaxed);
                        return Ok(());
                    }
                    Ok(false) => {
                        println!("⚠️  GPU found candidate '{}' but CPU verification failed", candidate_mnemonic);
                    }
                    Err(e) => {
                        println!("❌ Error verifying candidate '{}': {}", candidate_mnemonic, e);
                    }
                }
            }
        }
        
        // Check if another thread found a solution
        if found_solution.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        
        stats.add_processed(current_batch_size as u64);
        
        // Check for timeout (30 seconds per batch max)
        if processing_start.elapsed().as_secs() > 30 {
            println!("\n⚠️  GPU processing timeout detected. GPU may be too slow.");
            println!("💡 Consider using a more powerful GPU or reducing batch size.");
            return Err(anyhow::anyhow!("GPU processing timeout"));
        }
    }
    
    Ok(())
}

/// Validate BIP39 mnemonic checksum
fn is_valid_mnemonic(mnemonic: &str) -> bool {
    match Mnemonic::parse(mnemonic) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Convert mnemonic to BIP39 word indices
fn mnemonic_to_word_indices(mnemonic: &str) -> Result<Vec<u16>> {
    use bip39::Language;
    
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let mut indices = Vec::with_capacity(words.len());
    
    for word in words {
        // Find the index of this word in the BIP39 word list
        let word_list = Language::English.word_list();
        if let Some(index) = word_list.iter().position(|&w| w == word) {
            indices.push(index as u16);
        } else {
            return Err(anyhow::anyhow!("Word '{}' not found in BIP39 word list", word));
        }
    }
    
    Ok(indices)
}

/// Convert mnemonic to seed using PBKDF2-HMAC-SHA512
fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    let mnemonic = Mnemonic::parse(mnemonic)
        .context("Failed to parse mnemonic")?;
    
    let seed = mnemonic.to_seed(passphrase);
    Ok(seed)
}

/// Derive Ethereum address from seed using BIP44 path
fn derive_ethereum_address(seed: &[u8; 64], derivation_path: &str) -> Result<String> {
    let secp = Secp256k1::new();
    
    // Create master key from seed
    let master_key = Xpriv::new_master(Network::Bitcoin, seed)
        .context("Failed to create master key")?;
    
    // Parse derivation path
    let path = DerivationPath::from_str(derivation_path)
        .context("Failed to parse derivation path")?;
    
    // Derive private key
    let derived_key = master_key.derive_priv(&secp, &path)
        .context("Failed to derive private key")?;
    
    // Get public key
    let public_key = derived_key.private_key.public_key(&secp);
    
    // Convert to Ethereum address
    let public_key_bytes = public_key.serialize_uncompressed();
    let public_key_hash = Keccak256::digest(&public_key_bytes[1..]);
    let address = format!("0x{}", hex::encode(&public_key_hash[12..]));
    
    Ok(address.to_lowercase())
}

/// Check if mnemonic generates the target address
fn check_mnemonic(mnemonic: &str, passphrase: &str, derivation_path: &str, target_address: &str) -> Result<bool> {
    if !is_valid_mnemonic(mnemonic) {
        return Ok(false);
    }
    
    let seed = mnemonic_to_seed(mnemonic, passphrase)?;
    let address = derive_ethereum_address(&seed, derivation_path)?;
    
    Ok(address.to_lowercase() == target_address.to_lowercase())
}

/// Benchmark GPU performance with a small test
fn benchmark_gpu_performance(platform_id: core::types::abs::PlatformId, device_id: core::types::abs::DeviceId) -> Result<f64> {
    use ocl::core::*;
    
    // Simple test with 1000 candidates
    let _test_candidates = vec!["abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(); 1000];
    let start_time = std::time::Instant::now();
    
    // Create context and test kernel execution
    let context_properties = ContextProperties::new().platform(platform_id);
    let context = create_context(Some(&context_properties), &[device_id], None, None)?;
    let queue = create_command_queue(&context, &device_id, None)?;
    
    // Simple test kernel source
    let test_src = r#"
    __kernel void test_kernel(__global uint* input, __global uint* output, uint count) {
        uint id = get_global_id(0);
        if (id < count) {
            output[id] = input[id] * 2;  // Simple operation
        }
    }
    "#;
    
    let src_cstring = CString::new(test_src)?;
    let program = create_program_with_source(&context, &[src_cstring])?;
    build_program(&program, Some(&[device_id]), &CString::new("")?, None, None)?;
    let kernel = create_kernel(&program, "test_kernel")?;
    
    // Test data
    let test_data: Vec<u32> = (0..1000).collect();
    let input_buffer = unsafe {
        create_buffer(&context, flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR, 
            test_data.len(), Some(&test_data))?
    };
    let output_buffer = unsafe {
        create_buffer(&context, flags::MEM_WRITE_ONLY, test_data.len(), None::<&[u32]>)?
    };
    
    // Set kernel arguments and execute
    set_kernel_arg(&kernel, 0, ArgVal::mem(&input_buffer))?;
    set_kernel_arg(&kernel, 1, ArgVal::mem(&output_buffer))?;
    set_kernel_arg(&kernel, 2, ArgVal::scalar(&1000u32))?;
    
    let global_work_size = [1000, 0, 0];
    unsafe {
        enqueue_kernel::<(), ()>(&queue, &kernel, 1, None, &global_work_size, None, None, None)?;
    }
    
    // Wait for completion
    finish(&queue)?;
    
    let elapsed = start_time.elapsed();
    let ops_per_second = 1000.0 / elapsed.as_secs_f64();
    
    Ok(ops_per_second)
}

/// Detect OpenCL devices (GPUs and other compute devices)
fn detect_gpu_info() -> Result<(usize, f64)> {
    let platform_ids = core::get_platform_ids()
        .context("Failed to get OpenCL platforms")?;
    
    if platform_ids.is_empty() {
        return Ok((0, 0.0));
    }
    
    let mut device_count = 0;
    let mut total_memory = 0u64;
    
    for platform_id in &platform_ids {
        // Get platform info
        if let Ok(platform_info) = core::get_platform_info(*platform_id, core::PlatformInfo::Name) {
            if let core::PlatformInfoResult::Name(platform_name) = platform_info {
                println!("  Platform: {}", platform_name);
            }
        }
        
        // Try GPU devices first
        if let Ok(device_ids) = core::get_device_ids(*platform_id, Some(core::DeviceType::GPU), None) {
            for device_id in device_ids {
                device_count += 1;
                if let Ok(memory) = core::get_device_info(&device_id, core::DeviceInfo::GlobalMemSize) {
                    if let core::DeviceInfoResult::GlobalMemSize(mem_size) = memory {
                        total_memory += mem_size;
                        
                        // Get device name for detailed info
                        if let Ok(name_info) = core::get_device_info(&device_id, core::DeviceInfo::Name) {
                            if let core::DeviceInfoResult::Name(name) = name_info {
                                println!("    GPU {}: {} ({:.2} GB)", device_count, name, mem_size as f64 / (1024.0 * 1024.0 * 1024.0));
                            }
                        }
                    }
                }
            }
        }
        
        // If no GPUs, try all available devices
        if device_count == 0 {
            if let Ok(device_ids) = core::get_device_ids(*platform_id, Some(core::DeviceType::ALL), None) {
                for device_id in device_ids {
                    device_count += 1;
                    if let Ok(memory) = core::get_device_info(&device_id, core::DeviceInfo::GlobalMemSize) {
                        if let core::DeviceInfoResult::GlobalMemSize(mem_size) = memory {
                            total_memory += mem_size;
                            
                            // Get device name and type
                            let mut device_name = "Unknown".to_string();
                            if let Ok(name_info) = core::get_device_info(&device_id, core::DeviceInfo::Name) {
                                if let core::DeviceInfoResult::Name(name) = name_info {
                                    device_name = name;
                                }
                            }
                            
                            let mut device_type = "Unknown".to_string();
                            if let Ok(type_info) = core::get_device_info(&device_id, core::DeviceInfo::Type) {
                                if let core::DeviceInfoResult::Type(dtype) = type_info {
                                    device_type = format!("{:?}", dtype);
                                }
                            }
                            
                            println!("    Device {}: {} [{}] ({:.2} GB)", device_count, device_name, device_type, mem_size as f64 / (1024.0 * 1024.0 * 1024.0));
                        }
                    }
                }
            }
        }
    }
    
    Ok((device_count, total_memory as f64))
}

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

/// Calculate total search space combinations
fn calculate_total_combinations(config: &Config) -> Result<u64> {
    if config.word_constraints.is_empty() {
        return Ok(0);
    }
    
    let mut total: u64 = 1;
    for constraint in &config.word_constraints {
        if constraint.words.is_empty() {
            return Ok(0);
        }
        total = total.saturating_mul(constraint.words.len() as u64);
    }
    
    Ok(total)
}

/// Generate candidate mnemonics based on word constraints with BIP39 validation
fn generate_candidate_mnemonics(config: &Config) -> Result<Vec<String>> {
    if config.word_constraints.is_empty() {
        return Ok(Vec::new());
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
    
    println!("📊 Total combinations: {} | Using {} CPU cores", total_combinations, rayon::current_num_threads());
    
    // Generate combinations in parallel chunks for maximum speed
    let chunk_size = 50_000;
    let num_chunks = (total_combinations + chunk_size - 1) / chunk_size;
    
    let valid_candidates = Arc::new(Mutex::new(Vec::new()));
    let processed_count = Arc::new(AtomicU64::new(0));
    let start_time = std::time::Instant::now();
    
    (0..num_chunks).into_par_iter().for_each(|chunk_idx| {
        let start_idx = chunk_idx * chunk_size;
        let end_idx = std::cmp::min((chunk_idx + 1) * chunk_size, total_combinations);
        
        let mut chunk_valid = Vec::new();
        
        for combo_idx in start_idx..end_idx {
            // Convert linear index to word combination
            let mut temp_idx = combo_idx;
            let mut word_indices = vec![0usize; config.mnemonic_length];
            
            for pos in (0..config.mnemonic_length).rev() {
                let num_words = word_options[pos].len() as u64;
                word_indices[pos] = (temp_idx % num_words) as usize;
                temp_idx /= num_words;
            }
            
            // Build mnemonic
            let mnemonic: String = word_indices.iter()
                .enumerate()
                .map(|(pos, &word_idx)| word_options[pos][word_idx].clone())
                .collect::<Vec<_>>()
                .join(" ");
            
            // Validate BIP39 checksum
            if is_valid_mnemonic(&mnemonic) {
                chunk_valid.push(mnemonic);
            }
            
            // Update progress on same line (thread-safe)
            let current_processed = processed_count.fetch_add(1, Ordering::Relaxed) + 1;
            if current_processed % 50_000 == 0 {
                // Use atomic operation for thread-safe progress updates
                static LAST_PROGRESS_UPDATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let last_update = LAST_PROGRESS_UPDATE.load(Ordering::Relaxed);
                if current_processed.saturating_sub(last_update) >= 50_000 {
                    if LAST_PROGRESS_UPDATE.compare_exchange(last_update, current_processed, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                        let progress = (current_processed as f64 / total_combinations as f64) * 100.0;
                        let elapsed = start_time.elapsed().as_secs_f64();
                        let rate = current_processed as f64 / elapsed;
                        eprint!("\r🔍 Progress: {:.1}% ({}/{}) | Rate: {:.0}/s | Valid: {}    ", 
                               progress, current_processed, total_combinations, rate, 
                               valid_candidates.lock().unwrap().len());
                    }
                }
            }
        }
        
        // Add valid candidates to global list
        if !chunk_valid.is_empty() {
            valid_candidates.lock().unwrap().extend(chunk_valid);
        }
    });
    
    println!(); // New line after progress
    
    let final_candidates = Arc::try_unwrap(valid_candidates).unwrap().into_inner().unwrap();
    let total_processed = processed_count.load(Ordering::Relaxed);
    let efficiency = if total_processed > 0 {
        (final_candidates.len() as f64 / total_processed as f64) * 100.0
    } else {
        0.0
    };
    
    let elapsed = start_time.elapsed();
    println!("✅ Completed in {:.2}s | Efficiency: {:.2}% ({} valid / {} total)", 
             elapsed.as_secs_f64(), efficiency, final_candidates.len(), total_processed);
    
    Ok(final_candidates)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Recover { config: config_path, batch_size } => {
            println!("🚀 Starting Ethereum BIP39 GPU Solver");
            
            // Detect and display GPU information first
            let (gpu_count, total_memory) = detect_gpu_info()?;
            println!("🔍 Detected {} GPU device(s) with total memory: {:.2} GB", gpu_count, total_memory / (1024.0 * 1024.0 * 1024.0));
            
            // Benchmark GPU performance to determine if it's worth using
            let mut use_gpu = false;
            let mut _gpu_performance = 0.0;
            
            if gpu_count > 0 {
                println!("🧪 Benchmarking GPU performance...");
                let platform_ids = core::get_platform_ids().context("Failed to get platforms")?;
                
                for &platform_id in &platform_ids {
                    // Try GPU devices first, then fallback to ALL devices
                    let devices = core::get_device_ids(platform_id, Some(core::DeviceType::GPU), None)
                        .or_else(|_| core::get_device_ids(platform_id, Some(core::DeviceType::ALL), None));
                        
                    if let Ok(devices) = devices {
                        if !devices.is_empty() {
                            match benchmark_gpu_performance(platform_id, devices[0]) {
                                Ok(perf) => {
                                    _gpu_performance = perf;
                                    println!("  GPU Performance: {:.0} operations/sec", perf);
                                    // Use GPU if it can do at least 1000 ops/sec (adjust threshold as needed)
                                    if perf >= 1000.0 {
                                        use_gpu = true;
                                        println!("✅ GPU performance is adequate, will use GPU acceleration");
                                    } else {
                                        println!("❌ GPU performance is too low ({:.0} ops/sec), stopping process", perf);
                                        println!("💡 Consider using a more powerful GPU or try a different OpenCL device");
                                        return Ok(());
                                    }
                                    break;
                                }
                                Err(e) => {
                                    println!("❌ GPU benchmark failed: {}", e);
                                }
                            }
                        }
                    }
                }
            }
            
            if !use_gpu {
                println!("❌ No suitable GPU found or GPU performance insufficient");
                println!("💡 This program requires a GPU with adequate OpenCL performance");
                return Ok(());
            }
            
            // Load configuration
            let config_str = fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read config file: {}", config_path))?;
            
            let mut config: Config = toml::from_str(&config_str)
                .context("Failed to parse config file")?;
            
            let final_batch_size = if batch_size == 1024 {
                // Auto-detect optimal batch size based on GPU memory when using default
                match detect_optimal_batch_size() {
                    Ok(optimal_size) => {
                        println!("🔧 Auto-detected optimal batch size: {} (per GPU)", optimal_size);
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
            println!("Batch Size per GPU: {}", config.batch_size);
            println!("Total Batch Size: {}", config.batch_size * gpu_count as u64);
            println!("Passphrase: {}", if config.ethereum.passphrase.is_empty() { "(empty)" } else { "(provided)" });
            
            // Calculate total search space for accurate progress tracking
            let total_search_space = calculate_total_combinations(&config)
            .context("Failed to calculate total combinations")?;
            
            println!("📊 Total search space: {} combinations", total_search_space);
            
            // Generate candidate mnemonics with BIP39 validation
            println!("🔍 Generating candidates for GPU processing...");
            let candidates = generate_candidate_mnemonics(&config)
                .context("Failed to generate candidate mnemonics")?;
            
            if candidates.is_empty() {
                println!("❌ No candidate mnemonics generated!");
                return Ok(());
            }
            
            println!("✅ Generated {} candidate mnemonics for GPU processing", candidates.len());
            
            // Estimate completion time based on total search space
            let estimated_rate = config.batch_size * gpu_count as u64; // Conservative estimate
            let estimated_time_seconds = total_search_space / estimated_rate;
            println!("📊 Estimated completion time: {}h {}m {}s (at {} combinations/sec)",
                estimated_time_seconds / 3600,
                (estimated_time_seconds % 3600) / 60,
                estimated_time_seconds % 60,
                estimated_rate);
            
            // GPU-only processing
            println!("🚀 Starting GPU processing...");
            
            let found_solution = Arc::new(std::sync::atomic::AtomicBool::new(false));
            
            // Get OpenCL platforms and devices
            let platform_ids = core::get_platform_ids()
                .context("Failed to get OpenCL platform IDs")?;
            
            if platform_ids.is_empty() {
                return Err(anyhow::anyhow!("No OpenCL platforms found"));
            }
            
            let mut gpu_found = false;
            
            for &platform_id in &platform_ids {
                // Try GPU devices first, then fallback to ALL devices
                let devices = core::get_device_ids(platform_id, Some(core::DeviceType::GPU), None)
                    .or_else(|_| core::get_device_ids(platform_id, Some(core::DeviceType::ALL), None))
                    .context("Failed to get device IDs")?;
                
                if devices.is_empty() {
                    continue;
                }
                
                println!("✅ Found {} GPU device(s) on platform", devices.len());
                
                // Load metal compatible kernel
                let src = CString::new(fs::read_to_string("cl/metal_compatible.cl")?)?;
                
                // Process candidates on all available GPUs
                let candidates_per_gpu = candidates.len() / devices.len();
                let mut handles = Vec::new();
                
                for (gpu_index, &device_id) in devices.iter().enumerate() {
                     let start_idx = gpu_index * candidates_per_gpu;
                     let end_idx = if gpu_index == devices.len() - 1 {
                         candidates.len() // Last GPU gets remaining candidates
                     } else {
                         (gpu_index + 1) * candidates_per_gpu
                     };
                     
                     let gpu_candidates = candidates[start_idx..end_idx].to_vec();
                     let candidates_arc = Arc::new(gpu_candidates);
                     let stats = Arc::new(Stats::new());
                     stats.set_total_candidates(candidates_arc.len() as u64);
                     
                     let config_clone = config.clone();
                     let src_clone = src.clone();
                     let found_solution_clone = Arc::clone(&found_solution);
                     
                     println!("🚀 Starting GPU {} with {} candidates", gpu_index, candidates_arc.len());
                     
                     let handle = std::thread::spawn(move || {
                         if let Err(e) = mnemonic_gpu(platform_id, device_id, src_clone, "metal_compatible", 
                                                     &config_clone, stats, gpu_index, candidates_arc, found_solution_clone) {
                             eprintln!("GPU {} processing error: {}", gpu_index, e);
                         }
                     });
                     
                     handles.push(handle);
                 }
                
                // Wait for all GPU threads to complete
                for (i, handle) in handles.into_iter().enumerate() {
                    if let Err(e) = handle.join() {
                        eprintln!("GPU {} thread error: {:?}", i, e);
                    }
                }
                
                gpu_found = true;
                break;
            }
            
            if !gpu_found {
                return Err(anyhow::anyhow!("No suitable GPU devices found for processing"));
            }
            
            if !found_solution.load(std::sync::atomic::Ordering::Relaxed) {
                println!("❌ No solution found in {} candidates", candidates.len());
                println!("💡 This could mean:");
                println!("   - The target address doesn't match any of the generated candidates");
                println!("   - The word constraints are too restrictive");
                println!("   - The derivation path or passphrase is incorrect");
            }
        }
    }
    
    Ok(())
}
