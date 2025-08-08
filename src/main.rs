//! Main application for GPU-accelerated seed phrase recovery
//!
//! This binary provides a command-line interface for recovering Ethereum seed phrases
//! using GPU acceleration with OpenCL.

use ethereum_seed_recovery::recovery::RecoveryConfig;
use ethereum_seed_recovery::generator::CandidateGenerator;
use ethereum_seed_recovery::ethereum::EthereumGenerator;
use ethereum_seed_recovery::crypto::CryptoEngine;
use ethereum_seed_recovery::opencl::OpenCLContext;
use ethereum_seed_recovery::monitor::{RecoveryMonitor, MonitorConfig, Checkpoint};
use ethereum_seed_recovery::error::Result;
use clap::{Arg, Command};
use log::{info, error, warn};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use anyhow::Context;
use serde_json;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let matches = Command::new("eth-seed-recovery")
        .version(env!("CARGO_PKG_VERSION"))
        .about("High-performance Ethereum seed phrase recovery tool")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .required(true),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for results")
                .default_value("recovery_results.json"),
        )
        .arg(
            Arg::new("checkpoint")
                .long("checkpoint")
                .value_name("FILE")
                .help("Checkpoint file for resuming")
                .default_value("recovery_checkpoint.json"),
        )
        .arg(
            Arg::new("resume")
                .long("resume")
                .help("Resume from checkpoint")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Perform a dry run without actual recovery")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose logging")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let checkpoint_path = matches.get_one::<String>("checkpoint").unwrap();
    let resume = matches.get_flag("resume");
    let dry_run = matches.get_flag("dry-run");
    let verbose = matches.get_flag("verbose");

    if verbose {
        info!("Starting Ethereum seed recovery tool");
        info!("Config: {}", config_path);
        info!("Output: {}", output_path);
        info!("Checkpoint: {}", checkpoint_path);
    }

    // Load configuration
    let config = load_config(config_path).await
        .context("Failed to load configuration")?;
    
    if verbose {
        info!("Configuration loaded successfully");
        info!("Mnemonic length: {}", config.mnemonic_length);
        info!("Wallet type: {}", config.wallet_type);
        info!("Target address: {}", config.ethereum.target_address);
        info!("Derivation path: {}", config.ethereum.derivation_path);
        info!("Search space: {}", config.calculate_search_space());
    }

    if dry_run {
        info!("Dry run mode - performing validation only");
        return perform_dry_run(&config).await;
    }

    // Initialize components
    let generator = CandidateGenerator::new(&config)
        .context("Failed to create candidate generator")?;
    
    let crypto_engine = CryptoEngine::new();
    let ethereum_generator = EthereumGenerator::new();
    
    // Initialize OpenCL context if GPU is enabled
    let opencl_context = if config.use_gpu {
        match OpenCLContext::new(Default::default()) {
            Ok(ctx) => {
                info!("OpenCL context initialized successfully");
                if verbose {
                    info!("OpenCL context created successfully");
                }
                Some(Arc::new(ctx))
            }
            Err(e) => {
                warn!("Failed to initialize OpenCL: {}. Falling back to CPU.", e);
                None
            }
        }
    } else {
        info!("GPU acceleration disabled, using CPU only");
        None
    };

    // Initialize monitor
    let monitor_config = MonitorConfig::default();
    let monitor = Arc::new(Mutex::new(
        RecoveryMonitor::new(config.calculate_search_space(), monitor_config)
    ));

    // Resume from checkpoint if requested
    if resume {
        if let Ok(checkpoint_data) = fs::read_to_string(checkpoint_path) {
            if let Ok(checkpoint) = serde_json::from_str(&checkpoint_data) {
                monitor.lock().await.restore_from_checkpoint(&checkpoint);
                info!("Resumed from checkpoint");
            } else {
                warn!("Failed to parse checkpoint file, starting fresh");
            }
        } else {
            warn!("Checkpoint file not found, starting fresh");
        }
    }

    // Start recovery process
    let result = if let Some(opencl_ctx) = opencl_context {
        info!("Starting GPU-accelerated recovery...");
        
        match run_gpu_recovery(&config, &generator, &crypto_engine, &ethereum_generator, 
                              &opencl_ctx, &monitor, checkpoint_path).await {
            Ok(result) => {
                info!("GPU recovery completed successfully");
                Ok(result)
            }
            Err(e) => {
                warn!("GPU recovery failed: {}, falling back to CPU", e);
                run_cpu_recovery(&config, &generator, &crypto_engine, &ethereum_generator, 
                                &monitor, checkpoint_path).await
            }
        }
    } else {
        run_cpu_recovery(&config, &generator, &crypto_engine, &ethereum_generator, 
                        &monitor, checkpoint_path).await
    };

    match result {
        Ok(Some(found_mnemonic)) => {
            info!("SUCCESS: Found matching seed phrase!");
            info!("Mnemonic: {}", found_mnemonic);
            
            // Save result
            let result_data = serde_json::json!({
                "success": true,
                "mnemonic": found_mnemonic,
                "target_address": config.ethereum.target_address,
                "derivation_path": config.ethereum.derivation_path,
                "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                "performance": {}
            });
            
            fs::write(output_path, serde_json::to_string_pretty(&result_data)?)
                .context("Failed to write results")?;
            
            info!("Results saved to {}", output_path);
        }
        Ok(None) => {
            info!("Recovery completed - no matching seed phrase found");
            
            let result_data = serde_json::json!({
                "success": false,
                "message": "No matching seed phrase found",
                "target_address": config.ethereum.target_address,
                "derivation_path": config.ethereum.derivation_path,
                "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                "performance": {}
            });
            
            fs::write(output_path, serde_json::to_string_pretty(&result_data)?)
                .context("Failed to write results")?;
        }
        Err(e) => {
            error!("Recovery failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

async fn load_config(path: &str) -> Result<RecoveryConfig> {
    let config_data = fs::read_to_string(path)
        .context("Failed to read configuration file")?;
    
    let config: RecoveryConfig = serde_json::from_str(&config_data)
        .context("Failed to parse configuration JSON")?;
    
    config.validate()
        .context("Configuration validation failed")?;
    
    Ok(config)
}

async fn perform_dry_run(config: &RecoveryConfig) -> Result<()> {
    info!("=== DRY RUN MODE ===");
    
    // Validate configuration
    info!("✓ Configuration is valid");
    
    // Test candidate generation
    let mut generator = CandidateGenerator::new(&config)?;
    let test_batch = generator.generate_batch(10)?;
    if let Some(batch) = test_batch {
        info!("✓ Generated {} test candidates", batch.candidates.len());
        
        // Test crypto engine
        let crypto_engine = CryptoEngine::new();
        if let Some(candidate) = batch.candidates.first() {
            let mnemonic_str = candidate.words.join(" ");
            match crypto_engine.derive_bip39_seed(&mnemonic_str, &config.ethereum.passphrase) {
                Ok(_) => info!("✓ Crypto engine working correctly"),
                Err(e) => warn!("⚠ Crypto engine test failed: {}", e),
            }
        }
    } else {
        warn!("⚠ No test candidates generated");
    }
    
    // Test Ethereum generator
    let ethereum_generator = EthereumGenerator::new();
    let test_private_key = [1u8; 32];
    match ethereum_generator.generate_address(&test_private_key) {
        Ok(_) => info!("✓ Ethereum generator working correctly"),
        Err(e) => warn!("⚠ Ethereum generator test failed: {}", e),
    }
    
    // Test OpenCL if enabled
    if config.use_gpu {
        match OpenCLContext::new(Default::default()) {
            Ok(_ctx) => {
                info!("✓ OpenCL context can be created");
            }
            Err(e) => warn!("⚠ OpenCL initialization failed: {}", e),
        }
    }
    
    info!("=== DRY RUN COMPLETE ===");
    Ok(())
}

async fn run_cpu_recovery(
    config: &RecoveryConfig,
    _generator: &CandidateGenerator,
    crypto_engine: &CryptoEngine,
    ethereum_generator: &EthereumGenerator,
    monitor: &Arc<Mutex<RecoveryMonitor>>,
    checkpoint_path: &str,
) -> Result<Option<String>> {
    info!("Starting CPU-based recovery");
    
    let target_address = EthereumGenerator::validate_address(&config.ethereum.target_address)?;
    let derivation_path = config.ethereum.derivation_path.clone();
    
    monitor.lock().await.start();
    
    let generator_clone = CandidateGenerator::new(config)?;
    let mut batch_iterator = generator_clone.batch_iterator(config.batch_size);
    let mut last_checkpoint = Instant::now();
    let mut processed_count = 0u64;
    
    while let Some(batch_result) = batch_iterator.next() {
        let batch = batch_result?;
        let batch_start = Instant::now();
        
        // Process batch using CPU
        for candidate in &batch.candidates {
            let mnemonic_str = candidate.words.join(" ");
            
            // Derive seed from mnemonic
            // Derive private key using BIP44 directly from mnemonic
            let private_key = crypto_engine.derive_private_key_from_mnemonic(&mnemonic_str, &config.ethereum.passphrase, &derivation_path)?;
            
            // Generate Ethereum address
            let address = ethereum_generator.generate_address(&private_key.private_key)?;
            
            // Check if address matches target
            if address.address.to_string() == target_address.to_string() {
                monitor.lock().await.record_match();
                info!("MATCH FOUND: {}", mnemonic_str);
                return Ok(Some(mnemonic_str));
            }
        }
        
        // Update progress
        let batch_duration = batch_start.elapsed();
        processed_count += batch.candidates.len() as u64;
        {
            let mon = monitor.lock().await;
            mon.update_progress(batch.candidates.len() as u64);
            
            // Simple progress logging every 1000 batches
            if batch.candidates.len() % 1000 == 0 {
                info!(
                    "Processed {} candidates in {:.2}s",
                    batch.candidates.len(),
                    batch_duration.as_secs_f64()
                );
            }
        }
        
        // Save checkpoint periodically
        if last_checkpoint.elapsed() > Duration::from_secs(300) { // Every 5 minutes
            let checkpoint = monitor.lock().await.create_checkpoint(processed_count);
            if let Ok(checkpoint_data) = serde_json::to_string(&checkpoint) {
                let _ = fs::write(checkpoint_path, checkpoint_data);
            }
            last_checkpoint = Instant::now();
        }
        
        // Small delay to prevent CPU overload
        sleep(Duration::from_millis(1)).await;
    }
    
    Ok(None)
}

async fn run_gpu_recovery(
    config: &RecoveryConfig,
    _generator: &CandidateGenerator,
    crypto_engine: &CryptoEngine,
    ethereum_generator: &EthereumGenerator,
    opencl_context: &Arc<OpenCLContext>,
    monitor: &Arc<Mutex<RecoveryMonitor>>,
    checkpoint_path: &str,
) -> Result<Option<String>> {
    info!("Starting GPU recovery with OpenCL acceleration");
    
    let target_address = EthereumGenerator::validate_address(&config.ethereum.target_address)?;
    let _derivation_path = config.ethereum.derivation_path.clone();
    
    monitor.lock().await.start();
    let _monitoring_thread = {
        let monitor_clone = Arc::clone(monitor);
        tokio::spawn(async move {
            let monitor_config = MonitorConfig::default();
            let monitor_ref = monitor_clone.lock().await;
            monitor_ref.start_background_monitoring(monitor_config)
        })
    };
    
    // Load checkpoint if available
    let mut start_position = 0u64;
    if std::path::Path::new(checkpoint_path).exists() {
        if let Ok(checkpoint_data) = std::fs::read_to_string(checkpoint_path) {
            if let Ok(checkpoint) = serde_json::from_str::<Checkpoint>(&checkpoint_data) {
                monitor.lock().await.restore_from_checkpoint(&checkpoint);
                start_position = checkpoint.batch_position;
                info!("Resumed from checkpoint at position {}", start_position);
            }
        }
    }
    
    const BATCH_SIZE: usize = 1024; // GPU batch size
    let mut batch_count = 0u64;
    
    // Generate candidates and process in batches
    let mut generator_clone = CandidateGenerator::new(config)?;
    generator_clone.skip_to(start_position)?;
    
    while !generator_clone.is_exhausted() {
        // Generate a batch of candidates
        match generator_clone.generate_batch(BATCH_SIZE)? {
            Some(batch) => {
                let candidate_strings: Vec<String> = batch.candidates.iter()
                    .map(|c| c.phrase.clone())
                    .collect();
                
                // Process the batch
            match process_gpu_batch(
                &candidate_strings,
                crypto_engine,
                ethereum_generator,
                opencl_context,
                &target_address.to_string(),
            ).await {
                Ok(Some(found_mnemonic)) => {
                    monitor.lock().await.record_match();
                    monitor.lock().await.stop();
                    info!("Found matching seed phrase: {}", found_mnemonic);
                    return Ok(Some(found_mnemonic));
                }
                Ok(None) => {
                    // No match in this batch, continue
                    monitor.lock().await.update_progress(candidate_strings.len() as u64);
                }
                Err(e) => {
                    warn!("GPU batch processing failed: {}, falling back to CPU", e);
                    return run_cpu_recovery(config, &CandidateGenerator::new(config)?, crypto_engine, ethereum_generator, monitor, checkpoint_path).await;
                }
            }
            
            // Create checkpoint every 100 batches
            if batch_count % 100 == 0 {
                let checkpoint = monitor.lock().await.create_checkpoint(batch_count * BATCH_SIZE as u64);
                if let Ok(checkpoint_data) = serde_json::to_string(&checkpoint) {
                    let _ = std::fs::write(checkpoint_path, checkpoint_data);
                }
            }
                
                batch_count += 1;
                
                // Check for early termination
                if monitor.lock().await.has_match() {
                    break;
                }
            }
            None => {
                // No more batches available
                break;
            }
        }
    }
    
    monitor.lock().await.stop();
    info!("GPU recovery completed - no matches found");
    Ok(None)
}

/// Process a batch of candidates using GPU acceleration
async fn process_gpu_batch(
    candidates: &[String],
    _crypto_engine: &CryptoEngine,
    ethereum_generator: &EthereumGenerator,
    opencl_context: &OpenCLContext,
    target_address: &str,
) -> Result<Option<String>> {
    use ethereum_seed_recovery::opencl::GpuBatch;
    
    // Convert candidates to GPU-friendly format
    let mut mnemonic_bytes = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        mnemonic_bytes.push(candidate.as_bytes().to_vec());
    }
    
    // Create derivation path for Ethereum (m/44'/60'/0'/0/2)
    let derivation_path = vec![44 | 0x80000000, 60 | 0x80000000, 0x80000000, 0, 2];
    let passphrase = Vec::new(); // Empty passphrase
    
    // Create GPU batch
    let gpu_batch = GpuBatch::new(mnemonic_bytes, derivation_path, passphrase);
    
    // Process batch on GPU
    match opencl_context.process_batch_gpu(&gpu_batch) {
        Ok(gpu_results) => {
            // Check each result for address match
            for (i, private_key) in gpu_results.private_keys.iter().enumerate() {
                if gpu_results.success_flags[i] {
                    // Generate Ethereum address from private key
                    if private_key.len() >= 32 {
                        let mut key_array = [0u8; 32];
                        key_array.copy_from_slice(&private_key[..32]);
                        match ethereum_generator.generate_address(&key_array) {
                            Ok(address) => {
                                if address.address.to_string() == target_address {
                                    return Ok(Some(candidates[i].clone()));
                                }
                            }
                            Err(e) => {
                                 warn!("Failed to generate address from GPU result: {}", e);
                             }
                         }
                     }
                }
            }
            Ok(None)
        }
        Err(e) => {
            // GPU processing failed, return error to trigger CPU fallback
            Err(anyhow::anyhow!("GPU processing failed: {}", e).into())
        }
    }
}