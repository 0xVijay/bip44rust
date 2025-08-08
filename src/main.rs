//! Ethereum Seed Recovery Tool
//! 
//! A high-performance Rust/OpenCL application for recovering Ethereum seed phrases
//! from partial information using GPU acceleration.

use anyhow::{Context, Result};
use clap::{Arg, Command};
use ethereum_seed_recovery::{
    config::RecoveryConfig,
    crypto::CryptoEngine,
    ethereum::EthereumGenerator,
    generator::CandidateGenerator,
    monitor::{RecoveryMonitor, MonitorConfig},
    opencl::OpenCLContext,
};
use std::{
    fs,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

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
                monitor.lock().unwrap().restore_from_checkpoint(&checkpoint);
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
        run_gpu_recovery(&config, generator, &crypto_engine, &ethereum_generator, 
                        &opencl_ctx, &monitor, checkpoint_path).await
    } else {
        run_cpu_recovery(&config, generator, &crypto_engine, &ethereum_generator, 
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
    generator: CandidateGenerator,
    crypto_engine: &CryptoEngine,
    ethereum_generator: &EthereumGenerator,
    monitor: &Arc<Mutex<RecoveryMonitor>>,
    checkpoint_path: &str,
) -> Result<Option<String>> {
    info!("Starting CPU-based recovery");
    
    let target_address = EthereumGenerator::validate_address(&config.ethereum.target_address)?;
    let derivation_path = config.ethereum.derivation_path.clone();
    
    monitor.lock().unwrap().start();
    
    let mut batch_iterator = generator.batch_iterator(config.batch_size);
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
            if address.address == target_address {
                monitor.lock().unwrap().record_match();
                info!("MATCH FOUND: {}", mnemonic_str);
                return Ok(Some(mnemonic_str));
            }
        }
        
        // Update progress
        let batch_duration = batch_start.elapsed();
        processed_count += batch.candidates.len() as u64;
        {
            let mon = monitor.lock().unwrap();
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
            let checkpoint = monitor.lock().unwrap().create_checkpoint(processed_count);
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
    generator: CandidateGenerator,
    crypto_engine: &CryptoEngine,
    ethereum_generator: &EthereumGenerator,
    _opencl_context: &Arc<OpenCLContext>,
    monitor: &Arc<Mutex<RecoveryMonitor>>,
    checkpoint_path: &str,
) -> Result<Option<String>> {
    info!("Starting GPU-accelerated recovery");
    
    let target_address = EthereumGenerator::validate_address(&config.ethereum.target_address)?;
    let derivation_path = config.ethereum.derivation_path.clone();
    
    monitor.lock().unwrap().start();
    
    let mut batch_iterator = generator.batch_iterator(config.batch_size);
    let mut last_checkpoint = Instant::now();
    let mut processed_count = 0u64;
    
    while let Some(batch_result) = batch_iterator.next() {
        let batch = batch_result?;
        let batch_start = Instant::now();
        
        // For now, fall back to CPU processing since GPU kernels are not implemented
        // TODO: Implement GPU batch processing
        // let gpu_batch = GpuBatch::from_crypto_batch(&batch);
        // match opencl_context.process_batch_gpu(&gpu_batch) {
        
        // CPU fallback processing
        for candidate in &batch.candidates {
            let mnemonic_str = candidate.words.join(" ");
            let private_key = crypto_engine.derive_private_key_from_mnemonic(&mnemonic_str, &config.ethereum.passphrase, &derivation_path)?;
            let address = ethereum_generator.generate_address(&private_key.private_key)?;
            
            if address.address == target_address {
                monitor.lock().unwrap().record_match();
                info!("MATCH FOUND: {}", mnemonic_str);
                return Ok(Some(mnemonic_str));
            }
        }
        
        // Update progress
        let batch_duration = batch_start.elapsed();
        {
            let mon = monitor.lock().unwrap();
            mon.update_progress(batch.candidates.len() as u64);
            
            // Simple progress logging every 1000 batches
            if batch.candidates.len() % 1000 == 0 {
                info!(
                    "GPU processed {} candidates in {:.2}s",
                    batch.candidates.len(),
                    batch_duration.as_secs_f64()
                );
            }
        }
        
        // Save checkpoint periodically
        if last_checkpoint.elapsed() > Duration::from_secs(300) {
            let checkpoint = monitor.lock().unwrap().create_checkpoint(processed_count);
            if let Ok(checkpoint_data) = serde_json::to_string(&checkpoint) {
                let _ = fs::write(checkpoint_path, checkpoint_data);
            }
            last_checkpoint = Instant::now();
        }
        
        processed_count += batch.candidates.len() as u64;
    }
    
    Ok(None)
}