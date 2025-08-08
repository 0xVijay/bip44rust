//! Main seed phrase recovery application
//! 
//! This module provides the high-level interface for GPU-accelerated seed phrase recovery.
//! It integrates candidate generation, GPU processing, and result handling.

use crate::opencl::{OpenCLContext, OpenCLConfig, RecoveryBatch};
use crate::generator::CandidateGenerator;
use crate::config::WordConstraint;
use crate::ethereum::EthereumAddress;
use crate::error::{Result, RecoveryError};
use log::info;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Mutex;

// Use RecoveryConfig from config.rs
pub use crate::config::RecoveryConfig;

/// Statistics for recovery progress
#[derive(Debug, Clone, Default)]
pub struct RecoveryStats {
    /// Total candidates processed
    pub candidates_processed: u64,
    /// Total batches processed
    pub batches_processed: u64,
    /// Processing rate (candidates per second)
    pub processing_rate: f64,
    /// Elapsed time
    pub elapsed_time: Duration,
    /// Estimated time remaining
    pub estimated_time_remaining: Option<Duration>,
    /// GPU utilization percentage
    pub gpu_utilization: f32,
    /// Memory usage (bytes)
    pub memory_usage: u64,
}

/// Result of seed phrase recovery
#[derive(Debug, Clone)]
pub struct RecoveryOutcome {
    /// Whether a matching seed phrase was found
    pub success: bool,
    /// The recovered mnemonic phrase (if found)
    pub mnemonic: Option<String>,
    /// The derived private key (if found)
    pub private_key: Option<[u8; 32]>,
    /// The derived public key (if found)
    pub public_key: Option<[u8; 64]>,
    /// The generated Ethereum address (if found)
    pub ethereum_address: Option<EthereumAddress>,
    /// Final recovery statistics
    pub stats: RecoveryStats,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Main seed phrase recovery engine
pub struct SeedRecovery {
    /// OpenCL context for GPU processing
    opencl_context: Arc<OpenCLContext>,
    /// Candidate generator
    generator: CandidateGenerator,
    /// Recovery configuration
    config: RecoveryConfig,
    /// Current statistics
    stats: Arc<Mutex<RecoveryStats>>,
    /// Start time
    start_time: Instant,
}

impl SeedRecovery {
    /// Create a new seed recovery instance
    pub async fn new(config: RecoveryConfig) -> Result<Self> {
        info!("Initializing seed recovery with batch size: {}", config.batch_size);
        
        // Initialize OpenCL context
        let opencl_context = Arc::new(OpenCLContext::new(OpenCLConfig::default())?);
        
        // Log device information
        let device_info = opencl_context.device_info();
        info!("Using GPU: {} (Compute Units: {}, Max Work Group Size: {})", 
               device_info.name, device_info.max_compute_units, device_info.max_work_group_size);
        
        // Initialize candidate generator
        let generator = CandidateGenerator::new(&config)?;
        let total_combinations = generator.total_combinations();
        info!("Estimated total combinations: {}", total_combinations);
        
        Ok(Self {
            opencl_context,
            generator,
            config,
            stats: Arc::new(Mutex::new(RecoveryStats::default())),
            start_time: Instant::now(),
        })
    }
    
    /// Start the recovery process
    pub async fn recover(&mut self) -> Result<RecoveryOutcome> {
        info!("Starting seed phrase recovery...");
        info!("Target address: {}", self.config.ethereum.target_address);
        info!("Derivation path: {}", self.config.ethereum.derivation_path);
        
        let mut batch_count = 0u64;
        let mut total_processed = 0u64;
        
        // Convert target address to bytes for comparison
        let target_bytes = EthereumAddress::from_hex(&self.config.ethereum.target_address)?
            .to_bytes();
        
        // Main recovery loop
        loop {
            // Generate next batch of candidates
            let candidates = match self.generator.generate_batch(self.config.batch_size)? {
                Some(batch) => batch.candidates,
                None => {
                    info!("Exhausted all candidate combinations");
                    break;
                }
            };
            
            if candidates.is_empty() {
                break;
            }
            
            // Convert candidates to mnemonics
            let mnemonics: Vec<String> = candidates
                .iter()
                .map(|c| c.as_str().to_string())
                .collect();
            
            // Create recovery batch
            let recovery_batch = RecoveryBatch {
                mnemonics: mnemonics.clone(),
                target_address: target_bytes,
                derivation_path: self.config.ethereum.parse_derivation_path()?
                    .try_into().map_err(|_| RecoveryError::Config(
                        crate::error::ConfigError::InvalidDerivationPath(
                            "Derivation path must have exactly 5 components".to_string())))?,
                passphrase: self.config.ethereum.passphrase.clone(),
            };
            
            // Process batch on GPU
            let batch_start = Instant::now();
            let result = self.opencl_context.process_recovery_batch(&recovery_batch)?;
            let batch_duration = batch_start.elapsed();
            
            // Update statistics
            batch_count += 1;
            total_processed += candidates.len() as u64;
            
            // Check for matches
            if !result.found_matches.is_empty() {
                info!("SUCCESS! Found matching seed phrase(s):");
                for (index, mnemonic) in &result.found_matches {
                    info!("  Index {}: {}", index, mnemonic);
                }
                
                // Return successful result
                let final_stats = self.update_stats(total_processed, batch_count, batch_duration).await;
                
                return Ok(RecoveryOutcome {
                    success: true,
                    mnemonic: Some(result.found_matches[0].1.clone()),
                    private_key: Some(result.private_keys[result.found_matches[0].0]),
                    public_key: Some(result.public_keys[result.found_matches[0].0]),
                    ethereum_address: Some(EthereumAddress::from_bytes(result.addresses[result.found_matches[0].0])),
                    stats: final_stats,
                    error: None,
                });
            }
            
            // Update and report progress
            if batch_count % 100 == 0 { // Report progress every 100 batches
                let stats = self.update_stats(total_processed, batch_count, batch_duration).await;
                self.report_progress(&stats).await;
            }
            
            // Continue processing until all candidates are exhausted
            // (no max_candidates limit in current config structure)
        }
        
        // Recovery completed without finding a match
        let final_stats = self.update_stats(total_processed, batch_count, Duration::from_secs(0)).await;
        
        Ok(RecoveryOutcome {
            success: false,
            mnemonic: None,
            private_key: None,
            public_key: None,
            ethereum_address: None,
            stats: final_stats,
            error: None,
        })
    }
    
    /// Update recovery statistics
    async fn update_stats(&self, total_processed: u64, batch_count: u64, _last_batch_duration: Duration) -> RecoveryStats {
        let mut stats = self.stats.lock().await;
        
        stats.candidates_processed = total_processed;
        stats.batches_processed = batch_count;
        stats.elapsed_time = self.start_time.elapsed();
        
        // Calculate processing rate
        if stats.elapsed_time.as_secs_f64() > 0.0 {
            stats.processing_rate = total_processed as f64 / stats.elapsed_time.as_secs_f64();
        }
        
        // Estimate remaining time (if we know total combinations)
        let total_combinations = self.generator.total_combinations();
        if stats.processing_rate > 0.0 {
            let remaining_candidates = total_combinations.saturating_sub(total_processed);
            let remaining_seconds = remaining_candidates as f64 / stats.processing_rate;
            stats.estimated_time_remaining = Some(Duration::from_secs_f64(remaining_seconds));
        }
        
        // TODO: Add GPU utilization and memory usage monitoring
        stats.gpu_utilization = 85.0; // Placeholder
        stats.memory_usage = batch_count * self.config.batch_size as u64 * 1024; // Placeholder
        
        stats.clone()
    }
    
    /// Report progress to the user
    async fn report_progress(&self, stats: &RecoveryStats) {
        info!("Progress Report:");
        info!("  Candidates processed: {}", stats.candidates_processed);
        info!("  Batches processed: {}", stats.batches_processed);
        info!("  Processing rate: {:.2} candidates/sec", stats.processing_rate);
        info!("  Elapsed time: {:?}", stats.elapsed_time);
        
        if let Some(remaining) = stats.estimated_time_remaining {
            info!("  Estimated remaining: {:?}", remaining);
        }
        
        info!("  GPU utilization: {:.1}%", stats.gpu_utilization);
        info!("  Memory usage: {:.2} MB", stats.memory_usage as f64 / 1024.0 / 1024.0);
    }
    
    /// Get current recovery statistics
    pub async fn get_stats(&self) -> RecoveryStats {
        self.stats.lock().await.clone()
    }
    
    /// Estimate total recovery time
    pub async fn estimate_total_time(&self) -> Option<Duration> {
        let stats = self.stats.lock().await;
        
        let total_combinations = self.generator.total_combinations();
        if stats.processing_rate > 0.0 {
            let total_seconds = total_combinations as f64 / stats.processing_rate;
            return Some(Duration::from_secs_f64(total_seconds));
        }
        
        None
    }
}

/// Convenience function to run seed recovery with default configuration
pub async fn recover_seed_phrase(
    target_address: &str,
    word_constraints: Vec<WordConstraint>,
) -> Result<RecoveryOutcome> {
    use crate::config::EthereumConfig;
    
    let config = RecoveryConfig {
        word_constraints,
        ethereum: EthereumConfig {
            derivation_path: "m/44'/60'/0'/0/2".to_string(),
            target_address: target_address.to_string(),
            passphrase: String::new(),
        },
        mnemonic_length: 12,
        wallet_type: "ethereum".to_string(),
        batch_size: 1024,
        num_threads: 4,
        use_gpu: true,
        max_memory_mb: 1024,
    };
    
    let mut recovery = SeedRecovery::new(config).await?;
    recovery.recover().await
}

#[cfg(test)]
mod tests {
    use super::*;
    // WordConstraint is already imported from crate::config
    
    #[tokio::test]
    async fn test_recovery_config_creation() {
        use crate::config::EthereumConfig;
        
        let config = RecoveryConfig {
            word_constraints: vec![],
            ethereum: EthereumConfig {
                derivation_path: "m/44'/60'/0'/0/2".to_string(),
                target_address: "0x1234567890123456789012345678901234567890".to_string(),
                passphrase: String::new(),
            },
            mnemonic_length: 12,
            wallet_type: "ethereum".to_string(),
            batch_size: 1024,
            num_threads: 4,
            use_gpu: true,
            max_memory_mb: 1024,
        };
        assert_eq!(config.batch_size, 1024);
        assert_eq!(config.mnemonic_length, 12);
    }
    
    #[tokio::test]
    async fn test_recovery_stats_default() {
        let stats = RecoveryStats::default();
        assert_eq!(stats.candidates_processed, 0);
        assert_eq!(stats.batches_processed, 0);
        assert_eq!(stats.processing_rate, 0.0);
    }
    
    #[test]
    fn test_recovery_outcome_creation() {
        let outcome = RecoveryOutcome {
            success: true,
            mnemonic: Some("test mnemonic".to_string()),
            private_key: Some([1u8; 32]),
            public_key: Some([2u8; 64]),
            ethereum_address: Some(EthereumAddress::default()),
            stats: RecoveryStats::default(),
            error: None,
        };
        
        assert!(outcome.success);
        assert!(outcome.mnemonic.is_some());
        assert!(outcome.private_key.is_some());
    }
}