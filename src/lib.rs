//! Ethereum Seed Phrase Recovery Tool
//!
//! A high-performance tool for recovering Ethereum seed phrases using partial information
//! and GPU acceleration via OpenCL.

pub mod config;
pub mod crypto;
pub mod generator;
pub mod opencl;
pub mod ethereum;
pub mod monitor;
pub mod error;

// Re-export main types without utils modules to avoid conflicts
pub use config::{RecoveryConfig, WordConstraint, EthereumConfig};
pub use crypto::{CryptoEngine, Bip39Seed, DerivedKey, CryptoBatch, BatchResult};
pub use generator::{CandidateGenerator, Candidate, CandidateBatch, BatchIterator};
pub use ethereum::{EthereumGenerator, EthereumAddress, EthereumKeyPair};
pub use monitor::{RecoveryMonitor, MonitorConfig};
pub use error::*;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::config::{RecoveryConfig, WordConstraint, EthereumConfig};
    pub use crate::crypto::{CryptoEngine, Bip39Seed, DerivedKey, CryptoBatch, BatchResult};
    pub use crate::generator::{CandidateGenerator, Candidate, CandidateBatch, BatchIterator};
    pub use crate::ethereum::{EthereumGenerator, EthereumAddress, EthereumKeyPair};
    pub use crate::monitor::{RecoveryMonitor, MonitorConfig};
    pub use crate::error::*;
    pub use anyhow::{Result, Context};
}

#[cfg(test)]
mod tests;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default batch size for candidate processing
pub const DEFAULT_BATCH_SIZE: usize = 10000;

/// Maximum supported mnemonic length
pub const MAX_MNEMONIC_LENGTH: usize = 24;

/// Minimum supported mnemonic length
pub const MIN_MNEMONIC_LENGTH: usize = 12;