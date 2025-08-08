//! Configuration types and parsing for the Ethereum seed phrase recovery tool

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::{ConfigError, Result};

/// Main configuration structure for the recovery process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Word constraints for each position in the mnemonic
    pub word_constraints: Vec<WordConstraint>,
    
    /// Ethereum-specific configuration
    pub ethereum: EthereumConfig,
    
    /// Length of the mnemonic phrase
    pub mnemonic_length: usize,
    
    /// Type of wallet (currently only "ethereum" supported)
    pub wallet_type: String,
    
    /// Optional batch size for processing (defaults to DEFAULT_BATCH_SIZE)
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    
    /// Optional number of threads for CPU operations
    #[serde(default = "default_num_threads")]
    pub num_threads: usize,
    
    /// Whether to use GPU acceleration (default: true)
    #[serde(default = "default_use_gpu")]
    pub use_gpu: bool,
    
    /// Maximum memory usage in MB (default: 1024)
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: usize,
}

/// Word constraint for a specific position in the mnemonic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordConstraint {
    /// Position in the mnemonic (0-based)
    pub position: usize,
    
    /// List of possible words for this position
    pub words: Vec<String>,
}

/// Ethereum-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumConfig {
    /// BIP44 derivation path
    pub derivation_path: String,
    
    /// Target Ethereum address to match
    pub target_address: String,
    
    /// Optional passphrase for BIP39 seed generation
    #[serde(default)]
    pub passphrase: String,
}

/// GPU configuration for OpenCL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuConfig {
    /// Preferred platform index (None for auto-select)
    pub platform_index: Option<usize>,
    
    /// Preferred device indices (empty for all devices)
    pub device_indices: Vec<usize>,
    
    /// Work group size for kernels (None for auto-select)
    pub work_group_size: Option<usize>,
    
    /// Number of compute units to use (None for all)
    pub compute_units: Option<usize>,
}

/// Default functions for serde
fn default_batch_size() -> usize {
    crate::DEFAULT_BATCH_SIZE
}

fn default_num_threads() -> usize {
    num_cpus::get()
}

fn default_use_gpu() -> bool {
    true
}

fn default_max_memory_mb() -> usize {
    1024
}

impl RecoveryConfig {
    /// Load configuration from a JSON file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: RecoveryConfig = serde_json::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
    
    /// Load configuration from a JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        let config: RecoveryConfig = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to a JSON file
    pub fn to_file(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate mnemonic length
        if self.mnemonic_length < crate::MIN_MNEMONIC_LENGTH || 
           self.mnemonic_length > crate::MAX_MNEMONIC_LENGTH {
            return Err(ConfigError::InvalidMnemonicLength(self.mnemonic_length).into());
        }
        
        // Validate that mnemonic length is a multiple of 3
        if self.mnemonic_length % 3 != 0 {
            return Err(ConfigError::InvalidMnemonicLength(self.mnemonic_length).into());
        }
        
        // Validate wallet type
        if self.wallet_type != "ethereum" {
            return Err(ConfigError::UnsupportedWalletType(self.wallet_type.clone()).into());
        }
        
        // Validate batch size
        if self.batch_size == 0 {
            return Err(ConfigError::InvalidBatchSize(self.batch_size).into());
        }
        
        // Validate word constraints
        self.validate_word_constraints()?;
        
        // Validate Ethereum configuration
        self.ethereum.validate()?;
        
        Ok(())
    }
    
    /// Validate word constraints
    fn validate_word_constraints(&self) -> Result<()> {
        // Check that we have constraints for all positions
        let mut positions: HashMap<usize, &WordConstraint> = HashMap::new();
        
        for constraint in &self.word_constraints {
            if constraint.position >= self.mnemonic_length {
                return Err(ConfigError::InvalidInput(
                    format!("Position {} exceeds mnemonic length {}", 
                           constraint.position, self.mnemonic_length)
                ).into());
            }
            
            if constraint.words.is_empty() {
                return Err(ConfigError::EmptyWordConstraints(constraint.position).into());
            }
            
            // Validate that all words are valid BIP39 words
            for word in &constraint.words {
                if !is_valid_bip39_word(word) {
                    return Err(ConfigError::InvalidWord(word.clone()).into());
                }
            }
            
            positions.insert(constraint.position, constraint);
        }
        
        // Check that all positions are covered
        for i in 0..self.mnemonic_length {
            if !positions.contains_key(&i) {
                return Err(ConfigError::MissingWordConstraints(i).into());
            }
        }
        
        Ok(())
    }
    
    /// Calculate the total search space size
    pub fn calculate_search_space(&self) -> u64 {
        self.word_constraints
            .iter()
            .map(|constraint| constraint.words.len() as u64)
            .product()
    }
    
    /// Get word constraints as a map for easier access
    pub fn get_constraints_map(&self) -> HashMap<usize, &Vec<String>> {
        self.word_constraints
            .iter()
            .map(|constraint| (constraint.position, &constraint.words))
            .collect()
    }
}

impl EthereumConfig {
    /// Validate Ethereum configuration
    pub fn validate(&self) -> Result<()> {
        // Validate derivation path format
        if !self.derivation_path.starts_with("m/") {
            return Err(ConfigError::InvalidDerivationPath(self.derivation_path.clone()).into());
        }
        
        // Basic validation of derivation path components
        let parts: Vec<&str> = self.derivation_path[2..].split('/').collect();
        if parts.len() < 3 {
            return Err(ConfigError::InvalidDerivationPath(self.derivation_path.clone()).into());
        }
        
        // Validate Ethereum address format
        if !is_valid_ethereum_address(&self.target_address) {
            return Err(ConfigError::InvalidEthereumAddress(self.target_address.clone()).into());
        }
        
        Ok(())
    }
    
    /// Parse the derivation path into components
    pub fn parse_derivation_path(&self) -> Result<Vec<u32>> {
        let path_str = &self.derivation_path[2..]; // Remove "m/"
        let mut components = Vec::new();
        
        for part in path_str.split('/') {
            let (index_str, hardened) = if part.ends_with('\'') {
                (&part[..part.len()-1], true)
            } else {
                (part, false)
            };
            
            let index: u32 = index_str.parse()
                .map_err(|_| ConfigError::InvalidDerivationPath(self.derivation_path.clone()))?;
            
            let final_index = if hardened {
                index + 0x80000000
            } else {
                index
            };
            
            components.push(final_index);
        }
        
        Ok(components)
    }
}

/// Check if a word is a valid BIP39 word
fn is_valid_bip39_word(word: &str) -> bool {
    // For now, we'll do basic validation
    // In a production system, you'd check against the full BIP39 wordlist
    !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase())
}

/// Check if an Ethereum address is valid
fn is_valid_ethereum_address(address: &str) -> bool {
    // Basic validation: starts with 0x and is 42 characters long
    if !address.starts_with("0x") || address.len() != 42 {
        return false;
    }
    
    // Check that all characters after 0x are valid hex
    address[2..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_config() {
        let json = r#"{
            "word_constraints": [
                { "position": 0, "words": ["abandon", "ability"] },
                { "position": 1, "words": ["able", "about"] }
            ],
            "ethereum": {
                "derivation_path": "m/44'/60'/0'/0/0",
                "target_address": "0x1234567890123456789012345678901234567890"
            },
            "mnemonic_length": 12,
            "wallet_type": "ethereum"
        }"#;
        
        // This should fail because we don't have constraints for all positions
        let result = RecoveryConfig::from_json(json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_ethereum_address_validation() {
        assert!(is_valid_ethereum_address("0x1234567890123456789012345678901234567890"));
        assert!(!is_valid_ethereum_address("1234567890123456789012345678901234567890"));
        assert!(!is_valid_ethereum_address("0x123"));
        assert!(!is_valid_ethereum_address("0x123456789012345678901234567890123456789g"));
    }
    
    #[test]
    fn test_derivation_path_parsing() {
        let config = EthereumConfig {
            derivation_path: "m/44'/60'/0'/0/2".to_string(),
            target_address: "0x1234567890123456789012345678901234567890".to_string(),
            passphrase: String::new(),
        };
        
        let components = config.parse_derivation_path().unwrap();
        assert_eq!(components, vec![0x8000002C, 0x8000003C, 0x80000000, 0, 2]);
    }
}