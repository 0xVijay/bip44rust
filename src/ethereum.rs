//! Ethereum address generation and validation

use crate::error::{EthereumError, Result};
use crate::crypto::DerivedKey;
use bitcoin::secp256k1::{Secp256k1, PublicKey, SecretKey};
use keccak_hash::keccak;
use std::fmt;

/// Ethereum address (20 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EthereumAddress {
    /// The 20-byte address
    pub address: [u8; 20],
}

/// Ethereum public key (64 bytes uncompressed)
#[derive(Debug, Clone)]
pub struct EthereumPublicKey {
    /// The 64-byte uncompressed public key (without 0x04 prefix)
    pub key: [u8; 64],
}

/// Ethereum key pair
#[derive(Debug, Clone)]
pub struct EthereumKeyPair {
    /// Private key
    pub private_key: [u8; 32],
    /// Public key
    pub public_key: EthereumPublicKey,
    /// Ethereum address
    pub address: EthereumAddress,
    /// Derivation path used
    pub derivation_path: String,
}

/// Batch processing for Ethereum address generation
#[derive(Debug)]
pub struct EthereumBatch {
    /// Input private keys
    pub private_keys: Vec<DerivedKey>,
}

/// Result of batch Ethereum address generation
#[derive(Debug)]
pub struct EthereumBatchResult {
    /// Generated key pairs
    pub key_pairs: Vec<EthereumKeyPair>,
    /// Any errors encountered (indexed by private key position)
    pub errors: Vec<(usize, EthereumError)>,
}

/// Ethereum address generator
#[derive(Debug)]
pub struct EthereumGenerator {
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

impl EthereumGenerator {
    /// Create a new Ethereum generator
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }
    
    /// Generate Ethereum address from private key
    pub fn generate_address(&self, private_key: &[u8; 32]) -> Result<EthereumKeyPair> {
        // Create secp256k1 secret key
        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| EthereumError::InvalidPrivateKey(e.to_string()))?;
        
        // Generate public key
        let public_key = PublicKey::from_secret_key(&self.secp, &secret_key);
        
        // Get uncompressed public key bytes (65 bytes with 0x04 prefix)
        let public_key_bytes = public_key.serialize_uncompressed();
        
        // Remove the 0x04 prefix to get 64 bytes
        let mut eth_public_key = [0u8; 64];
        eth_public_key.copy_from_slice(&public_key_bytes[1..]);
        
        // Generate Ethereum address using Keccak-256
        let address = self.public_key_to_address(&eth_public_key)?;
        
        Ok(EthereumKeyPair {
            private_key: *private_key,
            public_key: EthereumPublicKey { key: eth_public_key },
            address,
            derivation_path: String::new(), // Will be set by caller
        })
    }
    
    /// Generate Ethereum address from DerivedKey
    pub fn generate_address_from_derived_key(&self, derived_key: &DerivedKey) -> Result<EthereumKeyPair> {
        let mut key_pair = self.generate_address(&derived_key.private_key)?;
        key_pair.derivation_path = derived_key.derivation_path.clone();
        Ok(key_pair)
    }
    
    /// Convert public key to Ethereum address
    pub fn public_key_to_address(&self, public_key: &[u8; 64]) -> Result<EthereumAddress> {
        // Hash the public key with Keccak-256
        let hash = keccak(public_key);
        
        // Take the last 20 bytes as the address
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash.as_bytes()[12..]);
        
        Ok(EthereumAddress { address })
    }
    
    /// Process a batch of private keys
    pub fn process_batch(&self, batch: &EthereumBatch) -> EthereumBatchResult {
        let mut key_pairs = Vec::new();
        let mut errors = Vec::new();
        
        for (index, derived_key) in batch.private_keys.iter().enumerate() {
            match self.generate_address_from_derived_key(derived_key) {
                Ok(key_pair) => key_pairs.push(key_pair),
                Err(e) => {
                    if let crate::error::RecoveryError::Ethereum(eth_err) = e {
                        errors.push((index, eth_err));
                    } else {
                        errors.push((index, EthereumError::InvalidPrivateKey("Unknown error".to_string())));
                    }
                }
            }
        }
        
        EthereumBatchResult {
            key_pairs,
            errors,
        }
    }
    
    /// Process batch in parallel using rayon
    pub fn process_batch_parallel(&self, batch: &EthereumBatch) -> EthereumBatchResult {
        use rayon::prelude::*;
        
        let results: Vec<_> = batch.private_keys
            .par_iter()
            .enumerate()
            .map(|(index, derived_key)| {
                let result = self.generate_address_from_derived_key(derived_key);
                (index, result)
            })
            .collect();
        
        let mut key_pairs = Vec::new();
        let mut errors = Vec::new();
        
        for (index, result) in results {
            match result {
                Ok(key_pair) => key_pairs.push(key_pair),
                Err(e) => {
                    if let crate::error::RecoveryError::Ethereum(eth_err) = e {
                        errors.push((index, eth_err));
                    } else {
                        errors.push((index, EthereumError::InvalidPrivateKey("Unknown error".to_string())));
                    }
                }
            }
        }
        
        EthereumBatchResult {
            key_pairs,
            errors,
        }
    }
    
    /// Validate an Ethereum address format
    pub fn validate_address(address_str: &str) -> Result<EthereumAddress> {
        // Remove 0x prefix if present
        let address_str = address_str.strip_prefix("0x").unwrap_or(address_str);
        
        // Check length (40 hex characters = 20 bytes)
        if address_str.len() != 40 {
            return Err(EthereumError::InvalidAddress("Address must be 40 hex characters".to_string()).into());
        }
        
        // Decode hex
        let bytes = hex::decode(address_str)
            .map_err(|e| EthereumError::InvalidAddress(format!("Invalid hex: {}", e)))?;
        
        if bytes.len() != 20 {
            return Err(EthereumError::InvalidAddress("Address must be 20 bytes".to_string()).into());
        }
        
        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes);
        
        Ok(EthereumAddress { address })
    }
    
    /// Check if a generated address matches the target
    pub fn matches_target(&self, generated: &EthereumAddress, target: &EthereumAddress) -> bool {
        generated.address == target.address
    }
}

impl Default for EthereumGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl EthereumAddress {
    /// Create from byte array
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self { address: bytes }
    }
    
    /// Get address as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.address
    }
    
    /// Convert to hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
    
    /// Convert to hex string without 0x prefix
    pub fn to_hex_no_prefix(&self) -> String {
        hex::encode(self.address)
    }
    
    /// Create from hex string (with or without 0x prefix)
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        EthereumGenerator::validate_address(hex_str)
    }
    
    /// Convert to checksum address (EIP-55)
    pub fn to_checksum(&self) -> String {
        let address_hex = hex::encode(self.address);
        let hash = keccak(address_hex.as_bytes());
        
        let mut checksum = String::with_capacity(42);
        checksum.push_str("0x");
        
        for (i, c) in address_hex.chars().enumerate() {
            if c.is_ascii_digit() {
                checksum.push(c);
            } else {
                // Check if the corresponding hash byte's high nibble is >= 8
                let hash_byte = hash.as_bytes()[i / 2];
                let nibble = if i % 2 == 0 {
                    hash_byte >> 4
                } else {
                    hash_byte & 0x0f
                };
                
                if nibble >= 8 {
                    checksum.push(c.to_ascii_uppercase());
                } else {
                    checksum.push(c.to_ascii_lowercase());
                }
            }
        }
        
        checksum
    }
    
    /// Validate checksum address (EIP-55)
    pub fn validate_checksum(address_str: &str) -> Result<Self> {
        let address = Self::from_hex(address_str)?;
        let expected_checksum = address.to_checksum();
        
        if address_str != expected_checksum {
            return Err(EthereumError::InvalidChecksum(format!(
                "Expected: {}, got: {}",
                expected_checksum,
                address_str
            )).into());
        }
        
        Ok(address)
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum())
    }
}

impl EthereumPublicKey {
    /// Get public key as byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
    
    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.key)
    }
    
    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| EthereumError::InvalidPublicKey(format!("Invalid hex: {}", e)))?;
        
        if bytes.len() != 64 {
            return Err(EthereumError::InvalidPublicKey("Public key must be 64 bytes".to_string()).into());
        }
        
        let mut key = [0u8; 64];
        key.copy_from_slice(&bytes);
        
        Ok(Self { key })
    }
}

impl EthereumKeyPair {
    /// Get the private key as hex string
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key)
    }
    
    /// Get the public key as hex string
    pub fn public_key_hex(&self) -> String {
        self.public_key.to_hex()
    }
    
    /// Get the address as hex string
    pub fn address_hex(&self) -> String {
        self.address.to_hex()
    }
    
    /// Get the address as checksum string
    pub fn address_checksum(&self) -> String {
        self.address.to_checksum()
    }
}

impl EthereumBatch {
    /// Create a new batch
    pub fn new(private_keys: Vec<DerivedKey>) -> Self {
        Self { private_keys }
    }
    
    /// Get the number of private keys in the batch
    pub fn len(&self) -> usize {
        self.private_keys.len()
    }
    
    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.private_keys.is_empty()
    }
}

impl EthereumBatchResult {
    /// Get the number of successful generations
    pub fn success_count(&self) -> usize {
        self.key_pairs.len()
    }
    
    /// Get the number of errors
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
    
    /// Check if all generations were successful
    pub fn all_successful(&self) -> bool {
        self.errors.is_empty()
    }
    
    /// Get success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.key_pairs.is_empty() && self.errors.is_empty() {
            return 0.0;
        }
        
        let total = self.key_pairs.len() + self.errors.len();
        (self.key_pairs.len() as f64 / total as f64) * 100.0
    }
    
    /// Find key pairs that match a target address
    pub fn find_matches(&self, target: &EthereumAddress) -> Vec<&EthereumKeyPair> {
        self.key_pairs
            .iter()
            .filter(|kp| kp.address == *target)
            .collect()
    }
}

/// Utility functions for Ethereum operations
pub mod utils {
    use super::*;
    
    /// Generate a random Ethereum private key for testing
    pub fn generate_random_private_key() -> [u8; 32] {
        use rand::rngs::OsRng;
        use rand::RngCore;
        
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);
        private_key
    }
    
    /// Check if an address string is valid Ethereum format
    pub fn is_valid_ethereum_address(address: &str) -> bool {
        EthereumGenerator::validate_address(address).is_ok()
    }
    
    /// Normalize address string (add 0x prefix if missing, lowercase)
    pub fn normalize_address(address: &str) -> String {
        let address = address.strip_prefix("0x").unwrap_or(address);
        format!("0x{}", address.to_lowercase())
    }
    
    /// Compare two addresses (case-insensitive)
    pub fn addresses_equal(addr1: &str, addr2: &str) -> bool {
        normalize_address(addr1) == normalize_address(addr2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CryptoEngine, DerivedKey};
    
    #[test]
    fn test_ethereum_generator_creation() {
        let _generator = EthereumGenerator::new();
        // Just verify it was created successfully
        assert!(true);
    }
    
    #[test]
    fn test_address_generation() {
        let generator = EthereumGenerator::new();
        
        // Test with a known private key
        let private_key = [
            0x4f, 0x3e, 0xdf, 0x98, 0x3a, 0xc6, 0x36, 0xa9,
            0x0e, 0x25, 0xe5, 0x28, 0xc2, 0x74, 0x8a, 0x33,
            0x4c, 0x09, 0x3d, 0x9c, 0x5c, 0x52, 0x15, 0x5c,
            0x2f, 0xd8, 0x10, 0x4d, 0x86, 0x7c, 0x36, 0xb0,
        ];
        
        let key_pair = generator.generate_address(&private_key).unwrap();
        
        // Verify the structure
        assert_eq!(key_pair.private_key, private_key);
        assert_eq!(key_pair.public_key.key.len(), 64);
        assert_eq!(key_pair.address.address.len(), 20);
    }
    
    #[test]
    fn test_address_from_mnemonic() {
        let crypto_engine = CryptoEngine::new();
        let eth_generator = EthereumGenerator::new();
        
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let derivation_path = "m/44'/60'/0'/0/0";
        
        let derived_key = crypto_engine
            .derive_private_key_from_mnemonic(mnemonic, "", derivation_path)
            .unwrap();
        
        let key_pair = eth_generator
            .generate_address_from_derived_key(&derived_key)
            .unwrap();
        
        // Known test vector for this mnemonic and path
        let expected_address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
        assert_eq!(key_pair.address.to_checksum().to_lowercase(), expected_address.to_lowercase());
    }
    
    #[test]
    fn test_address_validation() {
        let valid_address = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let invalid_address = "0xinvalid";
        
        assert!(EthereumGenerator::validate_address(valid_address).is_ok());
        assert!(EthereumGenerator::validate_address(invalid_address).is_err());
    }
    
    #[test]
    fn test_checksum_address() {
        let address = EthereumAddress::from_hex("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let checksum = address.to_checksum();
        
        // Should maintain the original checksum
        assert_eq!(checksum, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }
    
    #[test]
    fn test_batch_processing() {
        let crypto_engine = CryptoEngine::new();
        let eth_generator = EthereumGenerator::new();
        
        let mnemonics = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ];
        
        let derived_keys: Vec<DerivedKey> = mnemonics
            .iter()
            .map(|mnemonic| {
                crypto_engine
                    .derive_private_key_from_mnemonic(mnemonic, "", "m/44'/60'/0'/0/0")
                    .unwrap()
            })
            .collect();
        
        let batch = EthereumBatch::new(derived_keys);
        let result = eth_generator.process_batch(&batch);
        
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.error_count(), 0);
        assert!(result.all_successful());
        assert_eq!(result.success_rate(), 100.0);
    }
    
    #[test]
    fn test_address_matching() {
        let generator = EthereumGenerator::new();
        let address1 = EthereumAddress::from_hex("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let address2 = EthereumAddress::from_hex("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let address3 = EthereumAddress::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        
        assert!(generator.matches_target(&address1, &address2));
        assert!(!generator.matches_target(&address1, &address3));
    }
    
    #[test]
    fn test_utils() {
        assert!(utils::is_valid_ethereum_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
        assert!(!utils::is_valid_ethereum_address("invalid"));
        
        assert_eq!(
            utils::normalize_address("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        );
        
        assert!(utils::addresses_equal(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        ));
    }
}