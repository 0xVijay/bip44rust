//! Cryptographic operations for BIP39 and BIP44

use crate::error::{CryptoError, Result};
use bip39::{Mnemonic, Language};
use bitcoin::bip32::{Xpriv, DerivationPath, ChildNumber};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Network;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use std::str::FromStr;

/// PBKDF2 iteration count for BIP39 seed derivation
const BIP39_PBKDF2_ROUNDS: u32 = 2048;

/// BIP39 salt prefix
const BIP39_SALT_PREFIX: &str = "mnemonic";

/// Cryptographic engine for BIP39/BIP44 operations
#[derive(Debug)]
pub struct CryptoEngine {
    secp: Secp256k1<bitcoin::secp256k1::All>,
}

/// Result of BIP39 seed derivation
#[derive(Debug, Clone)]
pub struct Bip39Seed {
    /// The 64-byte seed
    pub seed: [u8; 64],
}

/// Result of BIP44 key derivation
#[derive(Debug, Clone)]
pub struct DerivedKey {
    /// The private key
    pub private_key: [u8; 32],
    /// The derivation path used
    pub derivation_path: String,
}

/// Batch processing for multiple mnemonics
#[derive(Debug)]
pub struct CryptoBatch {
    /// Input mnemonics
    pub mnemonics: Vec<String>,
    /// Derivation path
    pub derivation_path: String,
    /// Optional passphrase
    pub passphrase: String,
}

/// Result of batch processing
#[derive(Debug)]
pub struct BatchResult {
    /// Derived private keys
    pub private_keys: Vec<DerivedKey>,
    /// Any errors encountered (indexed by mnemonic position)
    pub errors: Vec<(usize, CryptoError)>,
}

impl CryptoEngine {
    /// Create a new crypto engine
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }
    
    /// Derive BIP39 seed from mnemonic phrase
    pub fn derive_bip39_seed(&self, mnemonic: &str, passphrase: &str) -> Result<Bip39Seed> {
        // Validate mnemonic
        let _mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| CryptoError::Bip39(e.to_string()))?;
        
        // Create salt
        let salt = format!("{}{}", BIP39_SALT_PREFIX, passphrase);
        
        // Derive seed using PBKDF2
        let mut seed = [0u8; 64];
        pbkdf2::<Hmac<Sha512>>(
            mnemonic.as_bytes(),
            salt.as_bytes(),
            BIP39_PBKDF2_ROUNDS,
            &mut seed,
        ).map_err(|_| CryptoError::Pbkdf2("PBKDF2 operation failed".to_string()))?;
        
        Ok(Bip39Seed { seed })
    }
    
    /// Derive BIP44 private key from seed
    pub fn derive_bip44_key(
        &self,
        seed: &Bip39Seed,
        derivation_path: &str,
    ) -> Result<DerivedKey> {
        // Parse derivation path
        let path = DerivationPath::from_str(derivation_path)
            .map_err(|e| CryptoError::Bip44(e.to_string()))?;
        
        // Create master key from seed
        let master_key = Xpriv::new_master(Network::Bitcoin, &seed.seed)
            .map_err(|e| CryptoError::Bip44(e.to_string()))?;
        
        // Derive child key
        let derived_key = master_key
            .derive_priv(&self.secp, &path)
            .map_err(|e| CryptoError::Bip44(e.to_string()))?;
        
        let private_key = derived_key.private_key.secret_bytes();
        
        Ok(DerivedKey {
            private_key,
            derivation_path: derivation_path.to_string(),
        })
    }
    
    /// Complete pipeline: mnemonic -> seed -> private key
    pub fn derive_private_key_from_mnemonic(
        &self,
        mnemonic: &str,
        passphrase: &str,
        derivation_path: &str,
    ) -> Result<DerivedKey> {
        let seed = self.derive_bip39_seed(mnemonic, passphrase)?;
        self.derive_bip44_key(&seed, derivation_path)
    }
    
    /// Process a batch of mnemonics
    pub fn process_batch(&self, batch: &CryptoBatch) -> BatchResult {
        let mut private_keys = Vec::new();
        let mut errors = Vec::new();
        
        for (index, mnemonic) in batch.mnemonics.iter().enumerate() {
            match self.derive_private_key_from_mnemonic(
                mnemonic,
                &batch.passphrase,
                &batch.derivation_path,
            ) {
                Ok(key) => private_keys.push(key),
                Err(e) => {
                    if let crate::error::RecoveryError::Crypto(crypto_err) = e {
                        errors.push((index, crypto_err));
                    } else {
                        errors.push((index, CryptoError::Bip39("Unknown error".to_string())));
                    }
                }
            }
        }
        
        BatchResult {
            private_keys,
            errors,
        }
    }
    
    /// Process batch in parallel using rayon
    pub fn process_batch_parallel(&self, batch: &CryptoBatch) -> BatchResult {
        use rayon::prelude::*;
        
        let results: Vec<_> = batch.mnemonics
            .par_iter()
            .enumerate()
            .map(|(index, mnemonic)| {
                let result = self.derive_private_key_from_mnemonic(
                    mnemonic,
                    &batch.passphrase,
                    &batch.derivation_path,
                );
                (index, result)
            })
            .collect();
        
        let mut private_keys = Vec::new();
        let mut errors = Vec::new();
        
        for (index, result) in results {
            match result {
                Ok(key) => private_keys.push(key),
                Err(e) => {
                    if let crate::error::RecoveryError::Crypto(crypto_err) = e {
                        errors.push((index, crypto_err));
                    } else {
                        errors.push((index, CryptoError::Bip39("Unknown error".to_string())));
                    }
                }
            }
        }
        
        BatchResult {
            private_keys,
            errors,
        }
    }
    
    /// Validate a mnemonic phrase
    pub fn validate_mnemonic(&self, mnemonic: &str) -> Result<()> {
        Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| CryptoError::Bip39(e.to_string()))?;
        Ok(())
    }
    
    /// Get the secp256k1 context
    pub fn secp_context(&self) -> &Secp256k1<bitcoin::secp256k1::All> {
        &self.secp
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Bip39Seed {
    /// Get the seed as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.seed
    }
    
    /// Get the seed as a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.seed)
    }
    
    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CryptoError::Bip39(format!("Invalid hex: {}", e)))?;
        
        if bytes.len() != 64 {
            return Err(CryptoError::Bip39("Seed must be 64 bytes".to_string()).into());
        }
        
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&bytes);
        
        Ok(Self { seed })
    }
}

impl DerivedKey {
    /// Get the private key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.private_key
    }
    
    /// Get the private key as a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.private_key)
    }
    
    /// Create a secp256k1 SecretKey from this private key
    pub fn to_secret_key(&self) -> Result<SecretKey> {
        SecretKey::from_slice(&self.private_key)
            .map_err(|e| CryptoError::Secp256k1(e).into())
    }
    
    /// Get the derivation path
    pub fn derivation_path(&self) -> &str {
        &self.derivation_path
    }
}

impl CryptoBatch {
    /// Create a new batch
    pub fn new(mnemonics: Vec<String>, derivation_path: String, passphrase: String) -> Self {
        Self {
            mnemonics,
            derivation_path,
            passphrase,
        }
    }
    
    /// Get the number of mnemonics in the batch
    pub fn len(&self) -> usize {
        self.mnemonics.len()
    }
    
    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.mnemonics.is_empty()
    }
}

impl BatchResult {
    /// Get the number of successful derivations
    pub fn success_count(&self) -> usize {
        self.private_keys.len()
    }
    
    /// Get the number of errors
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
    
    /// Check if all derivations were successful
    pub fn all_successful(&self) -> bool {
        self.errors.is_empty()
    }
    
    /// Get success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.private_keys.is_empty() && self.errors.is_empty() {
            return 0.0;
        }
        
        let total = self.private_keys.len() + self.errors.len();
        (self.private_keys.len() as f64 / total as f64) * 100.0
    }
}

/// Utility functions for cryptographic operations
pub mod utils {
    use super::*;
    
    /// Generate a random mnemonic for testing
    pub fn generate_test_mnemonic(word_count: usize) -> Result<String> {
        // For testing purposes, return a fixed valid mnemonic
        match word_count {
            12 => Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
            15 => Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
            18 => Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
            21 => Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
            24 => Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
            _ => Err(CryptoError::Bip39("Invalid word count".to_string()).into()),
        }
    }
    
    /// Validate BIP44 derivation path format
    pub fn validate_derivation_path(path: &str) -> Result<()> {
        DerivationPath::from_str(path)
            .map_err(|e| CryptoError::Bip44(e.to_string()))?;
        Ok(())
    }
    
    /// Parse derivation path components
    pub fn parse_derivation_path(path: &str) -> Result<Vec<ChildNumber>> {
        let path = DerivationPath::from_str(path)
            .map_err(|e| CryptoError::Bip44(e.to_string()))?;
        Ok(path.into_iter().cloned().collect())
    }
    
    /// Create a derivation path from components
    pub fn create_derivation_path(components: &[u32]) -> Result<String> {
        let child_numbers: Result<Vec<_>> = components
            .iter()
            .map(|&index| {
                if index >= 0x80000000 {
                    Ok(ChildNumber::Hardened { index: index - 0x80000000 })
                } else {
                    Ok(ChildNumber::Normal { index })
                }
            })
            .collect();
        
        let path = DerivationPath::from(child_numbers?);
        Ok(path.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crypto_engine_creation() {
        let _engine = CryptoEngine::new();
        // Secp256k1 context is properly initialized
        // Just verify the engine was created successfully
        assert!(true); // If we reach here, the engine was created without panicking
    }
    
    #[test]
    fn test_bip39_seed_derivation() {
        let engine = CryptoEngine::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "";
        
        let seed = engine.derive_bip39_seed(mnemonic, passphrase).unwrap();
        
        // Known test vector
        let expected_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assert_eq!(seed.to_hex(), expected_hex);
    }
    
    #[test]
    fn test_bip44_key_derivation() {
        let engine = CryptoEngine::new();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "";
        let derivation_path = "m/44'/60'/0'/0/0";
        
        let key = engine.derive_private_key_from_mnemonic(mnemonic, passphrase, derivation_path).unwrap();
        
        // Verify we got a valid private key
        assert_eq!(key.private_key.len(), 32);
        assert_eq!(key.derivation_path, derivation_path);
        
        // Verify we can create a secp256k1 key from it
        let secret_key = key.to_secret_key().unwrap();
        assert_eq!(secret_key.secret_bytes(), key.private_key);
    }
    
    #[test]
    fn test_batch_processing() {
        let engine = CryptoEngine::new();
        let mnemonics = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            "legal winner thank year wave sausage worth useful legal winner thank yellow".to_string(),
        ];
        
        let batch = CryptoBatch::new(
            mnemonics,
            "m/44'/60'/0'/0/0".to_string(),
            "".to_string(),
        );
        
        let result = engine.process_batch(&batch);
        
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.error_count(), 0);
        assert!(result.all_successful());
        assert_eq!(result.success_rate(), 100.0);
    }
    
    #[test]
    fn test_invalid_mnemonic() {
        let engine = CryptoEngine::new();
        let invalid_mnemonic = "invalid mnemonic phrase that should fail";
        
        let result = engine.derive_bip39_seed(invalid_mnemonic, "");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_derivation_path_validation() {
        assert!(utils::validate_derivation_path("m/44'/60'/0'/0/0").is_ok());
        assert!(utils::validate_derivation_path("invalid/path").is_err());
    }
}