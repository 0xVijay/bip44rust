//! Error types for the Ethereum seed phrase recovery tool

use thiserror::Error;

/// Main error type for the application
#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("OpenCL error: {0}")]
    OpenCL(#[from] OpenCLError),

    #[error("Generator error: {0}")]
    Generator(#[from] GeneratorError),

    #[error("Ethereum error: {0}")]
    Ethereum(#[from] EthereumError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid mnemonic length: {0}. Must be between 12 and 24")]
    InvalidMnemonicLength(usize),

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("Invalid Ethereum address: {0}")]
    InvalidEthereumAddress(String),

    #[error("Empty word constraints for position {0}")]
    EmptyWordConstraints(usize),

    #[error("Missing word constraints for position {0}")]
    MissingWordConstraints(usize),

    #[error("Invalid word in constraints: {0}")]
    InvalidWord(String),

    #[error("Unsupported wallet type: {0}")]
    UnsupportedWalletType(String),

    #[error("Invalid batch size: {0}. Must be greater than 0")]
    InvalidBatchSize(usize),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("BIP39 error: {0}")]
    Bip39(String),

    #[error("BIP44 derivation error: {0}")]
    Bip44(String),

    #[error("PBKDF2 error: {0}")]
    Pbkdf2(String),

    #[error("HMAC error: {0}")]
    Hmac(String),

    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Key derivation failed at path: {0}")]
    KeyDerivationFailed(String),
}

/// OpenCL-related errors
#[derive(Error, Debug)]
pub enum OpenCLError {
    #[error("OpenCL initialization failed: {0}")]
    InitializationFailed(String),

    #[error("OpenCL initialization error: {0}")]
    Initialization(String),

    #[error("Device query failed: {0}")]
    DeviceQuery(String),

    #[error("Kernel compilation failed: {0}")]
    KernelCompilation(String),

    #[error("No OpenCL devices found")]
    NoDevicesFound,

    #[error("Kernel compilation failed: {0}")]
    KernelCompilationFailed(String),

    #[error("Kernel execution failed: {0}")]
    KernelExecutionFailed(String),

    #[error("Memory allocation failed: {0}")]
    MemoryAllocationFailed(String),

    #[error("Buffer creation failed: {0}")]
    BufferCreationFailed(String),

    #[error("Data transfer failed: {0}")]
    DataTransferFailed(String),

    #[error("Device not supported: {0}")]
    DeviceNotSupported(String),

    #[error("OpenCL error: {0}")]
    Ocl(String),

    #[error("Kernel not found: {0}")]
    KernelNotFound(String),

    #[error("Kernel execution failed: {0}")]
    KernelExecution(String),
}

/// Candidate generation errors
#[derive(Error, Debug)]
pub enum GeneratorError {
    #[error("Search space too large: {0} combinations")]
    SearchSpaceTooLarge(u64),

    #[error("No valid candidates generated")]
    NoValidCandidates,

    #[error("Invalid word combination at positions: {0:?}")]
    InvalidWordCombination(Vec<usize>),

    #[error("Generator exhausted")]
    Exhausted,
}

/// Ethereum-specific errors
#[derive(Error, Debug)]
pub enum EthereumError {
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    #[error("Address generation failed: {0}")]
    AddressGenerationFailed(String),

    #[error("Invalid checksum: {0}")]
    InvalidChecksum(String),

    #[error("Checksum validation failed for address: {0}")]
    ChecksumValidationFailed(String),

    #[error("Keccak hash error: {0}")]
    KeccakError(String),
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, RecoveryError>;

/// Convert ocl errors to our error type
impl From<ocl::Error> for OpenCLError {
    fn from(err: ocl::Error) -> Self {
        OpenCLError::Ocl(err.to_string())
    }
}

/// Convert bitcoin errors to our crypto error type
impl From<bitcoin::bip32::Error> for CryptoError {
    fn from(err: bitcoin::bip32::Error) -> Self {
        CryptoError::Bip44(err.to_string())
    }
}

/// Convert bip39 errors to our crypto error type
impl From<bip39::Error> for CryptoError {
    fn from(err: bip39::Error) -> Self {
        CryptoError::Bip39(err.to_string())
    }
}

/// Convert anyhow::Error to RecoveryError
impl From<anyhow::Error> for RecoveryError {
    fn from(err: anyhow::Error) -> Self {
        RecoveryError::Internal(err.to_string())
    }
}