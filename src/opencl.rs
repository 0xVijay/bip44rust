//! OpenCL GPU acceleration for cryptographic operations

use crate::error::{OpenCLError, Result};
use crate::crypto::CryptoBatch;
use ocl::{Platform, Device, Context, Queue, Program, Kernel, Buffer};
use std::collections::HashMap;
use std::fs;
use tracing::{info, debug, error};

/// OpenCL device information
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Device name
    pub name: String,
    /// Device vendor
    pub vendor: String,
    /// Device version
    pub version: String,
    /// Maximum compute units
    pub max_compute_units: u32,
    /// Maximum work group size
    pub max_work_group_size: usize,
    /// Global memory size in bytes
    pub global_memory_size: u64,
    /// Local memory size in bytes
    pub local_memory_size: u64,
    /// Device type (GPU, CPU, etc.)
    pub device_type: String,
}

/// OpenCL platform information
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    /// Platform name
    pub name: String,
    /// Platform vendor
    pub vendor: String,
    /// Platform version
    pub version: String,
    /// Available devices
    pub devices: Vec<DeviceInfo>,
}

/// Configuration for OpenCL operations
#[derive(Debug, Clone)]
pub struct OpenCLConfig {
    /// Platform index to use (None for auto-select)
    pub platform_index: Option<usize>,
    /// Device index to use (None for auto-select)
    pub device_index: Option<usize>,
    /// Work group size for kernels (auto-optimized if None)
    pub work_group_size: Option<usize>,
    /// Global work size for batch processing (auto-calculated)
    pub global_work_size: usize,
    /// Whether to use multiple devices
    pub use_multiple_devices: bool,
    /// Maximum memory per device in MB (auto-calculated if 0)
    pub max_memory_per_device_mb: usize,
    /// Batch size (auto-optimized if 0)
    pub batch_size: usize,
    /// Memory utilization percentage (0.0-1.0)
    pub memory_utilization: f32,
}

/// OpenCL context for GPU operations
#[derive(Debug)]
pub struct OpenCLContext {
    /// OpenCL platform
    _platform: Platform,
    /// OpenCL device
    device: Device,
    /// OpenCL context
    context: Context,
    /// Command queue
    queue: Queue,
    /// Compiled programs
    pub programs: HashMap<String, Program>,
    /// Device information
    device_info: DeviceInfo,
    /// Configuration
    config: OpenCLConfig,
}

/// Batch data for GPU processing
#[derive(Debug)]
pub struct GpuBatch {
    /// Input mnemonics as byte arrays
    pub mnemonics: Vec<Vec<u8>>,
    /// Derivation path components
    pub derivation_path: Vec<u32>,
    /// Passphrase bytes
    pub passphrase: Vec<u8>,
    /// Batch size
    pub batch_size: usize,
}

/// Result of GPU batch processing
#[derive(Debug)]
pub struct GpuBatchResult {
    /// Generated private keys
    pub private_keys: Vec<[u8; 32]>,
    /// Success flags for each input
    pub success_flags: Vec<bool>,
    /// Processing time in milliseconds
    pub processing_time_ms: f64,
}

/// Batch data for complete seed phrase recovery
#[derive(Debug)]
pub struct RecoveryBatch {
    /// Input mnemonic phrases
    pub mnemonics: Vec<String>,
    /// Target Ethereum address to match
    pub target_address: [u8; 20],
    /// Derivation path (BIP44 standard: m/44'/60'/0'/0/2)
    pub derivation_path: [u32; 5],
    /// Passphrase for seed generation
    pub passphrase: String,
}

/// Result of complete recovery processing
#[derive(Debug, Default)]
pub struct RecoveryResult {
    /// Generated Ethereum addresses
    pub addresses: Vec<[u8; 20]>,
    /// Corresponding private keys
    pub private_keys: Vec<[u8; 32]>,
    /// Public keys (uncompressed)
    pub public_keys: Vec<[u8; 64]>,
    /// Match flags (true if address matches target)
    pub matches: Vec<bool>,
    /// Success flags for each operation
    pub success_flags: Vec<bool>,
    /// Processing time in milliseconds
    pub processing_time_ms: f64,
    /// Found matches with their indices
    pub found_matches: Vec<(usize, String)>, // (index, mnemonic)
}

// Note: Kernels are now managed directly through the programs HashMap
// in OpenCLContext for better performance and simpler architecture

impl Default for OpenCLConfig {
    fn default() -> Self {
        Self {
            platform_index: None,
            device_index: None,
            work_group_size: None,
            global_work_size: 0, // Auto-calculated
            use_multiple_devices: false,
            max_memory_per_device_mb: 0, // Auto-calculated
            batch_size: 0, // Auto-optimized
            memory_utilization: 0.8, // Use 80% of available memory
        }
    }
}

impl OpenCLContext {
    /// Create a new OpenCL context
    pub fn new(config: OpenCLConfig) -> Result<Self> {
        // Get available platforms
        let platforms = Platform::list();
        
        if platforms.is_empty() {
            return Err(OpenCLError::Initialization("No OpenCL platforms found".to_string()).into());
        }
        
        // Select platform
        let platform = if let Some(index) = config.platform_index {
            if index >= platforms.len() {
                return Err(OpenCLError::Initialization(format!("Platform index {} out of range", index)).into());
            }
            platforms[index]
        } else {
            // Auto-select best platform (prefer GPU platforms)
            Self::select_best_platform(&platforms)?
        };
        
        info!("Selected OpenCL platform: {}", platform.name().unwrap_or_default());
        
        // Get devices for the platform
        let devices = Device::list_all(platform)
            .map_err(|e| OpenCLError::Initialization(format!("Failed to list devices: {}", e)))?;
        
        if devices.is_empty() {
            return Err(OpenCLError::Initialization("No OpenCL devices found".to_string()).into());
        }
        
        // Select device
        let device = if let Some(index) = config.device_index {
            if index >= devices.len() {
                return Err(OpenCLError::Initialization(format!("Device index {} out of range", index)).into());
            }
            devices[index]
        } else {
            // Auto-select best device (prefer GPU)
            Self::select_best_device(&devices)?
        };
        
        let device_info = Self::get_device_info(&device)?;
        info!("Selected OpenCL device: {} ({})", device_info.name, device_info.device_type);
        
        // Create context and queue
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()
            .map_err(|e| OpenCLError::Initialization(format!("Failed to create context: {}", e)))?;
        
        let queue = Queue::new(&context, device, None)
            .map_err(|e| OpenCLError::Initialization(format!("Failed to create queue: {}", e)))?;
        
        let mut opencl_context = Self {
            _platform: platform,
            device,
            context,
            queue,
            programs: HashMap::new(),
            device_info,
            config,
        };
        
        // Initialize kernels
        opencl_context.initialize_kernels()?;
        
        Ok(opencl_context)
    }
    
    /// Initialize kernels for cryptographic operations
    pub fn initialize_kernels(&mut self) -> Result<()> {
        info!("Initializing OpenCL kernels...");
        
        // Load kernel sources
        let pbkdf2_source = include_str!("kernels/pbkdf2.cl");
        let hmac_source = include_str!("kernels/hmac.cl");
        let bip44_source = include_str!("kernels/bip44.cl");
        let secp256k1_source = fs::read_to_string("src/kernels/secp256k1.cl")?;
        let keccak_source = include_str!("kernels/keccak.cl");
        
        // Compile programs
        self.compile_program("pbkdf2", pbkdf2_source)?;
        self.compile_program("hmac", hmac_source)?;
        
        // Combine secp256k1 and bip44 sources for BIP44 program
        let combined_bip44_source = format!("{}

{}", secp256k1_source, bip44_source);
        self.compile_program("bip44", &combined_bip44_source)?;
        
        self.compile_program("secp256k1", &secp256k1_source)?;
        self.compile_program("keccak", keccak_source)?;
        
        info!("OpenCL kernels initialized successfully");
        Ok(())
    }
    
    /// Compile an OpenCL program from source
    fn compile_program(&mut self, name: &str, source: &str) -> Result<()> {
        debug!("Compiling OpenCL program: {}", name);
        
        let program = Program::builder()
            .devices(self.device)
            .src(source)
            .build(&self.context)
            .map_err(|e| {
                error!("Failed to compile {} program: {}", name, e);
                OpenCLError::KernelCompilation(format!("Failed to compile {}: {}", name, e))
            })?;
        
        self.programs.insert(name.to_string(), program);
        debug!("Successfully compiled OpenCL program: {}", name);
        Ok(())
    }
    
    /// Process a complete recovery batch on GPU (full pipeline)
    pub fn process_recovery_batch(&self, batch: &RecoveryBatch) -> Result<RecoveryResult> {
        let start_time = std::time::Instant::now();
        info!("Processing recovery batch of {} mnemonics", batch.mnemonics.len());
        
        let batch_size = batch.mnemonics.len();
        if batch_size == 0 {
            return Ok(RecoveryResult {
                addresses: Vec::new(),
                private_keys: Vec::new(),
                public_keys: Vec::new(),
                matches: Vec::new(),
                success_flags: Vec::new(),
                processing_time_ms: 0.0,
                found_matches: Vec::new(),
            });
        }
        
        // Step 1: Convert mnemonics to seeds using PBKDF2-HMAC-SHA512
        let seeds = self.process_pbkdf2_batch(batch)?;
        
        // Step 2: Derive master keys and child keys using BIP44
        let private_keys = self.process_bip44_batch(&seeds, &batch.derivation_path)?;
        
        // Step 3: Generate public keys using secp256k1
        let public_keys = self.process_secp256k1_batch(&private_keys)?;
        
        // Step 4: Generate Ethereum addresses using Keccak-256
        let addresses = self.process_keccak_batch(&public_keys)?;
        
        // Step 5: Compare addresses with target
        let (matches, found_matches) = self.compare_addresses(&addresses, &batch.target_address, &batch.mnemonics);
        
        let processing_time = start_time.elapsed().as_secs_f64() * 1000.0;
        
        Ok(RecoveryResult {
            addresses,
            private_keys,
            public_keys,
            matches,
            success_flags: vec![true; batch_size], // All successful for now
            processing_time_ms: processing_time,
            found_matches,
        })
    }
    
    /// Process a batch of mnemonics on GPU (PBKDF2 only)
    pub fn process_batch_gpu(&self, batch: &GpuBatch) -> Result<GpuBatchResult> {
        let start_time = std::time::Instant::now();
        
        // Get the PBKDF2 program
        let program = self.programs.get("pbkdf2")
            .ok_or_else(|| OpenCLError::KernelNotFound("pbkdf2".to_string()))?;
        
        // Create kernel with proper argument placeholders
        let kernel = Kernel::builder()
            .program(program)
            .name("pbkdf2_hmac_sha512")
            .queue(self.queue.clone())
            .global_work_size(batch.len())
            .arg(None::<&Buffer<u8>>)  // passwords
            .arg(None::<&Buffer<i32>>) // password_lengths
            .arg(None::<&Buffer<u8>>)  // salt
            .arg(None::<&Buffer<i32>>) // salt_lengths
            .arg(None::<&Buffer<u8>>)  // output
            .arg(batch.len() as i32)   // batch_size
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create kernel: {}", e)))?;
        
        // Prepare input data with fixed-size padding
        const MNEMONIC_SLOT_SIZE: usize = 256; // Fixed size per mnemonic
        const SALT_SLOT_SIZE: usize = 128;     // Fixed size per salt
        
        let mut padded_mnemonics = vec![0u8; batch.len() * MNEMONIC_SLOT_SIZE];
        let mut mnemonic_lengths = Vec::new();
        
        for (i, mnemonic) in batch.mnemonics.iter().enumerate() {
            let start_idx = i * MNEMONIC_SLOT_SIZE;
            let end_idx = start_idx + mnemonic.len().min(MNEMONIC_SLOT_SIZE);
            padded_mnemonics[start_idx..end_idx].copy_from_slice(&mnemonic[..end_idx - start_idx]);
            mnemonic_lengths.push(mnemonic.len() as i32);
        }
        
        // Prepare salt ("mnemonic" + passphrase) with padding
        let mut salt = b"mnemonic".to_vec();
        salt.extend_from_slice(&batch.passphrase);
        let salt_len = salt.len();
        
        let mut padded_salt = vec![0u8; batch.len() * SALT_SLOT_SIZE];
        for i in 0..batch.len() {
            let start_idx = i * SALT_SLOT_SIZE;
            let end_idx = start_idx + salt_len.min(SALT_SLOT_SIZE);
            padded_salt[start_idx..end_idx].copy_from_slice(&salt[..end_idx - start_idx]);
        }
        let salt_lengths = vec![salt_len as i32; batch.len()];
        
        // Create output buffers
        let mut seeds = vec![0u8; batch.len() * 64]; // 64 bytes per seed
        
        // Create OpenCL buffers
        let mnemonic_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(padded_mnemonics.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create mnemonic buffer: {}", e)))?;

        let mnemonic_lengths_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(mnemonic_lengths.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create mnemonic lengths buffer: {}", e)))?;

        let salt_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(padded_salt.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create salt buffer: {}", e)))?;

        let salt_lengths_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(salt_lengths.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create salt lengths buffer: {}", e)))?;

        let seed_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(seeds.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create seed buffer: {}", e)))?;


        
        // Write input data to buffers
        mnemonic_buffer.write(&padded_mnemonics)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write mnemonic data: {}", e)))?;

        mnemonic_lengths_buffer.write(&mnemonic_lengths)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write mnemonic lengths data: {}", e)))?;

        salt_buffer.write(&padded_salt)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write salt data: {}", e)))?;

        salt_lengths_buffer.write(&salt_lengths)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write salt lengths data: {}", e)))?;
        
        // Set kernel arguments (matching kernel signature: passwords, password_lengths, salt, salt_lengths, output, batch_size)
        kernel.set_arg(0, &mnemonic_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set passwords arg: {}", e)))?;
        kernel.set_arg(1, &mnemonic_lengths_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set password_lengths arg: {}", e)))?;
        kernel.set_arg(2, &salt_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set salt arg: {}", e)))?;
        kernel.set_arg(3, &salt_lengths_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set salt_lengths arg: {}", e)))?;
        kernel.set_arg(4, &seed_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set output arg: {}", e)))?;
        kernel.set_arg(5, batch.len() as i32)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set batch_size arg: {}", e)))?;
        
        // Execute kernel
        unsafe {
            kernel.enq()
                .map_err(|e| OpenCLError::KernelExecution(format!("Kernel execution failed: {}", e)))?;
        }
        
        // Read results
        seed_buffer.read(&mut seeds)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to read seed results: {}", e)))?;
        
        // Convert seeds to private keys (placeholder - will implement BIP44 derivation)
        let private_keys: Vec<[u8; 32]> = seeds.chunks(64)
            .map(|seed| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&seed[0..32]); // Use first 32 bytes as placeholder
                key
            })
            .collect();
        
        // For now, assume all operations succeed (will add proper validation later)
        let success_flags = vec![true; batch.len()];
        
        let result = GpuBatchResult {
            private_keys,
            success_flags,
            processing_time_ms: start_time.elapsed().as_millis() as f64,
        };
        
        Ok(result)
    }
    
    /// Process PBKDF2 batch for seed generation
    pub fn process_pbkdf2_batch(&self, batch: &RecoveryBatch) -> Result<Vec<[u8; 64]>> {
        debug!("Processing PBKDF2 batch for {} mnemonics", batch.mnemonics.len());
        
        // Get the PBKDF2 program
        let program = self.programs.get("pbkdf2")
            .ok_or_else(|| OpenCLError::KernelNotFound("pbkdf2".to_string()))?;
        
        // Create kernel with proper argument placeholders
        let kernel = Kernel::builder()
            .program(program)
            .name("pbkdf2_hmac_sha512")
            .queue(self.queue.clone())
            .global_work_size(batch.mnemonics.len())
            .arg(None::<&Buffer<u8>>)  // passwords
            .arg(None::<&Buffer<i32>>) // password_lengths
            .arg(None::<&Buffer<u8>>)  // salt
            .arg(None::<&Buffer<i32>>) // salt_lengths
            .arg(None::<&Buffer<u8>>)  // output
            .arg(batch.mnemonics.len() as i32)  // batch_size
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create kernel: {}", e)))?;
        
        // Prepare input data with fixed-size slots to match kernel expectations
        let max_mnemonic_len = 256; // Match kernel assumption
        let mut padded_mnemonics = vec![0u8; batch.mnemonics.len() * max_mnemonic_len];
        let mut mnemonic_lengths = Vec::new();
        
        for (i, mnemonic) in batch.mnemonics.iter().enumerate() {
            let mnemonic_bytes = mnemonic.as_bytes();
            let len = mnemonic_bytes.len().min(max_mnemonic_len);
            mnemonic_lengths.push(len as i32);
            
            let offset = i * max_mnemonic_len;
            padded_mnemonics[offset..offset + len].copy_from_slice(&mnemonic_bytes[..len]);
        }
        
        // Prepare salt ("mnemonic" + passphrase) with fixed-size slots
        let max_salt_len = 128; // Match kernel assumption
        let mut salt = b"mnemonic".to_vec();
        salt.extend_from_slice(batch.passphrase.as_bytes());
        let actual_salt_len = salt.len();
        
        let mut padded_salt = vec![0u8; batch.mnemonics.len() * max_salt_len];
        let salt_lengths = vec![actual_salt_len as i32; batch.mnemonics.len()];
        
        // Copy the same salt to each slot
        for i in 0..batch.mnemonics.len() {
            let offset = i * max_salt_len;
            padded_salt[offset..offset + actual_salt_len].copy_from_slice(&salt);
        }
        
        // Create output buffer for 64-byte seeds
        let mut seeds = vec![0u8; batch.mnemonics.len() * 64];
        
        // Create OpenCL buffers
        let mnemonic_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(padded_mnemonics.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create mnemonic buffer: {}", e)))?;

        let mnemonic_lengths_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(mnemonic_lengths.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create mnemonic lengths buffer: {}", e)))?;

        let salt_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(padded_salt.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create salt buffer: {}", e)))?;

        let salt_lengths_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(salt_lengths.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create salt lengths buffer: {}", e)))?;

        let seed_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(seeds.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create seed buffer: {}", e)))?;
        
        // Write input data to buffers
        mnemonic_buffer.write(&padded_mnemonics)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write mnemonic data: {}", e)))?;

        mnemonic_lengths_buffer.write(&mnemonic_lengths)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write mnemonic lengths data: {}", e)))?;

        salt_buffer.write(&padded_salt)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write salt data: {}", e)))?;

        salt_lengths_buffer.write(&salt_lengths)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write salt lengths data: {}", e)))?;
        
        // Set kernel arguments
        kernel.set_arg(0, &mnemonic_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set passwords arg: {}", e)))?;
        kernel.set_arg(1, &mnemonic_lengths_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set password_lengths arg: {}", e)))?;
        kernel.set_arg(2, &salt_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set salt arg: {}", e)))?;
        kernel.set_arg(3, &salt_lengths_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set salt_lengths arg: {}", e)))?;
        kernel.set_arg(4, &seed_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set output arg: {}", e)))?;
        kernel.set_arg(5, batch.mnemonics.len() as i32)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set batch_size arg: {}", e)))?;
        
        // Execute kernel
        unsafe {
            kernel.enq()
                .map_err(|e| OpenCLError::KernelExecution(format!("Kernel execution failed: {}", e)))?;
        }
        
        // Read results
        seed_buffer.read(&mut seeds)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to read seed results: {}", e)))?;
        
        // Convert flat byte array to array of 64-byte seeds
        let result_seeds: Vec<[u8; 64]> = seeds.chunks(64)
            .map(|chunk| {
                let mut seed = [0u8; 64];
                seed.copy_from_slice(chunk);
                seed
            })
            .collect();
        
        Ok(result_seeds)
    }
    
    /// Process BIP44 batch for key derivation
    pub fn process_bip44_batch(&self, seeds: &[[u8; 64]], derivation_path: &[u32; 5]) -> Result<Vec<[u8; 32]>> {
        debug!("Processing BIP44 batch for {} seeds", seeds.len());
        
        let batch_size = seeds.len();
        if batch_size == 0 {
            return Ok(Vec::new());
        }
        
        // Get BIP44 kernel
        let program = self.programs.get("bip44")
            .ok_or_else(|| OpenCLError::KernelNotFound("bip44".to_string()))?;
        
        let kernel = Kernel::builder()
            .program(program)
            .name("bip44_derive_keys")
            .queue(self.queue.clone())
            .global_work_size(batch_size)
            .arg(None::<&Buffer<u8>>)  // master_seeds
            .arg(None::<&Buffer<u8>>)  // private_keys
            .arg(None::<&Buffer<u8>>)  // public_keys
            .arg(None::<&Buffer<i32>>) // success_flags
            .arg(None::<&Buffer<u32>>) // derivation_path
            .arg(0i32)                 // batch_size
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create BIP44 kernel: {}", e)))?;
        
        // Create buffers
        let seeds_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(seeds.len() * 64)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create seeds buffer: {}", e)))?;
        
        let private_keys_buffer: Buffer<u8> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size * 32)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create private keys buffer: {}", e)))?;
        
        let public_keys_buffer: Buffer<u8> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size * 64)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create public keys buffer: {}", e)))?;
        
        let success_flags_buffer: Buffer<i32> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create success flags buffer: {}", e)))?;

        // Create derivation path buffer
        let derivation_path_buffer: Buffer<u32> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(5)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create derivation path buffer: {}", e)))?;

        // Flatten seeds for buffer
        let flattened_seeds: Vec<u8> = seeds.iter().flat_map(|s| s.iter()).cloned().collect();
        
        // Write data to buffers
        seeds_buffer.write(&flattened_seeds).enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write seeds: {}", e)))?;
        
        derivation_path_buffer.write(&derivation_path[..]).enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write derivation path: {}", e)))?;

        // Set kernel arguments
        kernel.set_arg(0, &seeds_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set seeds arg: {}", e)))?;
        kernel.set_arg(1, &private_keys_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set private_keys arg: {}", e)))?;
        kernel.set_arg(2, &public_keys_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set public_keys arg: {}", e)))?;
        kernel.set_arg(3, &success_flags_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set success_flags arg: {}", e)))?;
        kernel.set_arg(4, &derivation_path_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set derivation_path arg: {}", e)))?;
        kernel.set_arg(5, batch_size as i32)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set batch_size arg: {}", e)))?;
        
        // Execute kernel
        unsafe {
            kernel.enq()
                .map_err(|e| OpenCLError::KernelExecution(format!("Failed to execute BIP44 kernel: {}", e)))?;
        }
        
        // Read results
        let mut result_data = vec![0u8; batch_size * 32];
        private_keys_buffer.read(&mut result_data).enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to read BIP44 results: {}", e)))?;
        
        // Convert to private keys
        let private_keys: Vec<[u8; 32]> = result_data
            .chunks_exact(32)
            .map(|chunk| {
                let mut key = [0u8; 32];
                key.copy_from_slice(chunk);
                key
            })
            .collect();
        
        Ok(private_keys)
    }
    
    /// Process secp256k1 batch for public key generation
    fn process_secp256k1_batch(&self, private_keys: &[[u8; 32]]) -> Result<Vec<[u8; 64]>> {
        debug!("Processing secp256k1 batch for {} private keys", private_keys.len());
        
        let batch_size = private_keys.len();
        if batch_size == 0 {
            return Ok(Vec::new());
        }
        
        // Get secp256k1 kernel
        let program = self.programs.get("secp256k1")
            .ok_or_else(|| OpenCLError::KernelNotFound("secp256k1".to_string()))?;
        
        let kernel = Kernel::builder()
            .program(program)
            .name("secp256k1_generate_pubkey")
            .queue(self.queue.clone())
            .global_work_size(batch_size)
            .arg(None::<&Buffer<u8>>)  // private_keys
            .arg(None::<&Buffer<u8>>)  // public_keys
            .arg(None::<&Buffer<i32>>) // success_flags
            .arg(0i32)                 // batch_size
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create secp256k1 kernel: {}", e)))?;
        
        // Create buffers
        let private_keys_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(batch_size * 32)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create private keys buffer: {}", e)))?;
        
        let public_keys_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size * 64)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create public keys buffer: {}", e)))?;
        
        let success_flags_buffer: Buffer<i32> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create success flags buffer: {}", e)))?;
        
        // Flatten private keys for buffer
        let flattened_keys: Vec<u8> = private_keys.iter().flat_map(|k| k.iter()).cloned().collect();
        
        // Write data to buffers
        private_keys_buffer.write(&flattened_keys).enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write private keys: {}", e)))?;
        
        // Set kernel arguments
        kernel.set_arg(0, &private_keys_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set private_keys arg: {}", e)))?;
        kernel.set_arg(1, &public_keys_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set public_keys arg: {}", e)))?;
        kernel.set_arg(2, &success_flags_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set success_flags arg: {}", e)))?;
        kernel.set_arg(3, batch_size as i32)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set batch_size arg: {}", e)))?;
        
        // Execute kernel
        unsafe {
            kernel.enq()
                .map_err(|e| OpenCLError::KernelExecution(format!("Failed to execute secp256k1 kernel: {}", e)))?;
        }
        
        // Read results
        let mut result_data = vec![0u8; batch_size * 64];
        public_keys_buffer.read(&mut result_data).enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to read secp256k1 results: {}", e)))?;
        
        // Convert to public keys
        let public_keys: Vec<[u8; 64]> = result_data
            .chunks_exact(64)
            .map(|chunk| {
                let mut key = [0u8; 64];
                key.copy_from_slice(chunk);
                key
            })
            .collect();
        
        Ok(public_keys)
    }
    
    /// Process Keccak-256 batch for Ethereum address generation
    fn process_keccak_batch(&self, public_keys: &[[u8; 64]]) -> Result<Vec<[u8; 20]>> {
        debug!("Processing Keccak batch for {} public keys", public_keys.len());
        
        let batch_size = public_keys.len();
        if batch_size == 0 {
            return Ok(Vec::new());
        }
        
        // Get Keccak kernel
        let program = self.programs.get("keccak")
            .ok_or_else(|| OpenCLError::KernelNotFound("keccak".to_string()))?;
        
        let kernel = Kernel::builder()
            .program(program)
            .name("generate_ethereum_addresses")
            .queue(self.queue.clone())
            .global_work_size(batch_size)
            .arg(None::<&Buffer<u8>>)  // public_keys
            .arg(None::<&Buffer<u8>>)  // addresses
            .arg(None::<&Buffer<u8>>)  // checksum_addresses
            .arg(None::<&Buffer<i32>>) // success_flags
            .arg(0i32)                 // batch_size
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create Keccak kernel: {}", e)))?;
        
        // Create buffers
        let public_keys_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(batch_size * 64)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create public keys buffer: {}", e)))?;
        
        let addresses_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size * 20)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create addresses buffer: {}", e)))?;
        
        let checksum_addresses_buffer: Buffer<u8> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size * 42)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create checksum addresses buffer: {}", e)))?;
        
        let success_flags_buffer: Buffer<i32> = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size)
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create success flags buffer: {}", e)))?;
        
        // Flatten public keys for buffer
        let flattened_keys: Vec<u8> = public_keys.iter().flat_map(|k| k.iter()).cloned().collect();
        
        // Write data to buffers
        public_keys_buffer.write(&flattened_keys).enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write public keys: {}", e)))?;
        
        // Set kernel arguments
        kernel.set_arg(0, &public_keys_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set public_keys arg: {}", e)))?;
        kernel.set_arg(1, &addresses_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set addresses arg: {}", e)))?;
        kernel.set_arg(2, &checksum_addresses_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set checksum_addresses arg: {}", e)))?;
        kernel.set_arg(3, &success_flags_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set success_flags arg: {}", e)))?;
        kernel.set_arg(4, batch_size as i32)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set batch_size arg: {}", e)))?;
        
        // Execute kernel
        unsafe {
            kernel.enq()
                .map_err(|e| OpenCLError::KernelExecution(format!("Failed to execute Keccak kernel: {}", e)))?;
        }
        
        // Read results
        let mut result_data = vec![0u8; batch_size * 20];
        addresses_buffer.read(&mut result_data).enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to read Keccak results: {}", e)))?;
        
        // Convert to addresses
        let addresses: Vec<[u8; 20]> = result_data
            .chunks_exact(20)
            .map(|chunk| {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(chunk);
                addr
            })
            .collect();
        
        Ok(addresses)
    }
    
    /// Compare generated addresses with target address
    fn compare_addresses(&self, addresses: &[[u8; 20]], target: &[u8; 20], mnemonics: &[String]) -> (Vec<bool>, Vec<(usize, String)>) {
        let matches: Vec<bool> = addresses
            .iter()
            .map(|addr| addr == target)
            .collect();
        
        let found_matches: Vec<(usize, String)> = matches
            .iter()
            .enumerate()
            .filter_map(|(i, &is_match)| {
                if is_match {
                    Some((i, mnemonics[i].clone()))
                } else {
                    None
                }
            })
            .collect();
        
        if !found_matches.is_empty() {
            info!("Found {} matching addresses!", found_matches.len());
            for (index, mnemonic) in &found_matches {
                info!("Match at index {}: {}", index, mnemonic);
            }
        }
        
        (matches, found_matches)
    }
    
    /// Get device information
    pub fn get_device_info(device: &Device) -> Result<DeviceInfo> {
        let name = device.name()
            .map_err(|e| OpenCLError::DeviceQuery(format!("Failed to get device name: {}", e)))?;
        
        let vendor = device.vendor()
            .map_err(|e| OpenCLError::DeviceQuery(format!("Failed to get device vendor: {}", e)))?;
        
        let version = device.version()
            .map_err(|e| OpenCLError::DeviceQuery(format!("Failed to get device version: {}", e)))?;
        
        let max_compute_units = device.info(ocl::core::DeviceInfo::MaxComputeUnits)
            .map_err(|e| OpenCLError::DeviceQuery(format!("Failed to get max compute units: {}", e)))?;
        
        let max_work_group_size = device.info(ocl::core::DeviceInfo::MaxWorkGroupSize)
            .map_err(|e| OpenCLError::DeviceQuery(format!("Failed to get max work group size: {}", e)))?;
        
        let global_memory_size = device.info(ocl::core::DeviceInfo::GlobalMemSize)
            .map_err(|e| OpenCLError::DeviceQuery(format!("Failed to get global memory size: {}", e)))?;
        
        let local_memory_size = device.info(ocl::core::DeviceInfo::LocalMemSize)
            .map_err(|e| OpenCLError::DeviceQuery(format!("Failed to get local memory size: {}", e)))?;
        
        let device_type = device.info(ocl::core::DeviceInfo::Type)
            .map(|dt| format!("{:?}", dt))
            .unwrap_or_else(|_| "Unknown".to_string());
        
        Ok(DeviceInfo {
            name,
            vendor,
            version: version.to_string(),
            max_compute_units: match max_compute_units {
                ocl::core::DeviceInfoResult::MaxComputeUnits(val) => val,
                _ => 0,
            },
            max_work_group_size: match max_work_group_size {
                ocl::core::DeviceInfoResult::MaxWorkGroupSize(val) => val,
                _ => 0,
            },
            global_memory_size: match global_memory_size {
                ocl::core::DeviceInfoResult::GlobalMemSize(val) => val,
                _ => 0,
            },
            local_memory_size: match local_memory_size {
                ocl::core::DeviceInfoResult::LocalMemSize(val) => val,
                _ => 0,
            },
            device_type,
        })
    }
    
    /// Select the best platform (prefer GPU platforms)
    fn select_best_platform(platforms: &[Platform]) -> Result<Platform> {
        for platform in platforms {
            let devices = Device::list_all(*platform)
                .map_err(|e| OpenCLError::Initialization(format!("Failed to list devices: {}", e)))?;
            
            // Check if platform has GPU devices
            for device in devices {
                if let Ok(device_type) = device.info(ocl::core::DeviceInfo::Type) {
                    if format!("{:?}", device_type).contains("Gpu") {
                        return Ok(*platform);
                    }
                }
            }
        }
        
        // Fallback to first platform
        Ok(platforms[0])
    }
    
    /// Select the best device (prefer GPU)
    fn select_best_device(devices: &[Device]) -> Result<Device> {
        // First, try to find a GPU device
        for device in devices {
            if let Ok(device_type) = device.info(ocl::core::DeviceInfo::Type) {
                if format!("{:?}", device_type).contains("Gpu") {
                    return Ok(device.clone());
                }
            }
        }
        
        // Fallback to first device
        devices.first().cloned().ok_or_else(|| OpenCLError::NoDevicesFound.into())
    }
    
    /// Get available platforms and devices
    pub fn list_platforms() -> Result<Vec<PlatformInfo>> {
        let platforms = Platform::list();
        
        let mut platform_infos = Vec::new();
        
        for platform in platforms {
            let name = platform.name().unwrap_or_default();
            let vendor = platform.vendor().unwrap_or_default();
            let version = platform.version().unwrap_or_default();
            
            let devices = Device::list(platform, None)
                .map_err(|e| OpenCLError::Initialization(format!("Failed to list devices: {}", e)))?;
            
            let mut device_infos = Vec::new();
            for device in devices {
                if let Ok(device_info) = Self::get_device_info(&device) {
                    device_infos.push(device_info);
                }
            }
            
            platform_infos.push(PlatformInfo {
                name,
                vendor,
                version,
                devices: device_infos,
            });
        }
        
        Ok(platform_infos)
    }
    
    /// Get current device info
    pub fn device_info(&self) -> &DeviceInfo {
        &self.device_info
    }
    
    /// Get configuration
    pub fn config(&self) -> &OpenCLConfig {
        &self.config
    }
    
    /// Check if GPU acceleration is available
    pub fn is_gpu_available(&self) -> bool {
        self.device_info.device_type.contains("Gpu")
    }
    
    /// Get optimal work group size for current device
    pub fn get_optimal_work_group_size(&self, _kernel_name: &str) -> usize {
        if let Some(size) = self.config.work_group_size {
            return size;
        }
        
        // Auto-optimize based on device capabilities
        let max_wg = self.device_info.max_work_group_size;
        let compute_units = self.device_info.max_compute_units as usize;
        
        // Aim for multiple of 32 (warp/wavefront size) and good occupancy
        let optimal_size = if max_wg >= 256 && compute_units >= 8 {
            256
        } else if max_wg >= 128 && compute_units >= 4 {
            128
        } else if max_wg >= 64 {
            64
        } else {
            32.min(max_wg)
        };
        
        debug!("Auto-optimized work group size: {} (max: {}, CUs: {})", 
               optimal_size, max_wg, compute_units);
        optimal_size
    }

    /// Calculate optimal batch size based on device memory and configuration
    pub fn calculate_optimal_batch_size(&self, bytes_per_item: usize) -> usize {
        if self.config.batch_size > 0 {
            return self.config.batch_size;
        }
        
        let total_memory = self.device_info.global_memory_size as f64;
        let available_memory = (total_memory * self.config.memory_utilization as f64) as usize;
        
        // Reserve memory for kernels, buffers, and overhead
        let usable_memory = (available_memory as f64 * 0.7) as usize; // 70% for actual data
        
        // Calculate based on memory per item (includes all buffers needed)
        let memory_per_item = bytes_per_item * 4; // Account for multiple buffers
        let max_items_by_memory = usable_memory / memory_per_item;
        
        // Consider compute capability
        let compute_units = self.device_info.max_compute_units as usize;
        let work_group_size = self.get_optimal_work_group_size("pbkdf2");
        let max_items_by_compute = compute_units * work_group_size * 32; // 32 batches per CU
        
        let optimal_batch = max_items_by_memory.min(max_items_by_compute).min(1_000_000);
        
        info!("Auto-optimized batch size: {} (memory limit: {}, compute limit: {})",
              optimal_batch, max_items_by_memory, max_items_by_compute);
        
        optimal_batch.max(1024) // Minimum batch size
    }
    
    /// Calculate optimal global work size
    pub fn calculate_optimal_global_work_size(&self, batch_size: usize) -> usize {
        if self.config.global_work_size > 0 {
            return self.config.global_work_size;
        }
        
        let work_group_size = self.get_optimal_work_group_size("pbkdf2");
        // Round up to nearest multiple of work group size
        ((batch_size + work_group_size - 1) / work_group_size) * work_group_size
    }
    
    /// Get auto-optimized memory allocation per device
    pub fn get_optimal_memory_per_device_mb(&self) -> usize {
        if self.config.max_memory_per_device_mb > 0 {
            return self.config.max_memory_per_device_mb;
        }
        
        let total_memory_mb = (self.device_info.global_memory_size / 1024 / 1024) as usize;
        let usable_memory_mb = (total_memory_mb as f32 * self.config.memory_utilization) as usize;
        
        info!("Auto-calculated memory per device: {} MB (total: {} MB)", 
              usable_memory_mb, total_memory_mb);
        
        usable_memory_mb
    }
}

impl GpuBatch {
    /// Create a new GPU batch
    pub fn new(
        mnemonics: Vec<Vec<u8>>,
        derivation_path: Vec<u32>,
        passphrase: Vec<u8>,
    ) -> Self {
        let batch_size = mnemonics.len();
        Self {
            mnemonics,
            derivation_path,
            passphrase,
            batch_size,
        }
    }
    
    /// Convert from CPU crypto batch
    pub fn from_crypto_batch(batch: &CryptoBatch) -> Self {
        let mnemonics: Vec<Vec<u8>> = batch.mnemonics
            .iter()
            .map(|m| m.as_bytes().to_vec())
            .collect();
        
        // Parse derivation path (simplified)
        let derivation_path = vec![44 | 0x80000000, 60 | 0x80000000, 0x80000000, 0, 0]; // m/44'/60'/0'/0/0
        
        let passphrase = batch.passphrase.as_bytes().to_vec();
        
        Self::new(mnemonics, derivation_path, passphrase)
    }
    
    /// Get batch size
    pub fn len(&self) -> usize {
        self.batch_size
    }
    
    /// Check if batch is empty
    pub fn is_empty(&self) -> bool {
        self.batch_size == 0
    }
}

/// Utility functions for OpenCL operations
pub mod utils {
    use super::*;
    
    /// Check if OpenCL is available on the system
    pub fn is_opencl_available() -> bool {
        !Platform::list().is_empty()
    }
    
    /// Get system OpenCL information
    pub fn get_system_info() -> Result<String> {
        let platforms = OpenCLContext::list_platforms()?;
        
        let mut info = String::new();
        info.push_str("OpenCL System Information:\n");
        info.push_str(&format!("Found {} platform(s)\n\n", platforms.len()));
        
        for (i, platform) in platforms.iter().enumerate() {
            info.push_str(&format!("Platform {}: {}\n", i, platform.name));
            info.push_str(&format!("  Vendor: {}\n", platform.vendor));
            info.push_str(&format!("  Version: {}\n", platform.version));
            info.push_str(&format!("  Devices: {}\n", platform.devices.len()));
            
            for (j, device) in platform.devices.iter().enumerate() {
                info.push_str(&format!("    Device {}: {} ({})\n", j, device.name, device.device_type));
                info.push_str(&format!("      Compute Units: {}\n", device.max_compute_units));
                info.push_str(&format!("      Max Work Group Size: {}\n", device.max_work_group_size));
                info.push_str(&format!("      Global Memory: {:.1} MB\n", device.global_memory_size as f64 / (1024.0 * 1024.0)));
                info.push_str(&format!("      Local Memory: {:.1} KB\n", device.local_memory_size as f64 / 1024.0));
            }
            info.push('\n');
        }
        
        Ok(info)
    }
    
    /// Recommend optimal configuration for the system
    pub fn recommend_config() -> Result<OpenCLConfig> {
        let platforms = OpenCLContext::list_platforms()?;
        
        // Find the best GPU device
        for (platform_idx, platform) in platforms.iter().enumerate() {
            for (device_idx, device) in platform.devices.iter().enumerate() {
                if device.device_type.contains("Gpu") {
                    return Ok(OpenCLConfig {
                        platform_index: Some(platform_idx),
                        device_index: Some(device_idx),
                        work_group_size: Some(256),
                        global_work_size: 65536,
                        use_multiple_devices: false,
                        max_memory_per_device_mb: (device.global_memory_size / (1024 * 1024) / 2) as usize, // Use half of available memory
                        batch_size: 0, // Auto-calculate
                        memory_utilization: 0.8,
                    });
                }
            }
        }
        
        // Fallback to CPU configuration
        Ok(OpenCLConfig {
            platform_index: Some(0),
            device_index: Some(0),
            work_group_size: Some(64),
            global_work_size: 1024,
            use_multiple_devices: false,
            max_memory_per_device_mb: 512,
            batch_size: 0, // Auto-calculate
            memory_utilization: 0.8,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_opencl_availability() {
        // This test will pass if OpenCL is available, skip if not
        if utils::is_opencl_available() {
            println!("OpenCL is available");
            
            if let Ok(info) = utils::get_system_info() {
                println!("{}", info);
            }
        } else {
            println!("OpenCL is not available, skipping test");
        }
    }
    
    #[test]
    fn test_config_creation() {
        let config = OpenCLConfig::default();
        assert_eq!(config.global_work_size, 0); // Auto-calculate
        assert_eq!(config.batch_size, 0); // Auto-calculate
        assert_eq!(config.memory_utilization, 0.8);
        assert!(!config.use_multiple_devices);
    }
    
    #[test]
    fn test_gpu_batch_creation() {
        let mnemonics = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".as_bytes().to_vec(),
        ];
        let derivation_path = vec![44 | 0x80000000, 60 | 0x80000000, 0x80000000, 0, 0];
        let passphrase = "".as_bytes().to_vec();
        
        let batch = GpuBatch::new(mnemonics, derivation_path, passphrase);
        assert_eq!(batch.len(), 1);
        assert!(!batch.is_empty());
    }
    
    #[test]
    fn test_platform_listing() {
        if utils::is_opencl_available() {
            let platforms = OpenCLContext::list_platforms();
            assert!(platforms.is_ok());
            
            if let Ok(platforms) = platforms {
                assert!(!platforms.is_empty());
                
                for platform in platforms {
                    assert!(!platform.name.is_empty());
                    // Devices list can be empty for some platforms
                }
            }
        }
    }
}