//! OpenCL GPU acceleration for cryptographic operations

use crate::error::{OpenCLError, Result};
use crate::crypto::CryptoBatch;
use ocl::{Platform, Device, Context, Queue, Program, Kernel, Buffer};
use std::collections::HashMap;
use tracing::{info, debug, warn, error};

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
    /// Work group size for kernels
    pub work_group_size: Option<usize>,
    /// Global work size (total threads)
    pub global_work_size: usize,
    /// Whether to use multiple devices
    pub use_multiple_devices: bool,
    /// Maximum memory usage per device (MB)
    pub max_memory_per_device_mb: usize,
}

/// OpenCL context for GPU operations
#[derive(Debug)]
pub struct OpenCLContext {
    /// OpenCL platform
    platform: Platform,
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

/// OpenCL kernel manager
#[derive(Debug)]
pub struct KernelManager {
    /// PBKDF2 kernel for BIP39 seed derivation
    pbkdf2_kernel: Option<Kernel>,
    /// HMAC-SHA512 kernel for BIP44 derivation
    hmac_kernel: Option<Kernel>,
    /// secp256k1 kernel for key operations
    secp256k1_kernel: Option<Kernel>,
    /// Keccak-256 kernel for Ethereum addresses
    keccak_kernel: Option<Kernel>,
}

impl Default for OpenCLConfig {
    fn default() -> Self {
        Self {
            platform_index: None,
            device_index: None,
            work_group_size: None,
            global_work_size: 1024,
            use_multiple_devices: false,
            max_memory_per_device_mb: 1024,
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
            platform,
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
        let secp256k1_source = include_str!("kernels/secp256k1.cl");
        let keccak_source = include_str!("kernels/keccak.cl");
        
        // Compile programs
        self.compile_program("pbkdf2", pbkdf2_source)?;
        self.compile_program("hmac", hmac_source)?;
        self.compile_program("secp256k1", secp256k1_source)?;
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
    
    /// Process a batch of mnemonics on GPU using PBKDF2 kernel
    pub fn process_batch_gpu(&self, batch: &GpuBatch) -> Result<GpuBatchResult> {
        let start_time = std::time::Instant::now();
        
        // Get the PBKDF2 program
        let program = self.programs.get("pbkdf2")
            .ok_or_else(|| OpenCLError::KernelNotFound("pbkdf2".to_string()))?;
        
        // Create kernel with proper argument count
        let kernel = Kernel::builder()
            .program(program)
            .name("pbkdf2_bip39_batch_kernel")
            .queue(self.queue.clone())
            .global_work_size(batch.len())
            .arg(None::<&Buffer<u8>>)  // mnemonics
            .arg(None::<&Buffer<i32>>) // mnemonic_lengths
            .arg(None::<&Buffer<u8>>)  // salt
            .arg(0i32)                 // salt_length
            .arg(None::<&Buffer<u8>>)  // seeds
            .arg(None::<&Buffer<i32>>) // success_flags
            .arg(0i32)                 // batch_size
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create kernel: {}", e)))?;
        
        // Prepare input data
        let mut flattened_mnemonics = Vec::new();
        let mut mnemonic_lengths = Vec::new();
        
        for mnemonic in &batch.mnemonics {
            mnemonic_lengths.push(mnemonic.len() as i32);
            flattened_mnemonics.extend_from_slice(mnemonic);
        }
        
        // Prepare salt ("mnemonic" + passphrase)
        let mut salt = b"mnemonic".to_vec();
        salt.extend_from_slice(&batch.passphrase);
        
        // Create output buffers
        let mut seeds = vec![0u8; batch.len() * 64]; // 64 bytes per seed
        let mut success_flags = vec![0i32; batch.len()];
        
        // Create OpenCL buffers
        let mnemonic_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(flattened_mnemonics.len())
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
            .len(salt.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create salt buffer: {}", e)))?;

        let seed_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(seeds.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create seed buffer: {}", e)))?;

        let success_flags_buffer = Buffer::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(success_flags.len())
            .build()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to create success flags buffer: {}", e)))?;
        
        // Write input data to buffers
        mnemonic_buffer.write(&flattened_mnemonics)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write mnemonic data: {}", e)))?;

        mnemonic_lengths_buffer.write(&mnemonic_lengths)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write mnemonic lengths data: {}", e)))?;

        salt_buffer.write(&salt)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to write salt data: {}", e)))?;
        
        // Set kernel arguments (matching kernel signature)
        kernel.set_arg(0, &mnemonic_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set mnemonic arg: {}", e)))?;
        kernel.set_arg(1, &mnemonic_lengths_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set mnemonic lengths arg: {}", e)))?;
        kernel.set_arg(2, &salt_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set salt arg: {}", e)))?;
        kernel.set_arg(3, salt.len() as i32)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set salt length: {}", e)))?;
        kernel.set_arg(4, &seed_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set seed arg: {}", e)))?;
        kernel.set_arg(5, &success_flags_buffer)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set success flags arg: {}", e)))?;
        kernel.set_arg(6, batch.len() as i32)
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to set batch size: {}", e)))?;
        
        // Execute kernel
        unsafe {
            kernel.enq()
                .map_err(|e| OpenCLError::KernelExecution(format!("Kernel execution failed: {}", e)))?;
        }
        
        // Read results
        seed_buffer.read(&mut seeds)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to read seed results: {}", e)))?;

        success_flags_buffer.read(&mut success_flags)
            .enq()
            .map_err(|e| OpenCLError::KernelExecution(format!("Failed to read success flags: {}", e)))?;
        
        // Convert seeds to private keys (placeholder - will implement BIP44 derivation)
        let private_keys: Vec<[u8; 32]> = seeds.chunks(64)
            .map(|seed| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&seed[0..32]); // Use first 32 bytes as placeholder
                key
            })
            .collect();
        
        let result = GpuBatchResult {
            private_keys,
            success_flags: success_flags.into_iter().map(|f| f != 0).collect(),
            processing_time_ms: start_time.elapsed().as_millis() as f64,
        };
        
        Ok(result)
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
        // This is a simplified implementation
        // In practice, you would query the kernel for optimal work group size
        if let Some(configured_size) = self.config.work_group_size {
            configured_size.min(self.device_info.max_work_group_size)
        } else {
            // Use a reasonable default based on device type
            if self.is_gpu_available() {
                256.min(self.device_info.max_work_group_size)
            } else {
                64.min(self.device_info.max_work_group_size)
            }
        }
    }
    
    /// Calculate optimal batch size based on device memory
    pub fn calculate_optimal_batch_size(&self, bytes_per_item: usize) -> usize {
        let available_memory = (self.device_info.global_memory_size as f64 * 0.8) as usize; // Use 80% of memory
        let max_items = available_memory / bytes_per_item;
        
        // Ensure it's a multiple of work group size
        let work_group_size = self.get_optimal_work_group_size("default");
        (max_items / work_group_size) * work_group_size
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
        assert_eq!(config.global_work_size, 1024);
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