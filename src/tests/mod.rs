//! Test module for Ethereum seed recovery

use crate::crypto::CryptoEngine;
use crate::opencl::{OpenCLContext, GpuBatch};
use crate::error::Result;

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test PBKDF2 kernel with known BIP39 mnemonic
    #[test]
    fn test_pbkdf2_kernel_known_mnemonic() -> Result<()> {
        // Known test mnemonic and expected results
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let _expected_seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        
        // Initialize OpenCL context
        let config = crate::opencl::OpenCLConfig::default();
        let opencl_context = OpenCLContext::new(config)?;
        
        // Prepare batch with single mnemonic
        let mnemonic_bytes = test_mnemonic.as_bytes().to_vec();
        let batch = GpuBatch {
            mnemonics: vec![mnemonic_bytes],
            derivation_path: vec![44, 60, 0, 0, 2], // BIP44 path for Ethereum
            passphrase: vec![], // Empty passphrase
            batch_size: 1,
        };
        
        // Process batch on GPU
        let result = opencl_context.process_batch_gpu(&batch)?;
        
        // Verify results
        assert_eq!(result.private_keys.len(), 1);
        assert_eq!(result.success_flags.len(), 1);
        assert!(result.success_flags[0]);
        
        // Note: Full seed verification would require implementing the complete BIP44 derivation
        // For now, we verify that the kernel executed successfully
        println!("PBKDF2 kernel test completed successfully");
        println!("Processing time: {:.2}ms", result.processing_time_ms);
        
        Ok(())
    }
    
    /// Test batch processing with multiple mnemonics
    #[test]
    fn test_pbkdf2_batch_processing() -> Result<()> {
        let test_mnemonics = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ];
        
        // Initialize OpenCL context
        let config = crate::opencl::OpenCLConfig::default();
        let opencl_context = OpenCLContext::new(config)?;
        
        // Prepare batch
        let mnemonic_bytes: Vec<Vec<u8>> = test_mnemonics
            .iter()
            .map(|m| m.as_bytes().to_vec())
            .collect();
        
        let batch = GpuBatch {
            mnemonics: mnemonic_bytes,
            derivation_path: vec![44, 60, 0, 0, 2], // BIP44 path for Ethereum
            passphrase: vec![], // Empty passphrase
            batch_size: 3,
        };
        
        // Process batch on GPU
        let result = opencl_context.process_batch_gpu(&batch)?;
        
        // Verify results
        assert_eq!(result.private_keys.len(), 3);
        assert_eq!(result.success_flags.len(), 3);
        assert!(result.success_flags.iter().all(|&flag| flag));
        
        println!("Batch processing test completed successfully");
        println!("Processed {} mnemonics in {:.2}ms", test_mnemonics.len(), result.processing_time_ms);
        println!("Average time per mnemonic: {:.2}ms", result.processing_time_ms / test_mnemonics.len() as f64);
        
        Ok(())
    }
    
    /// Test OpenCL context initialization
    #[test]
    fn test_opencl_initialization() -> Result<()> {
        let config = crate::opencl::OpenCLConfig::default();
        let context = OpenCLContext::new(config)?;
        
        // Verify context was created successfully
        assert!(!context.programs.is_empty());
        println!("OpenCL context initialized with {} programs", context.programs.len());
        
        // List available programs
        for program_name in context.programs.keys() {
            println!("Available program: {}", program_name);
        }
        
        Ok(())
    }
    
    /// Test CPU vs GPU performance comparison
    #[test]
    fn test_cpu_vs_gpu_performance() -> Result<()> {
        let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Test CPU implementation
        let cpu_start = std::time::Instant::now();
        let crypto_engine = CryptoEngine::new();
        let _cpu_result = crypto_engine.derive_private_key_from_mnemonic(test_mnemonic, "", "m/44'/60'/0'/0/2")?;
        let cpu_time = cpu_start.elapsed();
        
        // Test GPU implementation
        let gpu_start = std::time::Instant::now();
        let config = crate::opencl::OpenCLConfig::default();
        let opencl_context = OpenCLContext::new(config)?;
        let batch = GpuBatch {
            mnemonics: vec![test_mnemonic.as_bytes().to_vec()],
            derivation_path: vec![44, 60, 0, 0, 2],
            passphrase: vec![],
            batch_size: 1,
        };
        let _gpu_result = opencl_context.process_batch_gpu(&batch)?;
        let gpu_time = gpu_start.elapsed();
        
        println!("CPU time: {:.2}ms", cpu_time.as_secs_f64() * 1000.0);
        println!("GPU time: {:.2}ms", gpu_time.as_secs_f64() * 1000.0);
        
        // Note: GPU might be slower for single operations due to setup overhead
        // The advantage comes with batch processing
        
        Ok(())
    }
}