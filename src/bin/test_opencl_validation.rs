//! Test OpenCL implementation against known cryptographic values
//! This validates that our GPU kernels produce the same results as CPU implementations

use ethereum_seed_recovery::{
    opencl::{OpenCLContext, OpenCLConfig, RecoveryBatch},
    error::Result,
};
use hex;
use anyhow;

fn main() -> Result<()> {
    println!("=== Testing OpenCL Implementation Against Known Values ===");
    
    // Initialize OpenCL context
    let config = OpenCLConfig::default();
    let mut opencl_ctx = OpenCLContext::new(config)?;
    opencl_ctx.initialize_kernels()?;
    
    println!("✓ OpenCL context initialized successfully");
    
    // Test data - the exact values provided by the user
    let mnemonic = "frequent lucky inquiry vendor engine dragon horse gorilla pear old dance shield".to_string();
    let target_address_hex = "543bd35f52147370c0decbd440863bc2a002c5c5";
    let mut target_address = [0u8; 20];
    hex::decode_to_slice(target_address_hex, &mut target_address).unwrap();
    
    let derivation_path = [44 + 0x80000000, 60 + 0x80000000, 0x80000000, 0, 2]; // m/44'/60'/0'/0/2
    let passphrase = "".to_string();
    
    // Expected values from user
    let expected_seed = "d553345b0fc89f270166f0a99646bea5478c58a55af3521537290c5ac39d74177d7ec6c052393249131f4ff53dd0f0fab4c73751ebd8e0b4357aada649df6ff1";
    let expected_private_key = "8d3464a68f0218eec3f6b9d869851ed88efeaefc7440c35159f70bfd453dfc9e";
    let expected_public_key = "04d4abed0c0dd336d5da496d6c763812b0bdc0607ef55cd4c0aba92d861f658b00502a0e3e7bf88a72b41a0660aba83953a0b2b581baf173360a31701ea717c124";
    let expected_address = "543bd35f52147370c0decbd440863bc2a002c5c5";
    
    // Create recovery batch
    let batch = RecoveryBatch {
        mnemonics: vec![mnemonic.clone()],
        target_address,
        derivation_path,
        passphrase,
    };
    
    println!("\n=== Testing Complete Recovery Pipeline ===");
    println!("Mnemonic: {}", mnemonic);
    println!("Target Address: 0x{}", target_address_hex);
    println!("Derivation Path: m/44'/60'/0'/0/2");
    
    // Process the batch through OpenCL
    let result = opencl_ctx.process_recovery_batch(&batch)?;
    
    println!("\n=== OpenCL Results ===");
    println!("Processing time: {:.2}ms", result.processing_time_ms);
    println!("Success flags: {:?}", result.success_flags);
    println!("Found matches: {:?}", result.found_matches);
    
    if !result.success_flags.is_empty() && result.success_flags[0] {
        // Extract results
        let generated_private_key = hex::encode(&result.private_keys[0]);
        let generated_public_key = hex::encode(&result.public_keys[0]);
        let generated_address = hex::encode(&result.addresses[0]);
        
        println!("\n=== Validation Results ===");
        
        // Validate private key
        println!("Private Key:");
        println!("  Expected: 0x{}", expected_private_key);
        println!("  Generated: 0x{}", generated_private_key);
        println!("  Match: {}", generated_private_key == expected_private_key);
        
        // Validate public key
        println!("\nPublic Key:");
        println!("  Expected: 0x{}", expected_public_key);
        println!("  Generated: 0x{}", generated_public_key);
        println!("  Match: {}", generated_public_key == expected_public_key);
        
        // Validate address
        println!("\nEthereum Address:");
        println!("  Expected: 0x{}", expected_address);
        println!("  Generated: 0x{}", generated_address);
        println!("  Match: {}", generated_address == expected_address);
        
        // Overall validation
        let all_match = generated_private_key == expected_private_key &&
                       generated_public_key == expected_public_key &&
                       generated_address == expected_address;
        
        println!("\n=== Final Result ===");
        if all_match {
            println!("✅ SUCCESS: All OpenCL kernels produce correct cryptographic results!");
            println!("✅ The GPU implementation matches the expected values exactly.");
        } else {
            println!("❌ FAILURE: OpenCL implementation has discrepancies.");
            return Err(anyhow::anyhow!("Validation failed").into());
        }
        
        // Test that the address matches the target
        if result.matches[0] {
            println!("✅ Address matching logic works correctly.");
        } else {
            println!("❌ Address matching logic failed.");
        }
        
    } else {
        println!("❌ FAILURE: OpenCL processing failed or returned no results.");
        return Err(anyhow::anyhow!("OpenCL processing failed").into());
    }
    
    println!("\n=== Performance Metrics ===");
    println!("Total processing time: {:.2}ms", result.processing_time_ms);
    println!("Throughput: {:.0} mnemonics/second", 1000.0 / result.processing_time_ms);
    
    Ok(())
}