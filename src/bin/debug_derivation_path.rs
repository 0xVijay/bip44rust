use anyhow::Result;
use bip39::{Mnemonic, Language};
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::Network;
use ethereum_seed_recovery::opencl::{OpenCLContext, OpenCLConfig};
use std::str::FromStr;

fn main() -> Result<()> {
    println!("=== Derivation Path Debug Test ===");
    
    // Use a hardcoded mnemonic for consistency
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    
    println!("Seed: {}", hex::encode(&seed));
    
    // Test different derivation path formats
    println!("\n=== Testing Different Derivation Path Formats ===");
    
    // 1. Standard hardened path (what we expect)
    let standard_path = DerivationPath::from_str("m/44'/60'/0'/0/2")?;
    let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;
    let derived_standard = xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &standard_path)?;
    println!("Standard path (m/44'/60'/0'/0/2): {}", hex::encode(derived_standard.private_key.secret_bytes()));
    
    // 2. Manual construction with hardened indices
    let manual_path = DerivationPath::from(vec![
        bitcoin::bip32::ChildNumber::from_hardened_idx(44)?,
        bitcoin::bip32::ChildNumber::from_hardened_idx(60)?,
        bitcoin::bip32::ChildNumber::from_hardened_idx(0)?,
        bitcoin::bip32::ChildNumber::from_normal_idx(0)?,
        bitcoin::bip32::ChildNumber::from_normal_idx(2)?,
    ]);
    let derived_manual = xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &manual_path)?;
    println!("Manual hardened path: {}", hex::encode(derived_manual.private_key.secret_bytes()));
    
    // 3. GPU implementation with raw values
    let config = OpenCLConfig::default();
    let context = OpenCLContext::new(config)?;
    
    let seeds = vec![seed.try_into().expect("Seed should be 64 bytes")];
    let derivation_path = [44u32, 60, 0, 0, 2]; // Raw values, GPU adds hardened bit
    let gpu_private_keys = context.process_bip44_batch(&seeds, &derivation_path)?;
    println!("GPU implementation: {}", hex::encode(&gpu_private_keys[0]));
    
    // 4. Test what happens if we manually add hardened bits
    let hardened_path = [44u32 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 2];
    let gpu_hardened_keys = context.process_bip44_batch(&seeds, &hardened_path)?;
    println!("GPU with pre-hardened values: {}", hex::encode(&gpu_hardened_keys[0]));
    
    // Compare results
    println!("\n=== Comparison ===");
    if derived_standard.private_key.secret_bytes() == derived_manual.private_key.secret_bytes() {
        println!("✅ Standard and manual CPU paths match!");
    } else {
        println!("❌ Standard and manual CPU paths differ!");
    }
    
    if derived_standard.private_key.secret_bytes() == gpu_private_keys[0] {
        println!("✅ CPU and GPU implementations match!");
    } else {
        println!("❌ CPU and GPU implementations differ!");
    }
    
    if gpu_private_keys[0] == gpu_hardened_keys[0] {
        println!("✅ GPU raw and pre-hardened paths match!");
    } else {
        println!("❌ GPU raw and pre-hardened paths differ!");
        println!("This suggests the GPU kernel is correctly adding hardened bits.");
    }
    
    // Print the actual derivation path values being used
    println!("\n=== Derivation Path Values ===");
    println!("Raw values: {:?}", derivation_path);
    println!("With hardened bits: {:?}", [
        44u32 | 0x80000000,
        60 | 0x80000000, 
        0 | 0x80000000,
        0,
        2
    ]);
    
    // Show what the GPU kernel should be processing
    println!("\n=== GPU Kernel Processing ===");
    for (i, &value) in derivation_path.iter().enumerate() {
        let processed_value = if i < 3 { value | 0x80000000 } else { value };
        println!("Path[{}]: {} -> {} ({})", 
            i, 
            value, 
            processed_value,
            if i < 3 { "hardened" } else { "normal" }
        );
    }
    
    Ok(())
}