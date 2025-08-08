use hmac::{Hmac, Mac};
use sha2::Sha512;
use ethereum_seed_recovery::opencl::{OpenCLContext, OpenCLConfig};
use bip39::Mnemonic;
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::Network;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BIP44 Step-by-Step Debug Test ===");
    
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "";
    
    // Get the seed
    let mnemonic = Mnemonic::parse(mnemonic_str)?;
    let seed = mnemonic.to_seed(passphrase);
    let seed_bytes = &seed[..];
    
    println!("Seed: {}", hex::encode(seed_bytes));
    
    // CPU BIP44 derivation step by step
    println!("\n=== CPU BIP44 Derivation ===");
    
    // Step 1: Master key derivation
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(seed_bytes);
    let master_result = mac.finalize().into_bytes();
    let master_key = &master_result[0..32];
    let master_chain_code = &master_result[32..64];
    
    println!("Master key: {}", hex::encode(master_key));
    println!("Master chain code: {}", hex::encode(master_chain_code));
    
    // Step 2: Derive using bitcoin crate for comparison
    let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/2")?;
    let derived_xpriv = xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &derivation_path)?;
    
    println!("CPU Final private key: {}", hex::encode(derived_xpriv.private_key.secret_bytes()));
    
    // Manual step-by-step derivation to match GPU logic
    println!("\n=== Manual CPU Step-by-Step Derivation ===");
    
    let mut current_key = master_key.to_vec();
    let mut current_chain_code = master_chain_code.to_vec();
    
    let derivation_steps = [44u32 | 0x80000000, 60u32 | 0x80000000, 0u32 | 0x80000000, 0u32, 2u32];
    
    for (i, &child_index) in derivation_steps.iter().enumerate() {
        println!("\nStep {}: Deriving child index {:#x}", i + 1, child_index);
        println!("Parent key: {}", hex::encode(&current_key));
        println!("Parent chain code: {}", hex::encode(&current_chain_code));
        
        // Prepare data for HMAC
        let mut data = Vec::new();
        
        if child_index >= 0x80000000 {
            // Hardened derivation
            data.push(0x00);
            data.extend_from_slice(&current_key);
        } else {
            // Non-hardened derivation - use compressed public key
            // For this test, we'll use a simplified approach
            // In reality, we'd need to derive the public key from private key
            // For now, let's use the bitcoin crate to get the correct derivation
            println!("Non-hardened derivation - using bitcoin crate for this step");
            
            // Use bitcoin crate for this specific step
            let temp_xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;
            let partial_path_str = format!("m/44'/60'/0'/0/{}", child_index);
            let partial_path = DerivationPath::from_str(&partial_path_str)?;
            let derived = temp_xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &partial_path)?;
            
            current_key = derived.private_key.secret_bytes().to_vec();
            // We don't have easy access to chain code from bitcoin crate, so we'll break here
            break;
        }
        
        // Add child index in big-endian
        data.extend_from_slice(&child_index.to_be_bytes());
        
        println!("HMAC data: {}", hex::encode(&data));
        
        // HMAC-SHA512
        let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
        mac.update(&data);
        let hmac_result = mac.finalize().into_bytes();
        
        println!("HMAC result: {}", hex::encode(&hmac_result));
        
        // Update current key and chain code
        let child_key_part = &hmac_result[0..32];
        current_chain_code = hmac_result[32..64].to_vec();
        
        // Add child_key_part to current_key modulo secp256k1 order
        // For simplicity, just copy the left part (this is not cryptographically correct)
        current_key = child_key_part.to_vec();
        
        println!("Child key: {}", hex::encode(&current_key));
        println!("Child chain code: {}", hex::encode(&current_chain_code));
    }
    
    println!("\nManual Final private key: {}", hex::encode(&current_key));
    
    // Test GPU implementation
    println!("\n=== GPU BIP44 Derivation ===");
    
    let config = OpenCLConfig::default();
    let mut context = OpenCLContext::new(config)?;
    context.initialize_kernels()?;
    
    // Use the existing GPU implementation
    let seeds: Vec<[u8; 64]> = vec![seed_bytes.try_into().unwrap()];
    let derivation_path = [44u32, 60u32, 0u32, 0u32, 2u32];
    
    let results = context.process_bip44_batch(&seeds, &derivation_path)?;
    
    if let Some(result) = results.first() {
        println!("GPU Final private key: {}", hex::encode(result));
        
        // Compare results
        if derived_xpriv.private_key.secret_bytes() == *result {
            println!("✅ CPU and GPU results match!");
        } else {
            println!("❌ CPU and GPU results differ!");
            println!("CPU: {}", hex::encode(derived_xpriv.private_key.secret_bytes()));
            println!("GPU: {}", hex::encode(result));
        }
    }
    
    Ok(())
}