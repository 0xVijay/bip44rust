use anyhow::Result;
use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use ocl::{ProQue, Buffer};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Sha512;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<()> {
    println!("=== Non-Hardened Derivation Debug ===");
    
    // Use the same mnemonic and derive to step 3 (m/44'/60'/0')
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    
    // Derive to step 3 manually (this matches our previous tests)
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(&seed);
    let master_result = mac.finalize().into_bytes();
    let mut current_key = master_result[0..32].to_vec();
    let mut current_chain_code = master_result[32..64].to_vec();
    
    // Step 1: m/44'
    let mut data = vec![0x00];
    data.extend_from_slice(&current_key);
    data.extend_from_slice(&(44u32 | 0x80000000).to_be_bytes());
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    current_key = add_mod_manual(&current_key, &hmac_result[0..32], &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    current_chain_code = hmac_result[32..64].to_vec();
    
    // Step 2: m/44'/60'
    let mut data = vec![0x00];
    data.extend_from_slice(&current_key);
    data.extend_from_slice(&(60u32 | 0x80000000).to_be_bytes());
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    current_key = add_mod_manual(&current_key, &hmac_result[0..32], &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    current_chain_code = hmac_result[32..64].to_vec();
    
    // Step 3: m/44'/60'/0'
    let mut data = vec![0x00];
    data.extend_from_slice(&current_key);
    data.extend_from_slice(&(0u32 | 0x80000000).to_be_bytes());
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    current_key = add_mod_manual(&current_key, &hmac_result[0..32], &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    current_chain_code = hmac_result[32..64].to_vec();
    
    println!("After step 3 (m/44'/60'/0'):");
    println!("Key: {}", hex::encode(&current_key));
    println!("Chain code: {}", hex::encode(&current_chain_code));
    
    // Now for step 4: m/44'/60'/0'/0 (non-hardened)
    println!("\n=== Step 4: Non-Hardened Derivation (CPU) ===");
    
    // Generate public key from private key
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&current_key)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize();
    
    println!("Private key: {}", hex::encode(&current_key));
    println!("Public key (compressed): {}", hex::encode(&public_key_bytes));
    
    // Prepare HMAC data for non-hardened derivation
    let mut data = Vec::new();
    data.extend_from_slice(&public_key_bytes); // 33 bytes compressed public key
    data.extend_from_slice(&0u32.to_be_bytes()); // child index 0
    
    println!("HMAC data: {}", hex::encode(&data));
    
    // Perform HMAC
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    
    println!("HMAC result: {}", hex::encode(&hmac_result));
    
    // Add to parent key
    let key_to_add = &hmac_result[0..32];
    let new_chain_code = &hmac_result[32..64];
    
    println!("Key to add: {}", hex::encode(key_to_add));
    
    let child_key = add_mod_manual(&current_key, key_to_add, &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    
    println!("Child key: {}", hex::encode(&child_key));
    println!("Child chain code: {}", hex::encode(new_chain_code));
    
    // Update for step 5
    current_key = child_key;
    current_chain_code = new_chain_code.to_vec();
    
    // Step 5: m/44'/60'/0'/0/2 (non-hardened)
    println!("\n=== Step 5: Non-Hardened Derivation (CPU) ===");
    
    let secret_key = SecretKey::from_slice(&current_key)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize();
    
    let mut data = Vec::new();
    data.extend_from_slice(&public_key_bytes);
    data.extend_from_slice(&2u32.to_be_bytes());
    
    println!("HMAC data: {}", hex::encode(&data));
    
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    
    println!("HMAC result: {}", hex::encode(&hmac_result));
    
    let key_to_add = &hmac_result[0..32];
    let final_child_key = add_mod_manual(&current_key, key_to_add, &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    
    println!("Final CPU result: {}", hex::encode(&final_child_key));
    
    // Compare with GPU
    println!("\n=== GPU Comparison ===");
    println!("GPU result from previous test: c82d77ee7686eb8947e779c9839db940566f116a6c421f2ed4fc05e4a0322026");
    
    if hex::encode(&final_child_key) == "c82d77ee7686eb8947e779c9839db940566f116a6c421f2ed4fc05e4a0322026" {
        println!("✅ CPU and GPU results match!");
    } else {
        println!("❌ CPU and GPU results still differ!");
        println!("CPU: {}", hex::encode(&final_child_key));
        println!("GPU: c82d77ee7686eb8947e779c9839db940566f116a6c421f2ed4fc05e4a0322026");
    }
    
    Ok(())
}

fn add_mod_manual(a: &[u8], b: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    use num_bigint::BigUint;
    
    let a_big = BigUint::from_bytes_be(a);
    let b_big = BigUint::from_bytes_be(b);
    let mod_big = BigUint::from_bytes_be(modulus);
    
    let result = (a_big + b_big) % mod_big;
    let mut result_bytes = result.to_bytes_be();
    
    // Pad to 32 bytes
    while result_bytes.len() < 32 {
        result_bytes.insert(0, 0);
    }
    
    Ok(result_bytes)
}