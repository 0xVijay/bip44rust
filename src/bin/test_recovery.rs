use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use tiny_keccak::{Hasher, Keccak};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test the exact same recovery logic as the OpenCL implementation
    let mnemonic_str = "frequent lucky inquiry vendor engine dragon horse gorilla pear old dance shield";
    let target_address = "0x543Bd35F52147370C0deCBd440863bc2a002C5c5";
    let derivation_path_str = "m/44'/60'/0'/0/2";
    
    println!("Testing recovery logic:");
    println!("Mnemonic: {}", mnemonic_str);
    println!("Target: {}", target_address);
    println!("Path: {}", derivation_path_str);
    println!();
    
    // Step 1: Convert mnemonic to seed (PBKDF2-HMAC-SHA512)
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let seed = mnemonic.to_seed(""); // Empty passphrase
    println!("Step 1 - PBKDF2 Seed: {}", hex::encode(&seed));
    
    // Step 2: BIP44 key derivation
    let secp = Secp256k1::new();
    let master_key = Xpriv::new_master(Network::Bitcoin, &seed)?;
    let derivation_path = DerivationPath::from_str(derivation_path_str)?;
    let derived_key = master_key.derive_priv(&secp, &derivation_path)?;
    let private_key = derived_key.private_key;
    println!("Step 2 - Private Key: 0x{}", hex::encode(private_key.secret_bytes()));
    
    // Step 3: Generate public key (secp256k1)
    let public_key = private_key.public_key(&secp);
    let public_key_bytes = public_key.serialize_uncompressed();
    println!("Step 3 - Public Key: {}", hex::encode(&public_key_bytes));
    
    // Step 4: Generate Ethereum address (Keccak-256)
    let mut keccak = Keccak::v256();
    let mut hash_output = [0u8; 32];
    keccak.update(&public_key_bytes[1..]);
    keccak.finalize(&mut hash_output);
    let address_bytes = &hash_output[12..];
    let generated_address = format!("0x{}", hex::encode(address_bytes));
    println!("Step 4 - Generated Address: {}", generated_address);
    
    // Step 5: Compare addresses
    let target_lower = target_address.to_lowercase();
    let generated_lower = generated_address.to_lowercase();
    let matches = target_lower == generated_lower;
    
    println!();
    println!("=== COMPARISON ===");
    println!("Target:    {}", target_lower);
    println!("Generated: {}", generated_lower);
    println!("Match: {}", matches);
    
    if matches {
        println!("✅ SUCCESS: Recovery logic works correctly!");
    } else {
        println!("❌ FAILURE: Recovery logic has a bug!");
        
        // Debug: Show byte-by-byte comparison
        let target_bytes = hex::decode(&target_address[2..])?;
        let generated_bytes = hex::decode(&generated_address[2..])?;
        
        println!("\nByte-by-byte comparison:");
        for (i, (t, g)) in target_bytes.iter().zip(generated_bytes.iter()).enumerate() {
            if t != g {
                println!("  Byte {}: target={:02x}, generated={:02x} ❌", i, t, g);
            } else {
                println!("  Byte {}: {:02x} ✅", i, t);
            }
        }
    }
    
    Ok(())
}