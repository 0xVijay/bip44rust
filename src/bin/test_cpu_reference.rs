use ethereum_seed_recovery::{
    crypto::CryptoEngine,
    error::Result,
};
use hex;

fn main() -> Result<()> {
    println!("=== Testing CPU Reference Implementation ===");
    
    // Test data - the exact values provided by the user
    let mnemonic = "frequent lucky inquiry vendor engine dragon horse gorilla pear old dance shield";
    let derivation_path = "m/44'/60'/0'/0/2";
    let passphrase = "";
    
    // Expected values from user
    let expected_seed = "d553345b0fc89f270166f0a99646bea5478c58a55af3521537290c5ac39d74177d7ec6c052393249131f4ff53dd0f0fab4c73751ebd8e0b4357aada649df6ff1";
    let expected_private_key = "8d3464a68f0218eec3f6b9d869851ed88efeaefc7440c35159f70bfd453dfc9e";
    let expected_public_key = "04d4abed0c0dd336d5da496d6c763812b0bdc0607ef55cd4c0aba92d861f658b00502a0e3e7bf88a72b41a0660aba83953a0b2b581baf173360a31701ea717c124";
    let expected_address = "543bd35f52147370c0decbd440863bc2a002c5c5";
    
    println!("Mnemonic: {}", mnemonic);
    println!("Derivation Path: {}", derivation_path);
    println!("Passphrase: '{}'", passphrase);
    
    // Create crypto engine
    let crypto = CryptoEngine::new();
    
    // Generate seed from mnemonic
    let seed_result = crypto.derive_bip39_seed(mnemonic, passphrase)?;
    let seed_hex = seed_result.to_hex();
    
    println!("\n=== Seed Generation ===");
    println!("Expected: {}", expected_seed);
    println!("Generated: {}", seed_hex);
    println!("Match: {}", seed_hex == expected_seed);
    
    // Derive private key
    let key_result = crypto.derive_bip44_key(&seed_result, derivation_path)?;
    let private_key_hex = key_result.to_hex();
    
    // For now, just test seed and private key since we don't have public key/address derivation in crypto module
    println!("\nNote: Only testing seed and private key derivation (public key/address generation not implemented in crypto module)");
    
    // Final result
    let seed_match = seed_hex == expected_seed;
    let key_match = private_key_hex == expected_private_key;
    
    println!("\n=== Final Result ===");
    if seed_match && key_match {
        println!("✅ SUCCESS: CPU reference implementation matches expected values for seed and private key.");
    } else {
        println!("❌ FAILURE: CPU reference implementation has discrepancies.");
        if !seed_match {
            println!("  - Seed mismatch");
        }
        if !key_match {
            println!("  - Private key mismatch");
        }
    }
    
    Ok(())
}