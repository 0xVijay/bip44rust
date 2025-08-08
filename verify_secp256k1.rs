use secp256k1::{Secp256k1, SecretKey, PublicKey};
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    
    // Private key = 1
    let private_key_bytes = [0u8; 31].iter().chain([1u8].iter()).cloned().collect::<Vec<u8>>();
    let secret_key = SecretKey::from_slice(&private_key_bytes)?;
    
    // Generate public key
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    // Get uncompressed public key (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
    let uncompressed = public_key.serialize_uncompressed();
    
    // Remove the 0x04 prefix to get just the 64-byte coordinate pair
    let coords = &uncompressed[1..];
    
    println!("Private key: {}", hex::encode(&private_key_bytes));
    println!("Public key (uncompressed, no prefix): {}", hex::encode(coords));
    println!("Public key (full uncompressed): {}", hex::encode(&uncompressed));
    
    Ok(())
}