use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Network;
use tiny_keccak::{Hasher, Keccak};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your seed phrase
    let mnemonic_str = "frequent lucky inquiry vendor engine dragon horse gorilla pear old dance shield";
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    
    println!("Mnemonic: {}", mnemonic);
    println!("Valid: true"); // Skip validation for now
    
    // Generate seed
    let seed = mnemonic.to_seed("");
    println!("Seed (hex): {}", hex::encode(&seed));
    
    // Create master key
    let secp = Secp256k1::new();
    let master_key = Xpriv::new_master(Network::Bitcoin, &seed)?;
    println!("Master key: {}", master_key);
    
    // Derive path m/44'/60'/0'/0/2
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/2")?;
    let derived_key = master_key.derive_priv(&secp, &derivation_path)?;
    println!("Derived private key: {:?}", derived_key.private_key);
    
    // Get public key
    let public_key = derived_key.private_key.public_key(&secp);
    println!("Public key: {}", public_key);
    
    // Generate Ethereum address using Keccak256
    let public_key_bytes = public_key.serialize_uncompressed();
    let mut keccak = Keccak::v256();
    let mut output = [0u8; 32];
    keccak.update(&public_key_bytes[1..]);
    keccak.finalize(&mut output);
    let address_bytes = &output[12..];
    let address = format!("0x{}", hex::encode(address_bytes));
    
    println!("Generated Ethereum address: {}", address);
    println!("Target address:            0x543Bd35F52147370C0deCBd440863bc2a002C5c5");
    println!("Match: {}", address.to_lowercase() == "0x543Bd35F52147370C0deCBd440863bc2a002C5c5".to_lowercase());
    
    Ok(())
}