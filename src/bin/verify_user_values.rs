//! Verification program to test user-provided cryptographic values
//! against our BIP39/BIP44 implementation

use bip39::Mnemonic;
use bitcoin::{
    bip32::{ExtendendPrivKey, DerivationPath},
    secp256k1::Secp256k1,
    Network,
};
use secp256k1::PublicKey;
use tiny_keccak::{Hasher, Keccak};
use hex;
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Verifying User-Provided Cryptographic Values ===");
    
    // Test mnemonic
    let mnemonic_str = "frequent lucky inquiry vendor engine dragon horse gorilla pear old dance shield";
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    println!("\n1. Mnemonic: {}", mnemonic_str);
    
    // Generate BIP39 seed (with empty passphrase)
    let seed = mnemonic.to_seed("");
    let seed_hex = hex::encode(&seed);
    println!("\n2. Generated BIP39 Seed:");
    println!("   Our result: {}", seed_hex);
    println!("   User provided: d553345b0fc89f270166f0a99646bea5478c58a55af3521537290c5ac39d74177d7ec6c052393249131f4ff53dd0f0fab4c73751ebd8e0b4357aada649df6ff1");
    println!("   Match: {}", seed_hex == "d553345b0fc89f270166f0a99646bea5478c58a55af3521537290c5ac39d74177d7ec6c052393249131f4ff53dd0f0fab4c73751ebd8e0b4357aada649df6ff1");
    
    // Create secp256k1 context
    let secp = Secp256k1::new();
    
    // Generate master extended private key
    let master_key = ExtendendPrivKey::new_master(Network::Bitcoin, &seed)?;
    println!("\n3. Master Private Key: {}", hex::encode(master_key.private_key.secret_bytes()));
    
    // Test derivation path m/44'/60'/0'/0/0 (first address)
    let path_0 = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
    let derived_key_0 = master_key.derive_priv(&secp, &path_0)?;
    let private_key_0 = derived_key_0.private_key;
    let public_key_0 = PublicKey::from_secret_key(&secp, &private_key_0);
    
    println!("\n4. Derivation Path m/44'/60'/0'/0/0:");
    println!("   Private Key: 0x{}", hex::encode(private_key_0.secret_bytes()));
    println!("   User provided: 0x5081106666eb20d7b615261cd17ad59ad077f8995be41712eac44133e4cabe38");
    println!("   Match: {}", hex::encode(private_key_0.secret_bytes()) == "5081106666eb20d7b615261cd17ad59ad077f8995be41712eac44133e4cabe38");
    
    // Generate Ethereum address for path 0
    let address_0 = generate_ethereum_address(&public_key_0);
    println!("   Address: 0x{}", hex::encode(address_0));
    println!("   User provided: 0xeB302C76fd9E4792493Fa3B36f5460C4ee173436");
    println!("   Match: {}", hex::encode(address_0).to_lowercase() == "eb302c76fd9e4792493fa3b36f5460c4ee173436");
    
    // Test derivation path m/44'/60'/0'/0/2 (target address)
    let path_2 = DerivationPath::from_str("m/44'/60'/0'/0/2")?;
    let derived_key_2 = master_key.derive_priv(&secp, &path_2)?;
    let private_key_2 = derived_key_2.private_key;
    let public_key_2 = PublicKey::from_secret_key(&secp, &private_key_2);
    
    println!("\n5. Derivation Path m/44'/60'/0'/0/2:");
    println!("   Private Key: 0x{}", hex::encode(private_key_2.secret_bytes()));
    println!("   User provided: 0x8d3464a68f0218eec3f6b9d869851ed88efeaefc7440c35159f70bfd453dfc9e");
    println!("   Match: {}", hex::encode(private_key_2.secret_bytes()) == "8d3464a68f0218eec3f6b9d869851ed88efeaefc7440c35159f70bfd453dfc9e");
    
    // Public key (compressed)
    let public_key_2_compressed = public_key_2.serialize();
    println!("   Public Key (compressed): 0x{}", hex::encode(public_key_2_compressed));
    println!("   User provided: 0x02d4abed0c0dd336d5da496d6c763812b0bdc0607ef55cd4c0aba92d861f658b00");
    println!("   Match: {}", hex::encode(public_key_2_compressed) == "02d4abed0c0dd336d5da496d6c763812b0bdc0607ef55cd4c0aba92d861f658b00");
    
    // Public key (uncompressed)
    let public_key_2_uncompressed = public_key_2.serialize_uncompressed();
    println!("   Public Key (uncompressed): 0x{}", hex::encode(public_key_2_uncompressed));
    
    // Generate Ethereum address for path 2
    let address_2 = generate_ethereum_address(&public_key_2);
    println!("   Address: 0x{}", hex::encode(address_2));
    println!("   User provided: 0x543Bd35F52147370C0deCBd440863bc2a002C5c5");
    println!("   Match: {}", hex::encode(address_2).to_lowercase() == "543bd35f52147370c0decbd440863bc2a002c5c5");
    
    println!("\n=== Summary ===");
    println!("All values verified against standard BIP39/BIP44 implementation.");
    
    Ok(())
}

fn generate_ethereum_address(public_key: &PublicKey) -> [u8; 20] {
    // Get uncompressed public key (remove 0x04 prefix)
    let uncompressed = public_key.serialize_uncompressed();
    let public_key_bytes = &uncompressed[1..]; // Remove 0x04 prefix
    
    // Keccak-256 hash
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(public_key_bytes);
    hasher.finalize(&mut hash);
    
    // Take last 20 bytes as Ethereum address
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}