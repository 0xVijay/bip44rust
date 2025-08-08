use bip39::Mnemonic;
use bitcoin::bip32::{Xpriv, ChildNumber, DerivationPath};
use bitcoin::secp256k1::Secp256k1;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use ethereum_seed_recovery::opencl::{OpenCLContext, OpenCLConfig};

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Master Key Debug Test ===");
    
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "";
    
    // CPU implementation
    let mnemonic = Mnemonic::parse(mnemonic_str)?;
    let seed = mnemonic.to_seed(passphrase);
    let seed_bytes = &seed[..];
    
    println!("Seed: {}", hex::encode(seed_bytes));
    
    // Derive master key using CPU
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(seed_bytes);
    let result = mac.finalize().into_bytes();
    let master_key = &result[0..32];
    let master_chain_code = &result[32..64];
    
    println!("CPU Master key: {}", hex::encode(master_key));
    println!("CPU Master chain code: {}", hex::encode(master_chain_code));
    
    // GPU implementation
    let config = OpenCLConfig::default();
    let context = OpenCLContext::new(config)?;
    
    let seeds = vec![seed_bytes.try_into().expect("Seed should be 64 bytes")];
    let derivation_path = [44u32, 60, 0, 0, 2];
    let gpu_private_keys = context.process_bip44_batch(&seeds, &derivation_path)?;
    
    println!("GPU BIP44 result: {}", hex::encode(&gpu_private_keys[0]));
    
    // For comparison, let's also derive the full path using CPU
    let secp = Secp256k1::new();
    let master_key_cpu = Xpriv::new_master(bitcoin::Network::Bitcoin, seed_bytes)?;
    let derivation_path_cpu = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44)?,
        ChildNumber::from_hardened_idx(60)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_normal_idx(0)?,
        ChildNumber::from_normal_idx(2)?,
    ]);
    let derived_key = master_key_cpu.derive_priv(&secp, &derivation_path_cpu)?;
    
    println!("CPU BIP44 result: {}", hex::encode(derived_key.private_key.secret_bytes()));
    
    if gpu_private_keys[0] == derived_key.private_key.secret_bytes() {
        println!("✅ BIP44 implementations match!");
    } else {
        println!("❌ BIP44 implementations differ!");
        println!("CPU first 16 bytes: {}", hex::encode(&derived_key.private_key.secret_bytes()[0..16]));
        println!("GPU first 16 bytes: {}", hex::encode(&gpu_private_keys[0][0..16]));
    }
    
    Ok(())
}