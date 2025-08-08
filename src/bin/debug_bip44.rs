use ethereum_seed_recovery::opencl::OpenCLContext;
use ethereum_seed_recovery::opencl::OpenCLConfig;
use bip39::{Mnemonic, Language};
use bitcoin::bip32::{Xpriv, ChildNumber, DerivationPath};
use bitcoin::secp256k1::Secp256k1;
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BIP44 Debug Test ===");
    
    let mnemonic_str = "frequent lucky inquiry vendor engine dragon horse gorilla pear old dance shield";
    let passphrase = "";
    let derivation_path = [44u32, 60, 0, 0, 2];
    
    // CPU implementation using bitcoin crate
    let mnemonic = Mnemonic::parse(mnemonic_str)?;
    let seed = mnemonic.to_seed(passphrase);
    
    println!("Seed: {}", hex::encode(&seed));
    
    // Derive master key
    let secp = Secp256k1::new();
    let master_key = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed)?;
    println!("Master key: {}", hex::encode(master_key.private_key.secret_bytes()));
    
    // Derive according to path m/44'/60'/0'/0/2
    let derivation_path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44)?,
        ChildNumber::from_hardened_idx(60)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_normal_idx(0)?,
        ChildNumber::from_normal_idx(2)?,
    ]);
    
    let address_key = master_key.derive_priv(&secp, &derivation_path)?;
    let cpu_private_key = address_key.private_key.secret_bytes();
    println!("CPU BIP44 result: {}", hex::encode(&cpu_private_key));
    
    // GPU implementation
    let config = OpenCLConfig::default();
    let mut context = OpenCLContext::new(config)?;
    context.initialize_kernels()?;
    
    let seeds = vec![seed.try_into().expect("Seed should be 64 bytes")];
    let gpu_private_keys = context.process_bip44_batch(&seeds, &[44u32, 60, 0, 0, 2])?;
    println!("GPU BIP44 result: {}", hex::encode(&gpu_private_keys[0]));
    
    if cpu_private_key == gpu_private_keys[0] {
        println!("✓ BIP44 implementations match!");
    } else {
        println!("❌ BIP44 implementations differ!");
        
        // Show first few bytes for debugging
        println!("CPU first 16 bytes: {}", hex::encode(&cpu_private_key[..16]));
        println!("GPU first 16 bytes: {}", hex::encode(&gpu_private_keys[0][..16]));
    }
    
    Ok(())
}