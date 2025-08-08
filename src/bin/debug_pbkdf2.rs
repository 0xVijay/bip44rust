use ethereum_seed_recovery::opencl::OpenCLContext;
use ethereum_seed_recovery::opencl::OpenCLConfig;
use ethereum_seed_recovery::opencl::RecoveryBatch;
use ethereum_seed_recovery::crypto::CryptoBatch;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PBKDF2 Debug Test ===");
    
    let mnemonic = "frequent lucky inquiry vendor engine dragon horse gorilla pear old dance shield";
    let passphrase = "";
    
    // CPU implementation
    let mut cpu_seed = [0u8; 64];
    let password = mnemonic.as_bytes();
    let salt = format!("mnemonic{}", passphrase);
    
    pbkdf2_hmac::<Sha512>(password, salt.as_bytes(), 2048, &mut cpu_seed);
    
    println!("CPU PBKDF2 result: {}", hex::encode(&cpu_seed));
    
    // GPU implementation
    let config = OpenCLConfig::default();
    let mut context = OpenCLContext::new(config)?;
    context.initialize_kernels()?;
    
    let batch = RecoveryBatch {
        mnemonics: vec![mnemonic.to_string()],
        target_address: [0u8; 20],
        derivation_path: [44, 60, 0, 0, 2],
        passphrase: passphrase.to_string(),
    };
    
    let gpu_seeds = context.process_pbkdf2_batch(&batch)?;
    println!("GPU PBKDF2 result: {}", hex::encode(&gpu_seeds[0]));
    
    if cpu_seed == gpu_seeds[0] {
        println!("✓ PBKDF2 implementations match!");
    } else {
        println!("❌ PBKDF2 implementations differ!");
        
        // Show first few bytes for debugging
        println!("CPU first 16 bytes: {}", hex::encode(&cpu_seed[..16]));
        println!("GPU first 16 bytes: {}", hex::encode(&gpu_seeds[0][..16]));
    }
    
    Ok(())
}