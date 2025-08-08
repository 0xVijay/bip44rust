use hmac::{Hmac, Mac};
use sha2::Sha512;
use ethereum_seed_recovery::opencl::{OpenCLContext, OpenCLConfig};
use bip39::Mnemonic;

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HMAC-SHA512 Debug Test ===");
    
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "";
    
    // Get the seed
    let mnemonic = Mnemonic::parse(mnemonic_str)?;
    let seed = mnemonic.to_seed(passphrase);
    let seed_bytes = &seed[..];
    
    println!("Seed: {}", hex::encode(seed_bytes));
    
    // CPU HMAC-SHA512 with "Bitcoin seed"
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(seed_bytes);
    let cpu_result = mac.finalize().into_bytes();
    let cpu_master_key = &cpu_result[0..32];
    let cpu_master_chain_code = &cpu_result[32..64];
    
    println!("CPU HMAC result: {}", hex::encode(&cpu_result[..]));
    println!("CPU Master key: {}", hex::encode(cpu_master_key));
    println!("CPU Master chain code: {}", hex::encode(cpu_master_chain_code));
    
    // Test GPU HMAC-SHA512 implementation
    let config = OpenCLConfig::default();
    let context = OpenCLContext::new(config)?;
    
    // Create a simple test kernel to test HMAC
    let kernel_source = format!(
        "{}
{}

__kernel void test_hmac(
    __global const uchar* seed,
    __global uchar* output
) {{
    uchar bitcoin_seed[] = \"Bitcoin seed\";
    uchar local_seed[64];
    uchar local_output[64];
    for (int i = 0; i < 64; i++) {{
        local_seed[i] = seed[i];
    }}
    hmac_sha512_bip44(bitcoin_seed, 12, local_seed, 64, local_output);
    for (int i = 0; i < 64; i++) {{
        output[i] = local_output[i];
    }}
}}",
        std::fs::read_to_string("/Users/vijay/bip44cuda/src/kernels/secp256k1.cl")?,
        std::fs::read_to_string("/Users/vijay/bip44cuda/src/kernels/bip44.cl")?
    );
    
    // Build and run the test kernel
    let pro_que = ocl::ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build()?;
    
    let seed_buffer = pro_que.buffer_builder::<u8>()
        .len(64)
        .build()?;
    let output_buffer = pro_que.buffer_builder::<u8>()
        .len(64)
        .build()?;
    
    seed_buffer.write(seed_bytes).enq()?;
    
    let kernel = pro_que.kernel_builder("test_hmac")
        .arg(&seed_buffer)
        .arg(&output_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut gpu_result = vec![0u8; 64];
    output_buffer.read(&mut gpu_result).enq()?;
    
    println!("GPU HMAC result: {}", hex::encode(&gpu_result));
    println!("GPU Master key: {}", hex::encode(&gpu_result[0..32]));
    println!("GPU Master chain code: {}", hex::encode(&gpu_result[32..64]));
    
    if cpu_result[..] == gpu_result[..] {
        println!("✅ HMAC implementations match!");
    } else {
        println!("❌ HMAC implementations differ!");
        println!("CPU first 16 bytes: {}", hex::encode(&cpu_result[0..16]));
        println!("GPU first 16 bytes: {}", hex::encode(&gpu_result[0..16]));
    }
    
    Ok(())
}