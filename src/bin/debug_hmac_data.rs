use hmac::{Hmac, Mac};
use sha2::Sha512;
use ethereum_seed_recovery::opencl::{OpenCLContext, OpenCLConfig};
use bip39::Mnemonic;
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::Network;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HMAC Data Debug Test ===");
    
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "";
    
    // Get the seed
    let mnemonic = Mnemonic::parse(mnemonic_str)?;
    let seed = mnemonic.to_seed(passphrase);
    let seed_bytes = &seed[..];
    
    println!("Seed: {}", hex::encode(seed_bytes));
    
    // CPU BIP44 derivation step by step
    println!("\n=== CPU BIP44 Derivation ===");
    
    // Step 1: Master key derivation
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(seed_bytes);
    let master_result = mac.finalize().into_bytes();
    let master_key = &master_result[0..32];
    let master_chain_code = &master_result[32..64];
    
    println!("Master key: {}", hex::encode(master_key));
    println!("Master chain code: {}", hex::encode(master_chain_code));
    
    // Test GPU implementation with detailed logging
    println!("\n=== GPU BIP44 Derivation with Debug ===");
    
    let config = OpenCLConfig::default();
    let mut context = OpenCLContext::new(config)?;
    context.initialize_kernels()?;
    
    // Create a debug kernel that logs each step
    let kernel_source = format!(
        "{}
{}

__kernel void debug_bip44_derivation(
    __global const uchar* master_seed,
    __global const uint* derivation_path,
    __global uchar* debug_output
) {{
    // Master key derivation
    uchar master_key[32];
    uchar master_chain_code[32];
    uchar hmac_result[64];
    
    uchar bitcoin_seed[] = \"Bitcoin seed\";
    uchar local_seed[64];
    for (int i = 0; i < 64; i++) {{
        local_seed[i] = master_seed[i];
    }}
    hmac_sha512_bip44(bitcoin_seed, 12, local_seed, 64, hmac_result);
    
    for (int i = 0; i < 32; i++) {{
        master_key[i] = hmac_result[i];
        master_chain_code[i] = hmac_result[32 + i];
    }}
    
    // Copy master key to debug output (first 32 bytes)
    for (int i = 0; i < 32; i++) {{
        debug_output[i] = master_key[i];
    }}
    
    // Copy master chain code to debug output (next 32 bytes)
    for (int i = 0; i < 32; i++) {{
        debug_output[32 + i] = master_chain_code[i];
    }}
    
    // Derive first child (m/44')
    uchar current_key[32], current_chain_code[32];
    uchar next_key[32], next_chain_code[32];
    
    for (int i = 0; i < 32; i++) {{
        current_key[i] = master_key[i];
        current_chain_code[i] = master_chain_code[i];
    }}
    
    // First derivation step: m/44'
    uint child_index = derivation_path[0] | 0x80000000;
    
    uchar data[37];
    data[0] = 0x00;
    for (int i = 0; i < 32; i++) {{
        data[1 + i] = current_key[i];
    }}
    bytes_to_big_endian_32(child_index, &data[33]);
    
    // Copy HMAC input data to debug output (next 37 bytes)
    for (int i = 0; i < 37; i++) {{
        debug_output[64 + i] = data[i];
    }}
    
    hmac_sha512_bip44(current_chain_code, 32, data, 37, hmac_result);
    
    // Copy HMAC result to debug output (next 64 bytes)
    for (int i = 0; i < 64; i++) {{
        debug_output[101 + i] = hmac_result[i];
    }}
    
    big_num_add_mod(current_key, hmac_result, SECP256K1_N, next_key);
    for (int i = 0; i < 32; i++) {{
        next_chain_code[i] = hmac_result[32 + i];
    }}
    
    // Copy first derived key to debug output (next 32 bytes)
    for (int i = 0; i < 32; i++) {{
        debug_output[165 + i] = next_key[i];
    }}
}}",
        std::fs::read_to_string("/Users/vijay/bip44cuda/src/kernels/secp256k1.cl")?,
        std::fs::read_to_string("/Users/vijay/bip44cuda/src/kernels/bip44.cl")?
    );
    
    // Build and run the debug kernel
    let pro_que = ocl::ProQue::builder()
        .src(kernel_source)
        .dims(1)
        .build()?;
    
    let seed_buffer = pro_que.buffer_builder::<u8>()
        .len(64)
        .build()?;
    let derivation_path_buffer = pro_que.buffer_builder::<u32>()
        .len(5)
        .build()?;
    let debug_output_buffer = pro_que.buffer_builder::<u8>()
        .len(256) // Enough space for all debug data
        .build()?;
    
    let derivation_path = [44u32, 60u32, 0u32, 0u32, 2u32];
    
    seed_buffer.write(seed_bytes).enq()?;
    derivation_path_buffer.write(&derivation_path[..]).enq()?;
    
    let kernel = pro_que.kernel_builder("debug_bip44_derivation")
        .arg(&seed_buffer)
        .arg(&derivation_path_buffer)
        .arg(&debug_output_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut debug_output = vec![0u8; 256];
    debug_output_buffer.read(&mut debug_output).enq()?;
    
    println!("GPU Master key: {}", hex::encode(&debug_output[0..32]));
    println!("GPU Master chain code: {}", hex::encode(&debug_output[32..64]));
    println!("GPU HMAC input data: {}", hex::encode(&debug_output[64..101]));
    println!("GPU HMAC result: {}", hex::encode(&debug_output[101..165]));
    println!("GPU First derived key: {}", hex::encode(&debug_output[165..197]));
    
    // Compare with CPU manual calculation
    println!("\n=== CPU Manual First Step ===");
    
    let child_index = 44u32 | 0x80000000;
    let mut data = Vec::new();
    data.push(0x00);
    data.extend_from_slice(master_key);
    data.extend_from_slice(&child_index.to_be_bytes());
    
    println!("CPU HMAC input data: {}", hex::encode(&data));
    
    let mut mac = HmacSha512::new_from_slice(master_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    
    println!("CPU HMAC result: {}", hex::encode(&hmac_result));
    
    // Compare the results
    if debug_output[0..32] == master_key[..] {
        println!("✅ Master keys match!");
    } else {
        println!("❌ Master keys differ!");
    }
    
    if debug_output[64..101] == data[..] {
        println!("✅ HMAC input data matches!");
    } else {
        println!("❌ HMAC input data differs!");
        println!("CPU: {}", hex::encode(&data));
        println!("GPU: {}", hex::encode(&debug_output[64..101]));
    }
    
    if debug_output[101..165] == hmac_result[..] {
        println!("✅ HMAC results match!");
    } else {
        println!("❌ HMAC results differ!");
        println!("CPU: {}", hex::encode(&hmac_result));
        println!("GPU: {}", hex::encode(&debug_output[101..165]));
    }
    
    Ok(())
}