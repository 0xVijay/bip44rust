use anyhow::Result;
use bip39::Mnemonic;
use hmac::{Hmac, Mac};
use ocl::{ProQue, Buffer};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sha2::Sha512;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<()> {
    println!("=== Public Key Generation Debug ===");
    
    // Use the same mnemonic and derive to step 3 (m/44'/60'/0')
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    
    // Derive to step 3 manually
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(&seed);
    let master_result = mac.finalize().into_bytes();
    let mut current_key = master_result[0..32].to_vec();
    let mut current_chain_code = master_result[32..64].to_vec();
    
    // Step 1: m/44'
    let mut data = vec![0x00];
    data.extend_from_slice(&current_key);
    data.extend_from_slice(&(44u32 | 0x80000000).to_be_bytes());
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    current_key = add_mod_manual(&current_key, &hmac_result[0..32], &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    current_chain_code = hmac_result[32..64].to_vec();
    
    // Step 2: m/44'/60'
    let mut data = vec![0x00];
    data.extend_from_slice(&current_key);
    data.extend_from_slice(&(60u32 | 0x80000000).to_be_bytes());
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    current_key = add_mod_manual(&current_key, &hmac_result[0..32], &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    current_chain_code = hmac_result[32..64].to_vec();
    
    // Step 3: m/44'/60'/0'
    let mut data = vec![0x00];
    data.extend_from_slice(&current_key);
    data.extend_from_slice(&(0u32 | 0x80000000).to_be_bytes());
    let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
    mac.update(&data);
    let hmac_result = mac.finalize().into_bytes();
    current_key = add_mod_manual(&current_key, &hmac_result[0..32], &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?)?;
    current_chain_code = hmac_result[32..64].to_vec();
    
    println!("After step 3 (m/44'/60'/0'):");
    println!("Private key: {}", hex::encode(&current_key));
    
    // Generate public key using CPU secp256k1
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&current_key)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize();
    
    println!("CPU Public key (compressed): {}", hex::encode(&public_key_bytes));
    
    // Test GPU public key generation
    println!("\n=== GPU Public Key Generation ===");
    
    let opencl_source = r#"
        #include "src/kernels/secp256k1.cl"
        #include "src/kernels/bip44.cl"
        
        __kernel void debug_pubkey(
            __global const uchar* private_key,
            __global uchar* public_key_full,
            __global uchar* public_key_compressed
        ) {
            int gid = get_global_id(0);
            if (gid != 0) return;
            
            uchar local_private_key[32];
            for (int i = 0; i < 32; i++) {
                local_private_key[i] = private_key[i];
            }
            
            uchar local_public_key[64];
            secp256k1_point_multiply(local_private_key, local_public_key);
            
            // Store full public key
            for (int i = 0; i < 64; i++) {
                public_key_full[i] = local_public_key[i];
            }
            
            // Create compressed public key
            uchar compressed[33];
            compressed[0] = (local_public_key[63] & 1) ? 0x03 : 0x02;
            for (int i = 0; i < 32; i++) {
                compressed[1 + i] = local_public_key[i];
            }
            
            for (int i = 0; i < 33; i++) {
                public_key_compressed[i] = compressed[i];
            }
        }
    "#;
    
    let pro_que = ProQue::builder()
        .src(opencl_source)
        .dims(1)
        .build()?;
    
    // Create buffers
    let private_key_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .build()?;
    
    let public_key_full_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(64)
        .build()?;
    
    let public_key_compressed_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(33)
        .build()?;
    
    // Write input data
    private_key_buffer.write(&current_key[..]).enq()?;
    
    // Execute kernel
    let kernel = pro_que.kernel_builder("debug_pubkey")
        .arg(&private_key_buffer)
        .arg(&public_key_full_buffer)
        .arg(&public_key_compressed_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    // Read results
    let mut gpu_public_key_full = vec![0u8; 64];
    let mut gpu_public_key_compressed = vec![0u8; 33];
    
    public_key_full_buffer.read(&mut gpu_public_key_full).enq()?;
    public_key_compressed_buffer.read(&mut gpu_public_key_compressed).enq()?;
    
    println!("GPU Public key (full): {}", hex::encode(&gpu_public_key_full));
    println!("GPU Public key (compressed): {}", hex::encode(&gpu_public_key_compressed));
    
    // Compare
    if public_key_bytes.to_vec() == gpu_public_key_compressed {
        println!("\n✅ CPU and GPU public keys match!");
    } else {
        println!("\n❌ CPU and GPU public keys differ!");
        println!("CPU: {}", hex::encode(&public_key_bytes));
        println!("GPU: {}", hex::encode(&gpu_public_key_compressed));
        
        // Let's also check the uncompressed form
        let uncompressed_public_key = public_key.serialize_uncompressed();
        println!("\nCPU uncompressed: {}", hex::encode(&uncompressed_public_key));
        println!("GPU full (x,y): {}", hex::encode(&gpu_public_key_full));
        
        // Check if the x-coordinate matches
        if uncompressed_public_key[1..33] == gpu_public_key_full[0..32] {
            println!("✅ X-coordinates match");
        } else {
            println!("❌ X-coordinates differ");
        }
        
        // Check if the y-coordinate matches
        if uncompressed_public_key[33..65] == gpu_public_key_full[32..64] {
            println!("✅ Y-coordinates match");
        } else {
            println!("❌ Y-coordinates differ");
        }
    }
    
    Ok(())
}

fn add_mod_manual(a: &[u8], b: &[u8], modulus: &[u8]) -> Result<Vec<u8>> {
    use num_bigint::BigUint;
    
    let a_big = BigUint::from_bytes_be(a);
    let b_big = BigUint::from_bytes_be(b);
    let mod_big = BigUint::from_bytes_be(modulus);
    
    let result = (a_big + b_big) % mod_big;
    let mut result_bytes = result.to_bytes_be();
    
    // Pad to 32 bytes
    while result_bytes.len() < 32 {
        result_bytes.insert(0, 0);
    }
    
    Ok(result_bytes)
}