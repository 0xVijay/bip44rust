use anyhow::Result;
use ocl::{ProQue, Buffer};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

fn main() -> Result<()> {
    println!("=== secp256k1 Implementation Debug ===");
    
    // Test with a simple known private key
    let test_private_key = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")?;
    
    println!("Test private key: {}", hex::encode(&test_private_key));
    
    // CPU secp256k1
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&test_private_key)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_uncompressed = public_key.serialize_uncompressed();
    let public_key_compressed = public_key.serialize();
    
    println!("CPU Public key (uncompressed): {}", hex::encode(&public_key_uncompressed));
    println!("CPU Public key (compressed): {}", hex::encode(&public_key_compressed));
    
    // GPU secp256k1
    let opencl_source = r#"
        #include "src/kernels/secp256k1.cl"
        #include "src/kernels/bip44.cl"
        
        __kernel void test_secp256k1(
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
    private_key_buffer.write(&test_private_key[..]).enq()?;
    
    // Execute kernel
    let kernel = pro_que.kernel_builder("test_secp256k1")
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
    
    // Expected result for private key = 1
    // Public key should be the generator point
    let expected_x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let expected_y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let expected_compressed = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    
    println!("\n=== Expected Results ===");
    println!("Expected X: {}", expected_x);
    println!("Expected Y: {}", expected_y);
    println!("Expected compressed: {}", expected_compressed);
    
    // Compare
    let gpu_x = hex::encode(&gpu_public_key_full[0..32]);
    let gpu_y = hex::encode(&gpu_public_key_full[32..64]);
    let gpu_compressed = hex::encode(&gpu_public_key_compressed);
    
    println!("\n=== Comparison ===");
    if gpu_x == expected_x {
        println!("✅ GPU X-coordinate matches expected");
    } else {
        println!("❌ GPU X-coordinate differs");
        println!("  GPU: {}", gpu_x);
        println!("  Expected: {}", expected_x);
    }
    
    if gpu_y == expected_y {
        println!("✅ GPU Y-coordinate matches expected");
    } else {
        println!("❌ GPU Y-coordinate differs");
        println!("  GPU: {}", gpu_y);
        println!("  Expected: {}", expected_y);
    }
    
    if gpu_compressed == expected_compressed {
        println!("✅ GPU compressed public key matches expected");
    } else {
        println!("❌ GPU compressed public key differs");
        println!("  GPU: {}", gpu_compressed);
        println!("  Expected: {}", expected_compressed);
    }
    
    // Also compare with CPU result
    let cpu_uncompressed_hex = hex::encode(&public_key_uncompressed);
    let cpu_compressed_hex = hex::encode(&public_key_compressed);
    
    println!("\n=== CPU vs GPU ===");
    if cpu_compressed_hex == gpu_compressed {
        println!("✅ CPU and GPU compressed public keys match");
    } else {
        println!("❌ CPU and GPU compressed public keys differ");
        println!("  CPU: {}", cpu_compressed_hex);
        println!("  GPU: {}", gpu_compressed);
    }
    
    Ok(())
}