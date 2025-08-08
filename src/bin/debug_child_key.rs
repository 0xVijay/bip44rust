use anyhow::Result;
use bip39::{Mnemonic, Language};
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::Network;
use hmac::{Hmac, Mac};
use ocl::{ProQue, Buffer};
use sha2::Sha512;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<()> {
    println!("=== Child Key Derivation Debug Test ===");
    
    // Use a hardcoded mnemonic for consistency
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    
    println!("Seed: {}", hex::encode(&seed));
    
    // CPU derivation using bitcoin crate
    let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;
    let path = DerivationPath::from_str("m/44'/60'/0'/0/2")?;
    let derived_xpriv = xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &path)?;
    
    println!("\n=== CPU BIP44 Result ===");
    println!("CPU private key: {}", hex::encode(derived_xpriv.private_key.secret_bytes()));
    
    // Manual step-by-step derivation to match GPU logic
    println!("\n=== Manual Step-by-Step Derivation ===");
    
    // Step 1: Master key derivation
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(&seed);
    let master_result = mac.finalize().into_bytes();
    let master_key = &master_result[0..32];
    let master_chain_code = &master_result[32..64];
    
    println!("Master key: {}", hex::encode(master_key));
    println!("Master chain code: {}", hex::encode(master_chain_code));
    
    // Step 2: Derive m/44' (purpose)
    let purpose_index = 44u32 | 0x80000000; // Hardened
    let mut data = Vec::new();
    data.push(0x00); // Hardened derivation prefix
    data.extend_from_slice(master_key);
    data.extend_from_slice(&purpose_index.to_be_bytes());
    
    let mut mac = HmacSha512::new_from_slice(master_chain_code)?;
    mac.update(&data);
    let purpose_result = mac.finalize().into_bytes();
    let purpose_key_add = &purpose_result[0..32];
    let purpose_chain_code = &purpose_result[32..64];
    
    println!("\nPurpose step:");
    println!("HMAC input data: {}", hex::encode(&data));
    println!("HMAC result: {}", hex::encode(&purpose_result));
    println!("Key to add: {}", hex::encode(purpose_key_add));
    
    // Manual modular addition
    let secp256k1_n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?;
    let purpose_key = add_mod_manual(master_key, purpose_key_add, &secp256k1_n);
    println!("Purpose key (manual): {}", hex::encode(&purpose_key));
    
    // GPU test for the same operation
    println!("\n=== GPU Child Key Derivation Test ===");
    
    let opencl_source = r#"
        #include "src/kernels/secp256k1.cl"
        #include "src/kernels/bip44.cl"
        
        __kernel void test_child_key_derivation(
            __global const uchar* parent_key,
            __global const uchar* parent_chain_code,
            const uint child_index,
            __global uchar* child_key,
            __global uchar* child_chain_code,
            __global uchar* debug_hmac_data,
            __global uchar* debug_hmac_result,
            __global uchar* debug_key_to_add
        ) {
            int gid = get_global_id(0);
            if (gid != 0) return;
            
            uchar local_parent_key[32];
            uchar local_parent_chain_code[32];
            uchar local_child_key[32];
            uchar local_child_chain_code[32];
            
            // Copy input data
            for (int i = 0; i < 32; i++) {
                local_parent_key[i] = parent_key[i];
                local_parent_chain_code[i] = parent_chain_code[i];
            }
            
            // Prepare HMAC data
            uchar data[37];
            data[0] = 0x00; // Hardened derivation
            for (int i = 0; i < 32; i++) {
                data[1 + i] = local_parent_key[i];
            }
            bytes_to_big_endian_32(child_index, &data[33]);
            
            // Copy debug data
            for (int i = 0; i < 37; i++) {
                debug_hmac_data[i] = data[i];
            }
            
            // Perform HMAC
            uchar hmac_result[64];
            hmac_sha512_bip44(local_parent_chain_code, 32, data, 37, hmac_result);
            
            // Copy debug HMAC result
            for (int i = 0; i < 64; i++) {
                debug_hmac_result[i] = hmac_result[i];
            }
            
            // Copy key to add for debugging
            for (int i = 0; i < 32; i++) {
                debug_key_to_add[i] = hmac_result[i];
            }
            
            // Perform modular addition
            big_num_add_mod(local_parent_key, hmac_result, SECP256K1_N, local_child_key);
            
            // Copy chain code
            for (int i = 0; i < 32; i++) {
                local_child_chain_code[i] = hmac_result[32 + i];
            }
            
            // Copy results
            for (int i = 0; i < 32; i++) {
                child_key[i] = local_child_key[i];
                child_chain_code[i] = local_child_chain_code[i];
            }
        }
    "#;
    
    let pro_que = ProQue::builder()
        .src(opencl_source)
        .dims(1)
        .build()?;
    
    // Create buffers
    let parent_key_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .build()?;
    
    let parent_chain_code_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .build()?;
    
    let child_key_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(32)
        .build()?;
    
    let child_chain_code_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(32)
        .build()?;
    
    let debug_hmac_data_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(37)
        .build()?;
    
    let debug_hmac_result_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(64)
        .build()?;
    
    let debug_key_to_add_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(32)
        .build()?;
    
    // Write input data
    parent_key_buffer.write(master_key).enq()?;
    parent_chain_code_buffer.write(master_chain_code).enq()?;
    
    // Execute kernel
    let kernel = pro_que.kernel_builder("test_child_key_derivation")
        .arg(&parent_key_buffer)
        .arg(&parent_chain_code_buffer)
        .arg(purpose_index)
        .arg(&child_key_buffer)
        .arg(&child_chain_code_buffer)
        .arg(&debug_hmac_data_buffer)
        .arg(&debug_hmac_result_buffer)
        .arg(&debug_key_to_add_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    // Read results
    let mut gpu_child_key = vec![0u8; 32];
    let mut gpu_child_chain_code = vec![0u8; 32];
    let mut gpu_hmac_data = vec![0u8; 37];
    let mut gpu_hmac_result = vec![0u8; 64];
    let mut gpu_key_to_add = vec![0u8; 32];
    
    child_key_buffer.read(&mut gpu_child_key).enq()?;
    child_chain_code_buffer.read(&mut gpu_child_chain_code).enq()?;
    debug_hmac_data_buffer.read(&mut gpu_hmac_data).enq()?;
    debug_hmac_result_buffer.read(&mut gpu_hmac_result).enq()?;
    debug_key_to_add_buffer.read(&mut gpu_key_to_add).enq()?;
    
    println!("GPU HMAC input data: {}", hex::encode(&gpu_hmac_data));
    println!("GPU HMAC result: {}", hex::encode(&gpu_hmac_result));
    println!("GPU key to add: {}", hex::encode(&gpu_key_to_add));
    println!("GPU child key: {}", hex::encode(&gpu_child_key));
    
    // Compare results
    if data == gpu_hmac_data {
        println!("✅ HMAC input data matches!");
    } else {
        println!("❌ HMAC input data differs!");
    }
    
    if purpose_result.as_slice() == gpu_hmac_result {
        println!("✅ HMAC results match!");
    } else {
        println!("❌ HMAC results differ!");
    }
    
    if purpose_key_add == gpu_key_to_add {
        println!("✅ Key to add matches!");
    } else {
        println!("❌ Key to add differs!");
    }
    
    if purpose_key == gpu_child_key {
        println!("✅ Child keys match!");
    } else {
        println!("❌ Child keys differ!");
        println!("Expected: {}", hex::encode(&purpose_key));
        println!("Got:      {}", hex::encode(&gpu_child_key));
    }
    
    Ok(())
}

fn add_mod_manual(a: &[u8], b: &[u8], modulus: &[u8]) -> Vec<u8> {
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
    
    result_bytes
}