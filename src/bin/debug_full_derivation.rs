use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::Network;
use hmac::{Hmac, Mac};
use ocl::{ProQue, Buffer};
use sha2::Sha512;
use std::str::FromStr;

type HmacSha512 = Hmac<Sha512>;

fn main() -> Result<()> {
    println!("=== Full Derivation Step-by-Step Debug ===");
    
    // Use a hardcoded mnemonic for consistency
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str)?;
    let seed = mnemonic.to_seed("");
    
    println!("Seed: {}", hex::encode(&seed));
    
    // CPU derivation step by step
    println!("\n=== CPU Step-by-Step Derivation ===");
    
    // Master key derivation
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")?;
    mac.update(&seed);
    let master_result = mac.finalize().into_bytes();
    let mut current_key = master_result[0..32].to_vec();
    let mut current_chain_code = master_result[32..64].to_vec();
    
    println!("Master key: {}", hex::encode(&current_key));
    println!("Master chain code: {}", hex::encode(&current_chain_code));
    
    // Derivation path: m/44'/60'/0'/0/2
    let derivation_indices = [44u32 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 2];
    
    for (step, &index) in derivation_indices.iter().enumerate() {
        println!("\n--- Step {} (index: {}) ---", step + 1, index);
        
        // Prepare HMAC data
        let mut data = Vec::new();
        if index >= 0x80000000 {
            // Hardened derivation
            data.push(0x00);
            data.extend_from_slice(&current_key);
        } else {
            // Non-hardened derivation - need public key
            // For simplicity, we'll use the bitcoin crate for this step
            println!("Non-hardened derivation - using bitcoin crate");
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&current_key);
            let mut chain_code_bytes = [0u8; 32];
            chain_code_bytes.copy_from_slice(&current_chain_code);
            
            let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;
            let path_str = format!("m/44'/60'/0'/{}", index);
            let derivation_path = DerivationPath::from_str(&path_str)?;
            let derived = xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &derivation_path)?;
            current_key = derived.private_key.secret_bytes().to_vec();
            current_chain_code = derived.chain_code.as_bytes().to_vec();
            println!("Child key: {}", hex::encode(&current_key));
            println!("Child chain code: {}", hex::encode(&current_chain_code));
            continue;
        }
        data.extend_from_slice(&index.to_be_bytes());
        
        println!("HMAC data: {}", hex::encode(&data));
        
        // Perform HMAC
        let mut mac = HmacSha512::new_from_slice(&current_chain_code)?;
        mac.update(&data);
        let hmac_result = mac.finalize().into_bytes();
        
        println!("HMAC result: {}", hex::encode(&hmac_result));
        
        // Add to parent key (modulo secp256k1 order)
        let key_to_add = &hmac_result[0..32];
        let new_chain_code = &hmac_result[32..64];
        
        println!("Key to add: {}", hex::encode(key_to_add));
        
        // Manual modular addition
        let secp256k1_n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")?;
        let new_key = add_mod_manual(&current_key, key_to_add, &secp256k1_n);
        
        current_key = new_key;
        current_chain_code = new_chain_code.to_vec();
        
        println!("Child key: {}", hex::encode(&current_key));
        println!("Child chain code: {}", hex::encode(&current_chain_code));
    }
    
    println!("\nFinal CPU result: {}", hex::encode(&current_key));
    
    // GPU step-by-step test
    println!("\n=== GPU Step-by-Step Test ===");
    
    let opencl_source = r#"
        #include "src/kernels/secp256k1.cl"
        #include "src/kernels/bip44.cl"
        
        __kernel void debug_full_derivation(
            __global const uchar* seed,
            __global const uint* derivation_path,
            __global uchar* step_keys,      // 6 * 32 bytes (master + 5 steps)
            __global uchar* step_chain_codes, // 6 * 32 bytes
            __global uchar* step_hmac_data,  // 5 * 37 bytes
            __global uchar* step_hmac_results // 5 * 64 bytes
        ) {
            int gid = get_global_id(0);
            if (gid != 0) return;
            
            uchar local_seed[64];
            for (int i = 0; i < 64; i++) {
                local_seed[i] = seed[i];
            }
            
            // Master key derivation
            uchar master_key[32];
            uchar master_chain_code[32];
            uchar hmac_result[64];
            
            uchar bitcoin_seed[] = "Bitcoin seed";
            hmac_sha512_bip44(bitcoin_seed, 12, local_seed, 64, hmac_result);
            
            for (int i = 0; i < 32; i++) {
                master_key[i] = hmac_result[i];
                master_chain_code[i] = hmac_result[32 + i];
            }
            
            // Store master key and chain code
            for (int i = 0; i < 32; i++) {
                step_keys[i] = master_key[i];
                step_chain_codes[i] = master_chain_code[i];
            }
            
            uchar current_key[32], current_chain_code[32];
            for (int i = 0; i < 32; i++) {
                current_key[i] = master_key[i];
                current_chain_code[i] = master_chain_code[i];
            }
            
            // Derive each step
            for (int step = 0; step < 5; step++) {
                uint child_index = derivation_path[step];
                if (step < 3) {
                    child_index |= 0x80000000;
                }
                
                uchar data[37];
                if (child_index >= 0x80000000) {
                    // Hardened derivation
                    data[0] = 0x00;
                    for (int i = 0; i < 32; i++) {
                        data[1 + i] = current_key[i];
                    }
                } else {
                    // Non-hardened derivation
                    uchar public_key[64];
                    secp256k1_point_multiply(current_key, public_key);
                    data[0] = (public_key[63] & 1) ? 0x03 : 0x02;
                    for (int i = 0; i < 32; i++) {
                        data[1 + i] = public_key[i];
                    }
                }
                bytes_to_big_endian_32(child_index, &data[33]);
                
                // Store HMAC data for debugging
                for (int i = 0; i < 37; i++) {
                    step_hmac_data[step * 37 + i] = data[i];
                }
                
                // Perform HMAC
                hmac_sha512_bip44(current_chain_code, 32, data, 37, hmac_result);
                
                // Store HMAC result for debugging
                for (int i = 0; i < 64; i++) {
                    step_hmac_results[step * 64 + i] = hmac_result[i];
                }
                
                // Derive child key
                big_num_add_mod(current_key, hmac_result, SECP256K1_N, current_key);
                
                // Update chain code
                for (int i = 0; i < 32; i++) {
                    current_chain_code[i] = hmac_result[32 + i];
                }
                
                // Store step result
                for (int i = 0; i < 32; i++) {
                    step_keys[(step + 1) * 32 + i] = current_key[i];
                    step_chain_codes[(step + 1) * 32 + i] = current_chain_code[i];
                }
            }
        }
    "#;
    
    let pro_que = ProQue::builder()
        .src(opencl_source)
        .dims(1)
        .build()?;
    
    // Create buffers
    let seed_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(64)
        .build()?;
    
    let derivation_path_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(5)
        .build()?;
    
    let step_keys_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(6 * 32) // master + 5 steps
        .build()?;
    
    let step_chain_codes_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(6 * 32)
        .build()?;
    
    let step_hmac_data_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(5 * 37)
        .build()?;
    
    let step_hmac_results_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(5 * 64)
        .build()?;
    
    // Write input data
    let derivation_path = [44u32, 60, 0, 0, 2];
    seed_buffer.write(&seed[..]).enq()?;
    derivation_path_buffer.write(&derivation_path[..]).enq()?;
    
    // Execute kernel
    let kernel = pro_que.kernel_builder("debug_full_derivation")
        .arg(&seed_buffer)
        .arg(&derivation_path_buffer)
        .arg(&step_keys_buffer)
        .arg(&step_chain_codes_buffer)
        .arg(&step_hmac_data_buffer)
        .arg(&step_hmac_results_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    // Read results
    let mut gpu_step_keys = vec![0u8; 6 * 32];
    let mut gpu_step_chain_codes = vec![0u8; 6 * 32];
    let mut gpu_step_hmac_data = vec![0u8; 5 * 37];
    let mut gpu_step_hmac_results = vec![0u8; 5 * 64];
    
    step_keys_buffer.read(&mut gpu_step_keys).enq()?;
    step_chain_codes_buffer.read(&mut gpu_step_chain_codes).enq()?;
    step_hmac_data_buffer.read(&mut gpu_step_hmac_data).enq()?;
    step_hmac_results_buffer.read(&mut gpu_step_hmac_results).enq()?;
    
    // Compare step by step
    println!("GPU Master key: {}", hex::encode(&gpu_step_keys[0..32]));
    println!("GPU Master chain code: {}", hex::encode(&gpu_step_chain_codes[0..32]));
    
    for step in 0..5 {
        println!("\n--- GPU Step {} ---", step + 1);
        let hmac_data = &gpu_step_hmac_data[step * 37..(step + 1) * 37];
        let hmac_result = &gpu_step_hmac_results[step * 64..(step + 1) * 64];
        let step_key = &gpu_step_keys[(step + 1) * 32..(step + 2) * 32];
        let step_chain_code = &gpu_step_chain_codes[(step + 1) * 32..(step + 2) * 32];
        
        println!("GPU HMAC data: {}", hex::encode(hmac_data));
        println!("GPU HMAC result: {}", hex::encode(hmac_result));
        println!("GPU Step key: {}", hex::encode(step_key));
        println!("GPU Step chain code: {}", hex::encode(step_chain_code));
    }
    
    let final_gpu_key = &gpu_step_keys[5 * 32..6 * 32];
    println!("\nFinal GPU result: {}", hex::encode(final_gpu_key));
    
    // Compare final results
    if current_key == final_gpu_key {
        println!("\n✅ CPU and GPU final results match!");
    } else {
        println!("\n❌ CPU and GPU final results differ!");
        println!("CPU: {}", hex::encode(&current_key));
        println!("GPU: {}", hex::encode(final_gpu_key));
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