use std::fs;
use ocl::{Platform, Device, Context, Queue, Program, Kernel, Buffer};
use hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing OpenCL kernels individually...");
    
    // Initialize OpenCL
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder()
        .platform(platform)
        .devices(device.clone())
        .build()?;
    let queue = Queue::new(&context, device, None)?;
    
    // Test PBKDF2 kernel
    println!("\n=== Testing PBKDF2 Kernel ===");
    test_pbkdf2_kernel(&context, &queue)?;
    
    // Test BIP44 kernel
    println!("\n=== Testing BIP44 Kernel ===");
    test_bip44_kernel(&context, &queue)?;
    
    // Test secp256k1 kernel
    println!("\n=== Testing secp256k1 Kernel ===");
    test_secp256k1_kernel(&context, &queue)?;
    
    // Test Keccak kernel
    println!("\n=== Testing Keccak Kernel ===");
    test_keccak_kernel(&context, &queue)?;
    
    Ok(())
}

fn test_pbkdf2_kernel(context: &Context, queue: &Queue) -> Result<(), Box<dyn std::error::Error>> {
    let source = fs::read_to_string("src/kernels/pbkdf2.cl")?;
    let program = Program::builder()
        .devices(queue.device())
        .src(source)
        .build(context)?;
    
    // Test with known mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let passphrase = "";
    let salt = format!("mnemonic{}", passphrase);
    
    let password_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(mnemonic.len())
        .build()?;
    
    let password_length_buffer: Buffer<i32> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(1)
        .build()?;
    
    let salt_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(salt.len())
        .build()?;
    
    let salt_length_buffer: Buffer<i32> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(1)
        .build()?;
    
    let seed_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(64)
        .build()?;
    
    password_buffer.write(mnemonic.as_bytes()).enq()?;
    password_length_buffer.write(&vec![mnemonic.len() as i32]).enq()?;
    salt_buffer.write(salt.as_bytes()).enq()?;
    salt_length_buffer.write(&vec![salt.len() as i32]).enq()?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("pbkdf2_hmac_sha512")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&password_buffer)
        .arg(&password_length_buffer)
        .arg(&salt_buffer)
        .arg(&salt_length_buffer)
        .arg(&seed_buffer)
        .arg(1i32)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut result = vec![0u8; 64];
    seed_buffer.read(&mut result).enq()?;
    
    println!("PBKDF2 result: {}", hex::encode(&result));
    
    // Expected result for this mnemonic (from CPU implementation)
    let expected = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    if hex::encode(&result) == expected {
        println!("✓ PBKDF2 kernel working correctly!");
    } else {
        println!("✗ PBKDF2 kernel result mismatch!");
        println!("Expected: {}", expected);
    }
    
    Ok(())
}

fn test_bip44_kernel(context: &Context, queue: &Queue) -> Result<(), Box<dyn std::error::Error>> {
    let secp256k1_source = fs::read_to_string("src/kernels/secp256k1.cl")?;
    let bip44_source = fs::read_to_string("src/kernels/bip44.cl")?;
    let combined_source = format!("{}{}", secp256k1_source, bip44_source);
    let program = Program::builder()
        .devices(queue.device())
        .src(combined_source)
        .build(context)?;
    
    // Use the seed from PBKDF2 test
    let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let seed = hex::decode(seed_hex)?;
    
    let seed_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(64)
        .build()?;
    
    let private_key_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(32)
        .build()?;
    
    let public_key_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(64)
        .build()?;
    
    let success_buffer: Buffer<i32> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(1)
        .build()?;
    
    // Derivation path: m/44'/60'/0'/0/2
    let derivation_path = vec![44u32, 60u32, 0u32, 0u32, 2u32];
    let derivation_path_buffer: Buffer<u32> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(5)
        .build()?;
    
    seed_buffer.write(&seed).enq()?;
    derivation_path_buffer.write(&derivation_path).enq()?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("bip44_derive_keys")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&seed_buffer)
        .arg(&private_key_buffer)
        .arg(&public_key_buffer)
        .arg(&success_buffer)
        .arg(&derivation_path_buffer)
        .arg(1i32)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut private_key = vec![0u8; 32];
    let mut public_key = vec![0u8; 64];
    let mut success = vec![0i32; 1];
    
    private_key_buffer.read(&mut private_key).enq()?;
    public_key_buffer.read(&mut public_key).enq()?;
    success_buffer.read(&mut success).enq()?;
    
    println!("BIP44 success: {}", success[0]);
    println!("Private key: {}", hex::encode(&private_key));
    println!("Public key: {}", hex::encode(&public_key));
    
    Ok(())
}

fn test_secp256k1_kernel(context: &Context, queue: &Queue) -> Result<(), Box<dyn std::error::Error>> {
    let source = fs::read_to_string("src/kernels/secp256k1.cl")?;
    let program = Program::builder()
        .devices(queue.device())
        .src(source)
        .build(context)?;
    
    // Test with a known private key
    let private_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let private_key = hex::decode(private_key_hex)?;
    
    let private_key_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .build()?;
    
    let public_key_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(64)
        .build()?;
    
    let success_buffer: Buffer<i32> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(1)
        .build()?;
    
    private_key_buffer.write(&private_key).enq()?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("secp256k1_generate_pubkey")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&private_key_buffer)
        .arg(&public_key_buffer)
        .arg(&success_buffer)
        .arg(1i32)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut public_key = vec![0u8; 64];
    let mut success = vec![0i32; 1];
    
    public_key_buffer.read(&mut public_key).enq()?;
    success_buffer.read(&mut success).enq()?;
    
    println!("secp256k1 success: {}", success[0]);
    println!("Public key: {}", hex::encode(&public_key));
    
    // Expected public key for private key = 1
    let expected = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    if hex::encode(&public_key) == expected {
        println!("✓ secp256k1 kernel working correctly!");
    } else {
        println!("✗ secp256k1 kernel result mismatch!");
        println!("Expected: {}", expected);
    }
    
    Ok(())
}

fn test_keccak_kernel(context: &Context, queue: &Queue) -> Result<(), Box<dyn std::error::Error>> {
    let source = fs::read_to_string("src/kernels/keccak.cl")?;
    let program = Program::builder()
        .devices(queue.device())
        .src(source)
        .build(context)?;
    
    // Test with known public key
    let public_key_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let public_key = hex::decode(public_key_hex)?;
    
    let public_key_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(64)
        .build()?;
    
    let address_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(20)
        .build()?;
    
    let checksum_buffer: Buffer<u8> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(42)
        .build()?;
    
    let success_buffer: Buffer<i32> = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(1)
        .build()?;
    
    public_key_buffer.write(&public_key).enq()?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("generate_ethereum_addresses")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&public_key_buffer)
        .arg(&address_buffer)
        .arg(&checksum_buffer)
        .arg(&success_buffer)
        .arg(1i32)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut address = vec![0u8; 20];
    address_buffer.read(&mut address).enq()?;
    
    let mut success = vec![0i32; 1];
    success_buffer.read(&mut success).enq()?;
    
    println!("Keccak success: {}", success[0]);
    println!("Ethereum address: 0x{}", hex::encode(&address));
    
    Ok(())
}