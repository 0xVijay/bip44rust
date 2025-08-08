use ethereum_seed_recovery::opencl::{OpenCLContext, OpenCLConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Modular Addition Debug Test ===");
    
    // Test the big_num_add_mod function with known values
    let config = OpenCLConfig::default();
    let mut context = OpenCLContext::new(config)?;
    context.initialize_kernels()?;
    
    // Create a simple test kernel to test modular addition
    let kernel_source = format!(
        "{}
{}

__kernel void test_modular_add(
    __global const uchar* a,
    __global const uchar* b,
    __global uchar* result
) {{
    uchar local_a[32], local_b[32], local_result[32];
    for (int i = 0; i < 32; i++) {{
        local_a[i] = a[i];
        local_b[i] = b[i];
    }}
    big_num_add_mod(local_a, local_b, SECP256K1_N, local_result);
    for (int i = 0; i < 32; i++) {{
        result[i] = local_result[i];
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
    
    // Test case: parent key from our debug output
    let parent_key = hex::decode("a268ffdc70b282391907bbd337986ee37e246059a4fc2ede8e93a6ea0b5593fc")?;
    // HMAC result left 32 bytes from step 4 (we need to calculate this properly)
    let hmac_left = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")?; // Simple test case
    
    println!("Parent key: {}", hex::encode(&parent_key));
    println!("HMAC left:  {}", hex::encode(&hmac_left));
    
    let a_buffer = pro_que.buffer_builder::<u8>()
        .len(32)
        .build()?;
    let b_buffer = pro_que.buffer_builder::<u8>()
        .len(32)
        .build()?;
    let result_buffer = pro_que.buffer_builder::<u8>()
        .len(32)
        .build()?;
    
    a_buffer.write(&parent_key).enq()?;
    b_buffer.write(&hmac_left).enq()?;
    
    let kernel = pro_que.kernel_builder("test_modular_add")
        .arg(&a_buffer)
        .arg(&b_buffer)
        .arg(&result_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut gpu_result = vec![0u8; 32];
    result_buffer.read(&mut gpu_result).enq()?;
    
    println!("GPU result: {}", hex::encode(&gpu_result));
    
    // Manual calculation for comparison
    let mut manual_result = parent_key.clone();
    // Simple addition (not modular for this test)
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = manual_result[i] as u16 + hmac_left[i] as u16 + carry;
        manual_result[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    
    println!("Manual add: {}", hex::encode(&manual_result));
    
    // Test with secp256k1 curve order
    let secp256k1_n = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")?;
    println!("Secp256k1 N: {}", hex::encode(&secp256k1_n));
    
    Ok(())
}