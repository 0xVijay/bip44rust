use ocl::{Platform, Device, Context, Queue, Program, Buffer, Kernel};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Modular Operations Debug ===");
    
    // Test simple modular multiplication: 2 * 3 mod 7 = 6
    let a = vec![0u8; 32];
    let mut a_test = a.clone();
    a_test[31] = 2; // a = 2
    
    let b = vec![0u8; 32];
    let mut b_test = b.clone();
    b_test[31] = 3; // b = 3
    
    // Simple modulus for testing: 7
    let p = vec![0u8; 32];
    let mut p_test = p.clone();
    p_test[31] = 7; // p = 7
    
    println!("Testing: 2 * 3 mod 7 (expected: 6)");
    
    // Setup OpenCL
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder().devices(device).build()?;
    let queue = Queue::new(&context, device, None)?;
    
    // Load kernel source
    let kernel_source = std::fs::read_to_string("src/kernels/secp256k1.cl")?;
    
    let test_kernel = format!(
        r#"{}
        
        __constant uchar TEST_MOD[32] = {{
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 7
        }};
        
        __kernel void test_mod_mul(
            __global const uchar* a,
            __global const uchar* b, 
            __global uchar* result
        ) {{
            uchar a_local[32], b_local[32], result_local[32];
            
            // Copy inputs
            for (int i = 0; i < 32; i++) {{
                a_local[i] = a[i];
                b_local[i] = b[i];
            }}
            
            // Test modular multiplication
            bn_mod_mul(a_local, b_local, TEST_MOD, result_local);
            
            // Copy result
            for (int i = 0; i < 32; i++) {{
                result[i] = result_local[i];
            }}
        }}
        "#,
        kernel_source
    );
    
    let program = Program::builder()
        .devices(device)
        .src(test_kernel)
        .build(&context)?;
    
    // Create buffers
    let a_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .copy_host_slice(&a_test)
        .build()?;
    
    let b_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .copy_host_slice(&b_test)
        .build()?;
    
    let result_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(32)
        .build()?;
    
    // Create and run kernel
    let kernel = Kernel::builder()
        .program(&program)
        .name("test_mod_mul")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&a_buffer)
        .arg(&b_buffer)
        .arg(&result_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    // Read result
    let mut gpu_result = vec![0u8; 32];
    result_buffer.read(&mut gpu_result).enq()?;
    
    println!("GPU result: {}", gpu_result[31]);
    println!("Expected: 6");
    
    if gpu_result[31] == 6 {
        println!("✅ Basic modular multiplication works!");
    } else {
        println!("❌ Basic modular multiplication failed");
        println!("Full GPU result: {:02x?}", gpu_result);
    }
    
    // Test with larger numbers
    println!("\n=== Testing with larger numbers ===");
    
    // Test: 123 * 456 mod 789
    let mut a_large = vec![0u8; 32];
    a_large[31] = 123;
    
    let mut b_large = vec![0u8; 32];
    b_large[30] = 1; // 456 = 0x01C8
    b_large[31] = 200; // 0xC8 = 200
    
    let mut p_large = vec![0u8; 32];
    p_large[30] = 3; // 789 = 0x0315
    p_large[31] = 21; // 0x15 = 21
    
    // Expected: 123 * 456 = 56088, 56088 mod 789 = 56088 - 71*789 = 56088 - 56019 = 69
    println!("Testing: 123 * 456 mod 789 (expected: 69)");
    
    a_buffer.write(&a_large).enq()?;
    b_buffer.write(&b_large).enq()?;
    
    unsafe { kernel.enq()?; }
    
    result_buffer.read(&mut gpu_result).enq()?;
    
    let gpu_value = (gpu_result[30] as u16) << 8 | gpu_result[31] as u16;
    println!("GPU result: {}", gpu_value);
    println!("Expected: 69");
    
    if gpu_value == 69 {
        println!("✅ Large number modular multiplication works!");
    } else {
        println!("❌ Large number modular multiplication failed");
        println!("Full GPU result: {:02x?}", &gpu_result[28..32]);
    }
    
    Ok(())
}