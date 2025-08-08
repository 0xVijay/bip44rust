use ocl::{Platform, Device, Context, Queue, Program, Buffer, Kernel};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Big Number Operations Debug ===");
    
    // Setup OpenCL
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder().devices(device).build()?;
    let queue = Queue::new(&context, device, None)?;
    
    // Load kernel source
    let kernel_source = std::fs::read_to_string("src/kernels/secp256k1.cl")?;
    
    let test_kernel = format!(
        r#"{}
        
        __kernel void test_bn_operations(
            __global const uchar* a,
            __global const uchar* b,
            __global uchar* add_result,
            __global uchar* mul_result,
            __global int* debug_info
        ) {{
            uchar a_local[32], b_local[32];
            uchar add_local[32], mul_local[32];
            
            // Copy inputs
            for (int i = 0; i < 32; i++) {{
                a_local[i] = a[i];
                b_local[i] = b[i];
            }}
            
            // Test addition
            bn_mod_add(a_local, b_local, SECP256K1_P, add_local);
            
            // Test multiplication with a simple modulus
            uchar simple_mod[32];
            bn_zero(simple_mod);
            simple_mod[31] = 100;  // mod 100
            
            bn_mod_mul_local(a_local, b_local, simple_mod, mul_local);
            
            // Copy results
            for (int i = 0; i < 32; i++) {{
                add_result[i] = add_local[i];
                mul_result[i] = mul_local[i];
            }}
            
            // Debug info
            debug_info[0] = a_local[31];  // a value
            debug_info[1] = b_local[31];  // b value
            debug_info[2] = add_local[31]; // add result
            debug_info[3] = mul_local[31]; // mul result
        }}
        "#,
        kernel_source
    );
    
    let program = Program::builder()
        .devices(device)
        .src(test_kernel)
        .build(&context)?;
    
    // Test 1: Simple single-byte numbers
    println!("\n=== Test 1: Single-byte numbers ===");
    let mut a1 = vec![0u8; 32];
    a1[31] = 5;
    let mut b1 = vec![0u8; 32];
    b1[31] = 7;
    
    println!("Testing: a=5, b=7");
    println!("Expected: add=12, mul=35 mod 100 = 35");
    
    let a_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_WRITE)
        .len(32)
        .copy_host_slice(&a1)
        .build()?;
    
    let b_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_WRITE)
        .len(32)
        .copy_host_slice(&b1)
        .build()?;
    
    let add_result_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(32)
        .build()?;
    
    let mul_result_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(32)
        .build()?;
    
    let debug_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(4)
        .build()?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("test_bn_operations")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&a_buffer)
        .arg(&b_buffer)
        .arg(&add_result_buffer)
        .arg(&mul_result_buffer)
        .arg(&debug_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut add_result = vec![0u8; 32];
    let mut mul_result = vec![0u8; 32];
    let mut debug_info = vec![0i32; 4];
    
    add_result_buffer.read(&mut add_result).enq()?;
    mul_result_buffer.read(&mut mul_result).enq()?;
    debug_buffer.read(&mut debug_info).enq()?;
    
    println!("Debug info: a={}, b={}, add={}, mul={}", 
             debug_info[0], debug_info[1], debug_info[2], debug_info[3]);
    println!("Add result: {}", add_result[31]);
    println!("Mul result: {}", mul_result[31]);
    
    // Test 2: Two-byte numbers
    println!("\n=== Test 2: Two-byte numbers ===");
    let mut a2 = vec![0u8; 32];
    a2[30] = 1;  // 256
    a2[31] = 0;
    let mut b2 = vec![0u8; 32];
    b2[30] = 0;
    b2[31] = 2;  // 2
    
    println!("Testing: a=256, b=2");
    println!("Expected: add=258, mul=512 mod 100 = 12");
    
    a_buffer.write(&a2).enq()?;
    b_buffer.write(&b2).enq()?;
    
    unsafe { kernel.enq()?; }
    
    add_result_buffer.read(&mut add_result).enq()?;
    mul_result_buffer.read(&mut mul_result).enq()?;
    debug_buffer.read(&mut debug_info).enq()?;
    
    let add_val = (add_result[30] as u16) << 8 | add_result[31] as u16;
    let mul_val = (mul_result[30] as u16) << 8 | mul_result[31] as u16;
    
    println!("Debug info: a={}, b={}, add={}, mul={}", 
             debug_info[0], debug_info[1], debug_info[2], debug_info[3]);
    println!("Add result: {} (bytes: {:02x} {:02x})", add_val, add_result[30], add_result[31]);
    println!("Mul result: {} (bytes: {:02x} {:02x})", mul_val, mul_result[30], mul_result[31]);
    
    Ok(())
}