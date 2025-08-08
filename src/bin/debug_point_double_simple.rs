use ocl::{Platform, Device, Context, Queue, Program, Buffer, Kernel};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Simple Point Doubling Debug ===");
    
    // Initialize OpenCL
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder().devices(device).build()?;
    let queue = Queue::new(&context, device, None)?;
    
    // Test point doubling with a simplified approach
    test_point_double_simple(&context, &queue)?;
    
    println!("\n=== Point Doubling Test Complete ===");
    Ok(())
}

fn test_point_double_simple(context: &Context, queue: &Queue) -> Result<(), Box<dyn Error>> {
    println!("\n=== Test: Simple Point Doubling (without modular inverse) ===");
    
    let kernel_code = r#"
    // Simplified point doubling that avoids modular inverse
    void point_double_simple(const uchar point[64], uchar result[64]) {
        if (point_is_zero(point)) {
            point_zero(result);
            return;
        }
        
        uchar x[32], y[32];
        uchar temp[32];
        
        // Extract x and y coordinates
        for (int i = 0; i < 32; i++) {
            x[i] = point[i];
            y[i] = point[32 + i];
        }
        
        // For testing, just return a simple transformation
        // This is not mathematically correct but will test the infrastructure
        
        // rx = x + 1 (mod p)
        uchar one[32];
        bn_zero(one);
        one[31] = 1;
        bn_mod_add(x, one, SECP256K1_P, temp);
        
        // ry = y + 1 (mod p)
        uchar temp2[32];
        bn_mod_add(y, one, SECP256K1_P, temp2);
        
        // Copy result
        for (int i = 0; i < 32; i++) {
            result[i] = temp[i];
            result[32 + i] = temp2[i];
        }
    }
    
    __kernel void test_point_double_simple(__global const uchar* input, __global uchar* result) {
        uchar point[64];
        uchar doubled[64];
        
        // Copy input to local point
        for (int i = 0; i < 64; i++) {
            point[i] = input[i];
        }
        
        // Perform simple doubling
        point_double_simple(point, doubled);
        
        // Copy result back
        for (int i = 0; i < 64; i++) {
            result[i] = doubled[i];
        }
    }
    "#;
    
    let full_source = format!("{}{}", std::fs::read_to_string("src/kernels/secp256k1.cl")?, kernel_code);
    let test_program = Program::builder()
        .devices(queue.device())
        .src(full_source)
        .build(context)?;
    
    // Use a simple test point (not the actual generator)
    let mut test_point = vec![0u8; 64];
    test_point[31] = 5;  // x = 5
    test_point[63] = 7;  // y = 7
    
    println!("Input point:");
    println!("  x: {:02x}", test_point[31]);
    println!("  y: {:02x}", test_point[63]);
    
    let input_buffer = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(64)
        .copy_host_slice(&test_point)
        .build()?;
    
    let result_buffer = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(64)
        .build()?;
    
    let kernel = Kernel::builder()
        .program(&test_program)
        .name("test_point_double_simple")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&input_buffer)
        .arg(&result_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut result = vec![0u8; 64];
    result_buffer.read(&mut result).enq()?;
    
    println!("\nResult point:");
    println!("  x: {:02x}", result[31]);
    println!("  y: {:02x}", result[63]);
    
    // Expected: x = 5 + 1 = 6, y = 7 + 1 = 8
    let expected_x = 6;
    let expected_y = 8;
    
    let success = result[31] == expected_x && result[63] == expected_y;
    println!("\nSimple doubling result: {}", if success { "PASS" } else { "FAIL" });
    
    if !success {
        println!("Expected: x={}, y={}", expected_x, expected_y);
        println!("Got:      x={}, y={}", result[31], result[63]);
    }
    
    Ok(())
}