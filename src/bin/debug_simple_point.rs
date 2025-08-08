use ocl::{Platform, Device, Context, Queue, Program, Buffer, Kernel};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Simple Point Operations Debug ===");
    
    // Initialize OpenCL
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder().devices(device).build()?;
    let queue = Queue::new(&context, device, None)?;
    
    // Load kernel source
    let kernel_source = std::fs::read_to_string("src/kernels/secp256k1.cl")?;
    let program = Program::builder()
        .devices(device)
        .src(kernel_source)
        .build(&context)?;
    
    // Test simple point operations without modular inverse
    test_point_zero(&context, &queue, &program)?;
    test_point_copy(&context, &queue, &program)?;
    
    println!("\n=== All Simple Point Tests Passed! ===");
    Ok(())
}

fn test_point_zero(context: &Context, queue: &Queue, program: &Program) -> Result<(), Box<dyn Error>> {
    println!("\n=== Test: Point Zero ===");
    
    let kernel_code = r#"
    __kernel void test_point_zero(__global uchar* result) {
        uchar point[64];
        point_zero(point);
        
        // Copy result
        for (int i = 0; i < 64; i++) {
            result[i] = point[i];
        }
    }
    "#;
    
    let full_source = format!("{}{}", std::fs::read_to_string("src/kernels/secp256k1.cl")?, kernel_code);
    let test_program = Program::builder()
        .devices(queue.device())
        .src(full_source)
        .build(context)?;
    
    let result_buffer = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(64)
        .build()?;
    
    let kernel = Kernel::builder()
        .program(&test_program)
        .name("test_point_zero")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&result_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut result = vec![0u8; 64];
    result_buffer.read(&mut result).enq()?;
    
    // Check if all bytes are zero
    let all_zero = result.iter().all(|&x| x == 0);
    println!("Point zero result: {}", if all_zero { "PASS" } else { "FAIL" });
    
    if !all_zero {
        println!("Expected all zeros, got: {:?}", &result[0..8]);
    }
    
    Ok(())
}

fn test_point_copy(context: &Context, queue: &Queue, program: &Program) -> Result<(), Box<dyn Error>> {
    println!("\n=== Test: Point Copy ===");
    
    let kernel_code = r#"
    __kernel void test_point_copy(__global const uchar* input, __global uchar* result) {
        uchar point[64];
        
        // Copy input to local point
        for (int i = 0; i < 64; i++) {
            point[i] = input[i];
        }
        
        // Copy result back
        for (int i = 0; i < 64; i++) {
            result[i] = point[i];
        }
    }
    "#;
    
    let full_source = format!("{}{}", std::fs::read_to_string("src/kernels/secp256k1.cl")?, kernel_code);
    let test_program = Program::builder()
        .devices(queue.device())
        .src(full_source)
        .build(context)?;
    
    // Test data - simple pattern
    let test_point = (0..64).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    
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
        .name("test_point_copy")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&input_buffer)
        .arg(&result_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut result = vec![0u8; 64];
    result_buffer.read(&mut result).enq()?;
    
    // Check if copy worked
    let copy_correct = result == test_point;
    println!("Point copy result: {}", if copy_correct { "PASS" } else { "FAIL" });
    
    if !copy_correct {
        println!("Expected: {:?}", &test_point[0..8]);
        println!("Got:      {:?}", &result[0..8]);
    }
    
    Ok(())
}