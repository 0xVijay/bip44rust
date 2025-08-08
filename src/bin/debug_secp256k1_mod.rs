use ocl::{Platform, Device, Context, Queue, Program, Buffer, Kernel};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== secp256k1 Modular Operations Debug ===");
    
    // Setup OpenCL
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder().devices(device).build()?;
    let queue = Queue::new(&context, device, None)?;
    
    // Load kernel source
    let kernel_source = std::fs::read_to_string("src/kernels/secp256k1.cl")?;
    
    let test_kernel = format!(
        r#"{}
        
        __kernel void test_secp256k1_mod(
            __global const uchar* a,
            __global const uchar* b,
            __global uchar* add_result,
            __global uchar* mul_result,
            __global uchar* debug_info
        ) {{
            uchar a_local[32], b_local[32];
            uchar add_local[32], mul_local[32];
            
            // Copy inputs
            for (int i = 0; i < 32; i++) {{
                a_local[i] = a[i];
                b_local[i] = b[i];
            }}
            
            // Test addition with secp256k1 prime
            bn_mod_add(a_local, b_local, SECP256K1_P, add_local);
            
            // Test multiplication with secp256k1 prime
            bn_mod_mul(a_local, b_local, SECP256K1_P, mul_local);
            
            // Copy results
            for (int i = 0; i < 32; i++) {{
                add_result[i] = add_local[i];
                mul_result[i] = mul_local[i];
            }}
            
            // Debug: copy secp256k1 prime for verification
            for (int i = 0; i < 32; i++) {{
                debug_info[i] = SECP256K1_P[i];
            }}
        }}
        "#,
        kernel_source
    );
    
    let program = Program::builder()
        .devices(device)
        .src(test_kernel)
        .build(&context)?;
    
    // Test with simple values that should work
    println!("\n=== Test: Simple values with secp256k1 prime ===");
    let mut a = vec![0u8; 32];
    a[31] = 2;  // a = 2
    let mut b = vec![0u8; 32];
    b[31] = 3;  // b = 3
    
    println!("Testing: a=2, b=3 with secp256k1 prime");
    println!("Expected: add=5, mul=6");
    
    let a_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .copy_host_slice(&a)
        .build()?;
    
    let b_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(32)
        .copy_host_slice(&b)
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
        .len(32)
        .build()?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("test_secp256k1_mod")
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
    let mut debug_info = vec![0u8; 32];
    
    add_result_buffer.read(&mut add_result).enq()?;
    mul_result_buffer.read(&mut mul_result).enq()?;
    debug_buffer.read(&mut debug_info).enq()?;
    
    println!("Add result: {}", add_result[31]);
    println!("Mul result: {}", mul_result[31]);
    
    // Verify secp256k1 prime
    println!("\n=== secp256k1 Prime Verification ===");
    let expected_p = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
    ];
    
    let mut p_matches = true;
    for i in 0..32 {
        if debug_info[i] != expected_p[i] {
            p_matches = false;
            break;
        }
    }
    
    if p_matches {
        println!("✅ secp256k1 prime matches expected value");
    } else {
        println!("❌ secp256k1 prime mismatch");
        println!("Expected: {:02x?}", &expected_p[28..32]);
        println!("Got:      {:02x?}", &debug_info[28..32]);
    }
    
    // Test with generator point coordinates
    println!("\n=== Test: Generator point coordinate operations ===");
    
    // Test: 1 * Gx mod p (should equal Gx)
    let mut gx = vec![
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
    ];
    
    let mut one = vec![0u8; 32];
    one[31] = 1;
    
    println!("Testing: 1 * Gx mod p (should equal Gx)");
    
    a_buffer.write(&one).enq()?;
    b_buffer.write(&gx).enq()?;
    
    unsafe { kernel.enq()?; }
    
    add_result_buffer.read(&mut add_result).enq()?;
    mul_result_buffer.read(&mut mul_result).enq()?;
    
    let mut mul_matches = true;
    for i in 0..32 {
        if mul_result[i] != gx[i] {
            mul_matches = false;
            break;
        }
    }
    
    if mul_matches {
        println!("✅ 1 * Gx = Gx (modular multiplication works)");
    } else {
        println!("❌ 1 * Gx ≠ Gx (modular multiplication broken)");
        println!("Expected: {:02x?}", &gx[28..32]);
        println!("Got:      {:02x?}", &mul_result[28..32]);
    }
    
    Ok(())
}