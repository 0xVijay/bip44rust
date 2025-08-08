use ocl::{Platform, Device, Context, Queue, Program, Buffer, Kernel};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Point Operations Debug ===");
    
    // Setup OpenCL
    let platform = Platform::default();
    let device = Device::first(platform)?;
    let context = Context::builder().devices(device).build()?;
    let queue = Queue::new(&context, device, None)?;
    
    // Load kernel source
    let kernel_source = std::fs::read_to_string("src/kernels/secp256k1.cl")?;
    
    let test_kernel = format!(
        r#"{}
        
        __kernel void test_point_double(
            __global const uchar* point_in,
            __global uchar* point_out,
            __global uchar* debug_info
        ) {{
            uchar point_local[64];
            uchar result_local[64];
            
            // Copy input point
            for (int i = 0; i < 64; i++) {{
                point_local[i] = point_in[i];
            }}
            
            // Test point doubling
            point_double(point_local, result_local);
            
            // Copy result
            for (int i = 0; i < 64; i++) {{
                point_out[i] = result_local[i];
            }}
            
            // Debug: copy input coordinates for verification
            for (int i = 0; i < 32; i++) {{
                debug_info[i] = point_local[i];      // x coordinate
                debug_info[32 + i] = point_local[32 + i]; // y coordinate
            }}
        }}
        "#,
        kernel_source
    );
    
    let program = Program::builder()
        .devices(device)
        .src(test_kernel)
        .build(&context)?;
    
    // Test with generator point: 2*G should give a known result
    println!("\n=== Test: 2 * Generator Point ===");
    
    // secp256k1 generator point
    let mut generator = vec![0u8; 64];
    
    // Gx
    let gx = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
    ];
    
    // Gy
    let gy = [
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
        0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
        0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
        0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
    ];
    
    // Copy coordinates to generator point
    for i in 0..32 {
        generator[i] = gx[i];
        generator[32 + i] = gy[i];
    }
    
    println!("Input Generator Point:");
    println!("  Gx: {:02x?}", &gx[28..32]);
    println!("  Gy: {:02x?}", &gy[28..32]);
    
    let point_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_READ_ONLY)
        .len(64)
        .copy_host_slice(&generator)
        .build()?;
    
    let result_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(64)
        .build()?;
    
    let debug_buffer = Buffer::builder()
        .queue(queue.clone())
        .flags(ocl::flags::MEM_WRITE_ONLY)
        .len(64)
        .build()?;
    
    let kernel = Kernel::builder()
        .program(&program)
        .name("test_point_double")
        .queue(queue.clone())
        .global_work_size(1)
        .arg(&point_buffer)
        .arg(&result_buffer)
        .arg(&debug_buffer)
        .build()?;
    
    unsafe { kernel.enq()?; }
    
    let mut result = vec![0u8; 64];
    let mut debug_info = vec![0u8; 64];
    
    result_buffer.read(&mut result).enq()?;
    debug_buffer.read(&mut debug_info).enq()?;
    
    println!("\nGPU Result (2*G):");
    println!("  X: {:02x?}", &result[28..32]);
    println!("  Y: {:02x?}", &result[60..64]);
    
    // Expected result for 2*G (from secp256k1 specification)
    // 2*G = (c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,
    //        1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a)
    let expected_2g_x = [
        0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d,
        0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8,
        0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7,
        0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5
    ];
    
    let expected_2g_y = [
        0x1a, 0xe1, 0x68, 0xfe, 0xa6, 0x3d, 0xc3, 0x39,
        0xa3, 0xc5, 0x84, 0x19, 0x46, 0x6c, 0xea, 0xee,
        0xf7, 0xf6, 0x32, 0x65, 0x32, 0x66, 0xd0, 0xe1,
        0x23, 0x64, 0x31, 0xa9, 0x50, 0xcf, 0xe5, 0x2a
    ];
    
    println!("\nExpected Result (2*G):");
    println!("  X: {:02x?}", &expected_2g_x[28..32]);
    println!("  Y: {:02x?}", &expected_2g_y[28..32]);
    
    // Check if results match
    let mut x_matches = true;
    let mut y_matches = true;
    
    for i in 0..32 {
        if result[i] != expected_2g_x[i] {
            x_matches = false;
        }
        if result[32 + i] != expected_2g_y[i] {
            y_matches = false;
        }
    }
    
    if x_matches && y_matches {
        println!("\n✅ Point doubling works correctly!");
    } else {
        println!("\n❌ Point doubling failed");
        if !x_matches {
            println!("  X coordinate mismatch");
            println!("    Expected: {:02x?}", expected_2g_x);
            println!("    Got:      {:02x?}", &result[0..32]);
        }
        if !y_matches {
            println!("  Y coordinate mismatch");
            println!("    Expected: {:02x?}", expected_2g_y);
            println!("    Got:      {:02x?}", &result[32..64]);
        }
    }
    
    // Verify input was copied correctly
    println!("\n=== Input Verification ===");
    let mut input_ok = true;
    for i in 0..64 {
        if debug_info[i] != generator[i] {
            input_ok = false;
            break;
        }
    }
    
    if input_ok {
        println!("✅ Input point copied correctly");
    } else {
        println!("❌ Input point copy failed");
    }
    
    Ok(())
}