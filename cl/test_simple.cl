// Minimal test kernel for GPU pipeline validation

// Test kernel that just checks word index patterns
__kernel void test_simple(
    __global const ushort* word_indices,
    __global uint* results,
    const uint batch_size,
    __global const uchar* target_address
) {
    uint idx = get_global_id(0);
    if (idx >= batch_size) return;
    
    // Initialize result as no match
    results[idx] = 0;
    
    // Get word indices for this candidate (12 words)
    ushort indices[12];
    for (int i = 0; i < 12; i++) {
        indices[i] = word_indices[idx * 12 + i];
    }
    
    // Simple test: check if this matches our known solution pattern
    // "inner barely tiny cup busy ramp stuff accuse timber exercise then decline"
    // Word indices: [931, 148, 1811, 429, 249, 1419, 1724, 13, 1809, 634, 1793, 455]
    
    if (indices[0] == 931 && indices[1] == 148 && indices[2] == 1811 &&
        indices[3] == 429 && indices[4] == 249 && indices[5] == 1419 &&
        indices[6] == 1724 && indices[7] == 13 && indices[8] == 1809 &&
        indices[9] == 634 && indices[10] == 1793 && indices[11] == 455) {
        results[idx] = 1;
    }
}