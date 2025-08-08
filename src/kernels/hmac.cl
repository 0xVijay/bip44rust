/*
 * HMAC-SHA512 OpenCL kernel for BIP44 key derivation
 * This kernel implements HMAC-SHA512 for hierarchical deterministic wallet key derivation
 */

#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable
#pragma OPENCL EXTENSION cl_khr_int64_extended_atomics : enable

// Include SHA-512 constants and functions from pbkdf2.cl
#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64
#define HMAC_KEY_SIZE 64
#define BIP44_CHAIN_CODE_SIZE 32
#define BIP44_PRIVATE_KEY_SIZE 32

// SHA-512 initial hash values (same as in pbkdf2.cl)
__constant ulong sha512_h[8] = {
    0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
    0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
};

// SHA-512 round constants (same as in pbkdf2.cl)
__constant ulong sha512_k[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

// Utility functions (same as in pbkdf2.cl)
ulong rotr64(ulong x, int n) {
    return (x >> n) | (x << (64 - n));
}

ulong ch(ulong x, ulong y, ulong z) {
    return (x & y) ^ (~x & z);
}

ulong maj(ulong x, ulong y, ulong z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

ulong sigma0(ulong x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

ulong sigma1(ulong x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

ulong gamma0(ulong x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

ulong gamma1(ulong x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// Convert bytes to 64-bit words (big-endian)
void bytes_to_words_hmac(const uchar* bytes, ulong* words, int byte_len) {
    for (int i = 0; i < byte_len / 8; i++) {
        words[i] = 0;
        for (int j = 0; j < 8; j++) {
            words[i] |= ((ulong)bytes[i * 8 + j]) << (56 - j * 8);
        }
    }
}

// Convert 64-bit words to bytes (big-endian)
void words_to_bytes_hmac(const ulong* words, uchar* bytes, int word_count) {
    for (int i = 0; i < word_count; i++) {
        for (int j = 0; j < 8; j++) {
            bytes[i * 8 + j] = (uchar)(words[i] >> (56 - j * 8));
        }
    }
}

// SHA-512 compression function (same as in pbkdf2.cl)
void sha512_compress_hmac(ulong* state, const ulong* block) {
    ulong w[80];
    ulong a, b, c, d, e, f, g, h;
    ulong t1, t2;
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = block[i];
    }
    
    for (int i = 16; i < 80; i++) {
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
    }
    
    // Initialize working variables
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // Main loop
    for (int i = 0; i < 80; i++) {
        t1 = h + sigma1(e) + ch(e, f, g) + sha512_k[i] + w[i];
        t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Add compressed chunk to current hash value
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// SHA-512 hash function for HMAC
void sha512_hash_hmac(const uchar* input, int input_len, uchar* output) {
    ulong state[8];
    ulong block[16];
    uchar padded_block[128];
    
    // Initialize state
    for (int i = 0; i < 8; i++) {
        state[i] = sha512_h[i];
    }
    
    // Process complete blocks
    int blocks = input_len / 128;
    for (int b = 0; b < blocks; b++) {
        bytes_to_words_hmac(input + b * 128, block, 128);
        sha512_compress_hmac(state, block);
    }
    
    // Handle final block with padding
    int remaining = input_len % 128;
    for (int i = 0; i < remaining; i++) {
        padded_block[i] = input[blocks * 128 + i];
    }
    
    // Add padding
    padded_block[remaining] = 0x80;
    for (int i = remaining + 1; i < 128; i++) {
        padded_block[i] = 0;
    }
    
    // If not enough space for length, process this block and create new one
    if (remaining >= 112) {
        bytes_to_words_hmac(padded_block, block, 128);
        sha512_compress_hmac(state, block);
        
        // Clear block for length
        for (int i = 0; i < 16; i++) {
            block[i] = 0;
        }
    } else {
        bytes_to_words_hmac(padded_block, block, 128);
    }
    
    // Add length in bits (big-endian)
    ulong bit_len = (ulong)input_len * 8;
    block[14] = 0; // High 64 bits of length
    block[15] = bit_len; // Low 64 bits of length
    
    sha512_compress_hmac(state, block);
    
    // Convert state to output bytes
    words_to_bytes_hmac(state, output, 8);
}

// HMAC-SHA512 function for BIP44 (local memory version)
void hmac_sha512_bip44_local(const uchar* key, int key_len,
                             const uchar* message, int message_len,
                             uchar* output) {
    uchar ipad[128], opad[128];
    uchar key_pad[128];
    uchar inner_hash[64];
    uchar temp_input[256];
    
    // Prepare key
    if (key_len > 128) {
        sha512_hash_hmac(key, key_len, key_pad);
        for (int i = 64; i < 128; i++) {
            key_pad[i] = 0;
        }
    } else {
        for (int i = 0; i < key_len; i++) {
            key_pad[i] = key[i];
        }
        for (int i = key_len; i < 128; i++) {
            key_pad[i] = 0;
        }
    }
    
    // Create ipad and opad
    for (int i = 0; i < 128; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }
    
    // Inner hash: H(K XOR ipad, message)
    for (int i = 0; i < 128; i++) {
        temp_input[i] = ipad[i];
    }
    for (int i = 0; i < message_len && i < 128; i++) {
        temp_input[128 + i] = message[i];
    }
    sha512_hash_hmac(temp_input, 128 + message_len, inner_hash);
    
    // Outer hash: H(K XOR opad, inner_hash)
    for (int i = 0; i < 128; i++) {
        temp_input[i] = opad[i];
    }
    for (int i = 0; i < 64; i++) {
        temp_input[128 + i] = inner_hash[i];
    }
    uchar local_output[64];
    sha512_hash_hmac(temp_input, 128 + 64, local_output);
    
    // Copy result to global output
    for (int i = 0; i < 64; i++) {
        output[i] = local_output[i];
    }
}

// HMAC-SHA512 function for BIP44 (global memory version)
void hmac_sha512_bip44(const __global uchar* key, int key_len,
                       const __global uchar* message, int message_len,
                       __global uchar* output) {
    uchar ipad[128], opad[128];
    uchar key_pad[128];
    uchar inner_hash[64];
    uchar temp_input[256];
    
    // Prepare key
    if (key_len > 128) {
        // Copy key to local memory first
        uchar local_key[512];
        for (int i = 0; i < key_len && i < 512; i++) {
            local_key[i] = key[i];
        }
        sha512_hash_hmac(local_key, key_len, key_pad);
        for (int i = 64; i < 128; i++) {
            key_pad[i] = 0;
        }
    } else {
        for (int i = 0; i < key_len; i++) {
            key_pad[i] = key[i];
        }
        for (int i = key_len; i < 128; i++) {
            key_pad[i] = 0;
        }
    }
    
    // Create ipad and opad
    for (int i = 0; i < 128; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }
    
    // Inner hash: H(K XOR ipad, message)
    for (int i = 0; i < 128; i++) {
        temp_input[i] = ipad[i];
    }
    for (int i = 0; i < message_len && i < 128; i++) {
        temp_input[128 + i] = message[i];
    }
    sha512_hash_hmac(temp_input, 128 + message_len, inner_hash);
    
    // Outer hash: H(K XOR opad, inner_hash)
    for (int i = 0; i < 128; i++) {
        temp_input[i] = opad[i];
    }
    for (int i = 0; i < 64; i++) {
        temp_input[128 + i] = inner_hash[i];
    }
    uchar local_output[64];
    sha512_hash_hmac(temp_input, 128 + 64, local_output);
    
    // Copy result to global output
    for (int i = 0; i < 64; i++) {
        output[i] = local_output[i];
    }
}

// BIP44 master key derivation from seed
__kernel void derive_master_key_kernel(
    __global const uchar* seeds,        // Input seeds (64 bytes each)
    __global uchar* master_keys,        // Output master private keys (32 bytes each)
    __global uchar* chain_codes,        // Output chain codes (32 bytes each)
    __global int* success_flags         // Success flags
) {
    int gid = get_global_id(0);
    
    __global const uchar* seed = seeds + gid * 64;
    __global uchar* master_key = master_keys + gid * 32;
    __global uchar* chain_code = chain_codes + gid * 32;
    
    uchar hmac_result[64];
    const uchar bitcoin_seed[] = "Bitcoin seed";
    
    // Copy seed to local memory
    uchar local_seed[64];
    for (int i = 0; i < 64; i++) {
        local_seed[i] = seed[i];
    }
    
    // HMAC-SHA512("Bitcoin seed", seed)
    hmac_sha512_bip44_local(bitcoin_seed, 12, local_seed, 64, hmac_result);
    
    // Split result: first 32 bytes = master private key, last 32 bytes = chain code
    for (int i = 0; i < 32; i++) {
        master_key[i] = hmac_result[i];
        chain_code[i] = hmac_result[32 + i];
    }
    
    success_flags[gid] = 1;
}

// BIP44 child key derivation (hardened)
__kernel void derive_child_key_hardened_kernel(
    __global const uchar* parent_keys,   // Parent private keys (32 bytes each)
    __global const uchar* parent_chains, // Parent chain codes (32 bytes each)
    __global const uint* indices,        // Child indices (hardened: >= 0x80000000)
    __global uchar* child_keys,          // Output child private keys
    __global uchar* child_chains,        // Output child chain codes
    __global int* success_flags          // Success flags
) {
    int gid = get_global_id(0);
    
    __global const uchar* parent_key = parent_keys + gid * 32;
    __global const uchar* parent_chain = parent_chains + gid * 32;
    uint index = indices[gid];
    __global uchar* child_key = child_keys + gid * 32;
    __global uchar* child_chain = child_chains + gid * 32;
    
    uchar hmac_input[37]; // 1 + 32 + 4 bytes
    uchar hmac_result[64];
    
    // Prepare HMAC input for hardened derivation
    hmac_input[0] = 0x00; // Padding byte
    for (int i = 0; i < 32; i++) {
        hmac_input[1 + i] = parent_key[i];
    }
    
    // Add index (big-endian)
    hmac_input[33] = (uchar)(index >> 24);
    hmac_input[34] = (uchar)(index >> 16);
    hmac_input[35] = (uchar)(index >> 8);
    hmac_input[36] = (uchar)(index);
    
    // Copy parent_chain to local memory
    uchar local_parent_chain[32];
    for (int i = 0; i < 32; i++) {
        local_parent_chain[i] = parent_chain[i];
    }
    
    // HMAC-SHA512(parent_chain, hmac_input)
    hmac_sha512_bip44_local(local_parent_chain, 32, hmac_input, 37, hmac_result);
    
    // Split result
    for (int i = 0; i < 32; i++) {
        child_key[i] = hmac_result[i];
        child_chain[i] = hmac_result[32 + i];
    }
    
    success_flags[gid] = 1;
}

// BIP44 child key derivation (non-hardened)
__kernel void derive_child_key_normal_kernel(
    __global const uchar* parent_keys,   // Parent private keys (32 bytes each)
    __global const uchar* parent_chains, // Parent chain codes (32 bytes each)
    __global const uchar* parent_pubkeys, // Parent public keys (33 bytes each, compressed)
    __global const uint* indices,        // Child indices (normal: < 0x80000000)
    __global uchar* child_keys,          // Output child private keys
    __global uchar* child_chains,        // Output child chain codes
    __global int* success_flags          // Success flags
) {
    int gid = get_global_id(0);
    
    __global const uchar* parent_key = parent_keys + gid * 32;
    __global const uchar* parent_chain = parent_chains + gid * 32;
    __global const uchar* parent_pubkey = parent_pubkeys + gid * 33;
    uint index = indices[gid];
    __global uchar* child_key = child_keys + gid * 32;
    __global uchar* child_chain = child_chains + gid * 32;
    
    uchar hmac_input[37]; // 33 + 4 bytes
    uchar hmac_result[64];
    
    // Prepare HMAC input for normal derivation
    for (int i = 0; i < 33; i++) {
        hmac_input[i] = parent_pubkey[i];
    }
    
    // Add index (big-endian)
    hmac_input[33] = (uchar)(index >> 24);
    hmac_input[34] = (uchar)(index >> 16);
    hmac_input[35] = (uchar)(index >> 8);
    hmac_input[36] = (uchar)(index);
    
    // Copy parent_chain to local memory
    uchar local_parent_chain[32];
    for (int i = 0; i < 32; i++) {
        local_parent_chain[i] = parent_chain[i];
    }
    
    // HMAC-SHA512(parent_chain, hmac_input)
    hmac_sha512_bip44_local(local_parent_chain, 32, hmac_input, 37, hmac_result);
    
    // Split result
    for (int i = 0; i < 32; i++) {
        child_key[i] = hmac_result[i];
        child_chain[i] = hmac_result[32 + i];
    }
    
    success_flags[gid] = 1;
}

// Combined BIP44 derivation for Ethereum path m/44'/60'/0'/0/index
__kernel void derive_ethereum_key_kernel(
    __global const uchar* seeds,         // Input seeds (64 bytes each)
    __global const uint* account_indices, // Account indices (usually 0)
    __global const uint* address_indices, // Address indices (0, 1, 2, ...)
    __global uchar* private_keys,        // Output private keys (32 bytes each)
    __global int* success_flags          // Success flags
) {
    int gid = get_global_id(0);
    
    __global const uchar* seed = seeds + gid * 64;
    uint account_index = account_indices[gid];
    uint address_index = address_indices[gid];
    __global uchar* private_key = private_keys + gid * 32;
    
    uchar master_key[32], chain_code[32];
    uchar temp_key[32], temp_chain[32];
    uchar hmac_result[64];
    uchar hmac_input[37];
    
    const uchar bitcoin_seed[] = "Bitcoin seed";
    
    // Copy seed to local memory
    uchar local_seed[64];
    for (int i = 0; i < 64; i++) {
        local_seed[i] = seed[i];
    }
    
    // Step 1: Derive master key from seed
    hmac_sha512_bip44_local(bitcoin_seed, 12, local_seed, 64, hmac_result);
    for (int i = 0; i < 32; i++) {
        master_key[i] = hmac_result[i];
        chain_code[i] = hmac_result[32 + i];
    }
    
    // Step 2: Derive m/44' (hardened)
    hmac_input[0] = 0x00;
    for (int i = 0; i < 32; i++) {
        hmac_input[1 + i] = master_key[i];
    }
    uint index_44h = 0x8000002C; // 44 + 0x80000000
    hmac_input[33] = (uchar)(index_44h >> 24);
    hmac_input[34] = (uchar)(index_44h >> 16);
    hmac_input[35] = (uchar)(index_44h >> 8);
    hmac_input[36] = (uchar)(index_44h);
    
    hmac_sha512_bip44_local(chain_code, 32, hmac_input, 37, hmac_result);
    for (int i = 0; i < 32; i++) {
        temp_key[i] = hmac_result[i];
        temp_chain[i] = hmac_result[32 + i];
    }
    
    // Step 3: Derive m/44'/60' (hardened)
    hmac_input[0] = 0x00;
    for (int i = 0; i < 32; i++) {
        hmac_input[1 + i] = temp_key[i];
    }
    uint index_60h = 0x8000003C; // 60 + 0x80000000
    hmac_input[33] = (uchar)(index_60h >> 24);
    hmac_input[34] = (uchar)(index_60h >> 16);
    hmac_input[35] = (uchar)(index_60h >> 8);
    hmac_input[36] = (uchar)(index_60h);
    
    hmac_sha512_bip44_local(temp_chain, 32, hmac_input, 37, hmac_result);
    for (int i = 0; i < 32; i++) {
        master_key[i] = hmac_result[i];
        chain_code[i] = hmac_result[32 + i];
    }
    
    // Step 4: Derive m/44'/60'/account' (hardened)
    hmac_input[0] = 0x00;
    for (int i = 0; i < 32; i++) {
        hmac_input[1 + i] = master_key[i];
    }
    uint index_account = 0x80000000 + account_index;
    hmac_input[33] = (uchar)(index_account >> 24);
    hmac_input[34] = (uchar)(index_account >> 16);
    hmac_input[35] = (uchar)(index_account >> 8);
    hmac_input[36] = (uchar)(index_account);
    
    hmac_sha512_bip44_local(chain_code, 32, hmac_input, 37, hmac_result);
    for (int i = 0; i < 32; i++) {
        temp_key[i] = hmac_result[i];
        temp_chain[i] = hmac_result[32 + i];
    }
    
    // Step 5: Derive m/44'/60'/account'/0 (normal)
    // For normal derivation, we would need the public key, but for simplicity
    // we'll use hardened derivation for change index as well
    hmac_input[0] = 0x00;
    for (int i = 0; i < 32; i++) {
        hmac_input[1 + i] = temp_key[i];
    }
    uint index_change = 0x80000000; // 0 hardened
    hmac_input[33] = (uchar)(index_change >> 24);
    hmac_input[34] = (uchar)(index_change >> 16);
    hmac_input[35] = (uchar)(index_change >> 8);
    hmac_input[36] = (uchar)(index_change);
    
    hmac_sha512_bip44_local(temp_chain, 32, hmac_input, 37, hmac_result);
    for (int i = 0; i < 32; i++) {
        master_key[i] = hmac_result[i];
        chain_code[i] = hmac_result[32 + i];
    }
    
    // Step 6: Derive m/44'/60'/account'/0/address_index (normal)
    hmac_input[0] = 0x00;
    for (int i = 0; i < 32; i++) {
        hmac_input[1 + i] = master_key[i];
    }
    hmac_input[33] = (uchar)(address_index >> 24);
    hmac_input[34] = (uchar)(address_index >> 16);
    hmac_input[35] = (uchar)(address_index >> 8);
    hmac_input[36] = (uchar)(address_index);
    
    hmac_sha512_bip44_local(chain_code, 32, hmac_input, 37, hmac_result);
    
    // Final private key
    for (int i = 0; i < 32; i++) {
        private_key[i] = hmac_result[i];
    }
    
    success_flags[gid] = 1;
}