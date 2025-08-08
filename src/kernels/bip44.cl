// BIP44 Hierarchical Deterministic Key Derivation OpenCL Kernel
// Implements BIP44 key derivation for Ethereum wallets
// Derivation path: m/44'/60'/0'/0/2 (Metamask standard)

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#define SECP256K1_N_SIZE 32
#define PRIVATE_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 64
#define CHAIN_CODE_SIZE 32
#define HMAC_SHA512_SIZE 64
#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128

// secp256k1 curve parameters are defined in secp256k1.cl

// BIP44 derivation path constants
#define BIP44_PURPOSE 0x8000002C  // 44'
#define BIP44_COIN_TYPE 0x8000003C // 60' (Ethereum)
#define BIP44_ACCOUNT 0x80000000   // 0'
#define BIP44_CHANGE 0x00000000    // 0 (external)
#define BIP44_ADDRESS_INDEX 0x00000002 // 2

// SHA-512 constants (reused from pbkdf2.cl)
__constant ulong K[80] = {
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

// Right rotate for 64-bit values
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

// SHA-512 functions
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define Sigma1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define sigma0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define sigma1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

// Convert 64-bit to bytes big-endian
void u64_to_bytes_be(ulong value, __private uchar* bytes, int offset) {
    bytes[offset] = (uchar)(value >> 56);
    bytes[offset + 1] = (uchar)(value >> 48);
    bytes[offset + 2] = (uchar)(value >> 40);
    bytes[offset + 3] = (uchar)(value >> 32);
    bytes[offset + 4] = (uchar)(value >> 24);
    bytes[offset + 5] = (uchar)(value >> 16);
    bytes[offset + 6] = (uchar)(value >> 8);
    bytes[offset + 7] = (uchar)value;
}

// SHA-512 compression function
void sha512_compress(ulong state[8], const ulong block[16]) {
    ulong W[80];
    ulong a, b, c, d, e, f, g, h;
    ulong T1, T2;
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        W[i] = block[i];
    }
    
    for (int i = 16; i < 80; i++) {
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }
    
    // Initialize working variables
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    // Main loop
    for (int i = 0; i < 80; i++) {
        T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    
    // Add to state
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// SHA-512 hash function
void sha512(__private const uchar* input, int input_len, __private uchar output[64]) {
    ulong state[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };
    
    ulong block[16];
    int blocks = (input_len + 128) / 128; // Include padding
    
    for (int b = 0; b < blocks; b++) {
        // Clear block
        for (int i = 0; i < 16; i++) block[i] = 0;
        
        int block_start = b * 128;
        int block_len = min(128, input_len - block_start);
        
        // Copy data to block
        for (int i = 0; i < block_len; i += 8) {
            if (block_start + i < input_len) {
                int remaining = min(8, input_len - (block_start + i));
                ulong word = 0;
                for (int j = 0; j < remaining; j++) {
                    word |= ((ulong)input[block_start + i + j]) << (56 - j * 8);
                }
                block[i / 8] = word;
            }
        }
        
        // Add padding on last block
        if (b == blocks - 1) {
            if (block_len < 128) {
                // Add padding bit
                int pad_byte = block_len;
                int word_idx = pad_byte / 8;
                int byte_idx = pad_byte % 8;
                block[word_idx] |= 0x80UL << (56 - byte_idx * 8);
            }
            
            // Add length in bits at end
            block[15] = (ulong)input_len * 8;
        }
        
        sha512_compress(state, block);
    }
    
    // Convert state to output bytes
    for (int i = 0; i < 8; i++) {
        u64_to_bytes_be(state[i], output, i * 8);
    }
}

// HMAC-SHA512 function (proper implementation)
void hmac_sha512_bip44(__private const uchar* key, int key_len,
                       __private const uchar* data, int data_len,
                       __private uchar output[64]) {
    uchar ipad[128], opad[128];
    uchar key_pad[128];
    uchar inner_hash[64];
    
    // Prepare key
    for (int i = 0; i < 128; i++) {
        if (i < key_len) {
            key_pad[i] = key[i];
        } else {
            key_pad[i] = 0;
        }
    }
    
    // If key is longer than block size, hash it
    if (key_len > 128) {
        sha512(key, key_len, key_pad);
        for (int i = 64; i < 128; i++) {
            key_pad[i] = 0;
        }
    }
    
    // Create ipad and opad
    for (int i = 0; i < 128; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }
    
    // Inner hash: SHA512(ipad || data)
    uchar inner_input[128 + 1024]; // Assume max data length
    for (int i = 0; i < 128; i++) {
        inner_input[i] = ipad[i];
    }
    for (int i = 0; i < data_len && i < 1024; i++) {
        inner_input[128 + i] = data[i];
    }
    sha512(inner_input, 128 + data_len, inner_hash);
    
    // Outer hash: SHA512(opad || inner_hash)
    uchar outer_input[128 + 64];
    for (int i = 0; i < 128; i++) {
        outer_input[i] = opad[i];
    }
    for (int i = 0; i < 64; i++) {
        outer_input[128 + i] = inner_hash[i];
    }
    sha512(outer_input, 128 + 64, output);
}

// Big number comparison (-1: a < b, 0: a == b, 1: a > b)
int big_num_compare(const uchar a[32], const uchar b[32]) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// Version for comparing with constant memory
int big_num_compare_const(const uchar a[32], __constant const uchar* b) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// Proper big number addition with modulo
void big_num_add_mod(const uchar a[32], const uchar b[32], __constant const uchar* mod, uchar result[32]) {
    uint carry = 0;
    uchar temp[32];
    
    // Add a + b
    for (int i = 31; i >= 0; i--) {
        uint sum = (uint)a[i] + (uint)b[i] + carry;
        temp[i] = (uchar)(sum & 0xFF);
        carry = sum >> 8;
    }
    
    // If result >= mod, subtract mod
    if (carry || big_num_compare_const(temp, mod) >= 0) {
        carry = 0;
        for (int i = 31; i >= 0; i--) {
            int diff = (int)temp[i] - (int)mod[i] - carry;
            if (diff < 0) {
                result[i] = (uchar)(diff + 256);
                carry = 1;
            } else {
                result[i] = (uchar)diff;
                carry = 0;
            }
        }
    } else {
        for (int i = 0; i < 32; i++) {
            result[i] = temp[i];
        }
    }
}

// Verify private key is valid (not zero, less than curve order)
int secp256k1_verify_private_key(const uchar key[32]) {
    // Check if key is zero
    int is_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (key[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    if (is_zero) return 0;
    
    // Check if key < curve order
    return big_num_compare_const(key, SECP256K1_N) < 0;
}

// Convert 32-bit integer to big-endian bytes
void bytes_to_big_endian_32(uint value, uchar bytes[4]) {
    bytes[0] = (uchar)(value >> 24);
    bytes[1] = (uchar)(value >> 16);
    bytes[2] = (uchar)(value >> 8);
    bytes[3] = (uchar)value;
}

// SHA-256 constants
__constant uint sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 helper functions
uint rotr32(uint x, int n) {
    return (x >> n) | (x << (32 - n));
}

uint ch(uint x, uint y, uint z) {
    return (x & y) ^ (~x & z);
}

uint maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint sha256_sigma0(uint x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

uint sha256_sigma1(uint x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

uint sha256_gamma0(uint x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

uint sha256_gamma1(uint x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

// Simple SHA-256 implementation
void sha256_hash(const uchar* input, uint input_len, uchar* output) {
    uint h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Prepare message with padding
    uchar message[128]; // Support up to 64 bytes input + padding
    for (uint i = 0; i < input_len && i < 64; i++) {
        message[i] = input[i];
    }
    
    // Add padding
    message[input_len] = 0x80;
    for (uint i = input_len + 1; i < 64; i++) {
        message[i] = 0;
    }
    
    // Add length in bits (big-endian)
    uint bit_len = input_len * 8;
    message[60] = (bit_len >> 24) & 0xff;
    message[61] = (bit_len >> 16) & 0xff;
    message[62] = (bit_len >> 8) & 0xff;
    message[63] = bit_len & 0xff;
    
    // Process the message in 512-bit chunks
    uint w[64];
    
    // Break chunk into sixteen 32-bit big-endian words
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint)message[i*4] << 24) | ((uint)message[i*4+1] << 16) | 
               ((uint)message[i*4+2] << 8) | (uint)message[i*4+3];
    }
    
    // Extend the sixteen 32-bit words into sixty-four 32-bit words
    for (int i = 16; i < 64; i++) {
        w[i] = sha256_gamma1(w[i-2]) + w[i-7] + sha256_gamma0(w[i-15]) + w[i-16];
    }
    
    // Initialize working variables
    uint a = h[0], b = h[1], c = h[2], d = h[3];
    uint e = h[4], f = h[5], g = h[6], h_var = h[7];
    
    // Main loop
    for (int i = 0; i < 64; i++) {
        uint t1 = h_var + sha256_sigma1(e) + ch(e, f, g) + sha256_k[i] + w[i];
        uint t2 = sha256_sigma0(a) + maj(a, b, c);
        h_var = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    // Add this chunk's hash to result
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_var;
    
    // Convert to bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        output[i*4] = (h[i] >> 24) & 0xff;
        output[i*4+1] = (h[i] >> 16) & 0xff;
        output[i*4+2] = (h[i] >> 8) & 0xff;
        output[i*4+3] = h[i] & 0xff;
    }
}

// secp256k1 point multiplication: private_key * G
void secp256k1_point_multiply(const uchar scalar[32], uchar result[64]) {
    // Copy scalar to local memory
    uchar local_scalar[32];
    for (int i = 0; i < 32; i++) {
        local_scalar[i] = scalar[i];
    }
    
    // Generator point
    uchar generator[64];
    for (int i = 0; i < 32; i++) {
        generator[i] = SECP256K1_GX[i];
        generator[32 + i] = SECP256K1_GY[i];
    }
    
    // Compute public key = private_key * G
    uchar public_key[64];
    point_multiply(local_scalar, generator, public_key);
    
    // Copy result to output
    for (int i = 0; i < 64; i++) {
        result[i] = public_key[i];
    }
}

// Derive child key from parent using BIP32 specification
void derive_child_key(const uchar parent_key[32], const uchar parent_chain_code[32],
                      uint child_index, uchar child_key[32], uchar child_chain_code[32]) {
    uchar data[37]; // 1 + 32 + 4 bytes
    uchar hmac_result[64];
    
    // Check if hardened derivation
    if (child_index >= 0x80000000) {
        // Hardened derivation: data = 0x00 || parent_key || index
        data[0] = 0x00;
        for (int i = 0; i < 32; i++) {
            data[1 + i] = parent_key[i];
        }
    } else {
        // Non-hardened derivation: data = public_key || index
        // Derive public key from private key
        uchar public_key[64];
        secp256k1_point_multiply(parent_key, public_key);
        
        // Use compressed public key format
        data[0] = (public_key[63] & 1) ? 0x03 : 0x02; // Compressed public key prefix
        for (int i = 0; i < 32; i++) {
            data[1 + i] = public_key[i]; // X coordinate of public key
        }
    }
    
    // Append child index in big-endian
    bytes_to_big_endian_32(child_index, &data[33]);
    
    // HMAC-SHA512(parent_chain_code, data)
    hmac_sha512_bip44(parent_chain_code, 32, data, 37, hmac_result);
    
    // Left 32 bytes become the child private key (added to parent)
    big_num_add_mod(parent_key, hmac_result, SECP256K1_N, child_key);
    
    // Right 32 bytes become the child chain code
    for (int i = 0; i < 32; i++) {
        child_chain_code[i] = hmac_result[32 + i];
    }
}

// BIP44 key derivation kernel
__kernel void bip44_derive_keys(
    __global const uchar* master_seeds,     // Input: 64-byte master seeds from PBKDF2
    __global uchar* private_keys,           // Output: 32-byte private keys
    __global uchar* public_keys,            // Output: 64-byte public keys (uncompressed)
    __global int* success_flags,            // Output: success flags
    __global const uint* derivation_path,   // Input: 5-element derivation path
    const int batch_size
) {
    int gid = get_global_id(0);
    if (gid >= batch_size) return;
    
    // Calculate offsets
    int seed_offset = gid * 64;
    int private_key_offset = gid * 32;
    int public_key_offset = gid * 64;
    
    // Derive master private key and chain code from seed
    uchar master_key[32];
    uchar master_chain_code[32];
    uchar hmac_result[64];
    
    // HMAC-SHA512("Bitcoin seed", master_seed)
    uchar bitcoin_seed[] = "Bitcoin seed";
    uchar local_seed[64];
    for (int i = 0; i < 64; i++) {
        local_seed[i] = master_seeds[seed_offset + i];
    }
    hmac_sha512_bip44(bitcoin_seed, 12, local_seed, 64, hmac_result);
    
    // Split result into master key and chain code
    for (int i = 0; i < 32; i++) {
        master_key[i] = hmac_result[i];
        master_chain_code[i] = hmac_result[32 + i];
    }
    
    // Verify master key is valid
    if (!secp256k1_verify_private_key(master_key)) {
        success_flags[gid] = 0;
        return;
    }
    
    // BIP44 derivation path: m/44'/60'/0'/0/2
    uchar current_key[32], current_chain_code[32];
    uchar next_key[32], next_chain_code[32];
    
    // Initialize with master key
    for (int i = 0; i < 32; i++) {
        current_key[i] = master_key[i];
        current_chain_code[i] = master_chain_code[i];
    }
    
    // Derive using the provided derivation path
    // derivation_path[0] = purpose (44), derivation_path[1] = coin_type (60), etc.
    for (int path_index = 0; path_index < 5; path_index++) {
        uint child_index = derivation_path[path_index];
        // Add hardened bit for first 3 levels (purpose, coin_type, account)
        if (path_index < 3) {
            child_index |= 0x80000000;
        }
        
        derive_child_key(current_key, current_chain_code, child_index, next_key, next_chain_code);
        for (int i = 0; i < 32; i++) {
            current_key[i] = next_key[i];
            current_chain_code[i] = next_chain_code[i];
        }
    }
    
    // Copy final derived key
    for (int i = 0; i < 32; i++) {
        next_key[i] = current_key[i];
    }
    
    // Verify final private key
    if (!secp256k1_verify_private_key(next_key)) {
        success_flags[gid] = 0;
        return;
    }
    
    // Copy private key to output
    for (int i = 0; i < 32; i++) {
        private_keys[private_key_offset + i] = next_key[i];
    }
    
    // Derive public key from private key
    uchar public_key[64];
    secp256k1_point_multiply(next_key, public_key);
    
    // Copy public key to output
    for (int i = 0; i < 64; i++) {
        public_keys[public_key_offset + i] = public_key[i];
    }
    
    success_flags[gid] = 1;
}