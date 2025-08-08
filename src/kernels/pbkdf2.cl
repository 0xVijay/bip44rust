// PBKDF2-HMAC-SHA512 kernel for BIP39 seed derivation
// This kernel implements the PBKDF2 key derivation function
// using HMAC-SHA512 as the pseudorandom function
// Optimized for 2048 iterations as per BIP39 specification

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128
#define PBKDF2_ITERATIONS 2048
#define BIP39_SEED_SIZE 64

// SHA-512 constants
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

// Convert bytes to 64-bit big-endian
ulong bytes_to_u64_be(__global const uchar* bytes, int offset) {
    return ((ulong)bytes[offset] << 56) |
           ((ulong)bytes[offset + 1] << 48) |
           ((ulong)bytes[offset + 2] << 40) |
           ((ulong)bytes[offset + 3] << 32) |
           ((ulong)bytes[offset + 4] << 24) |
           ((ulong)bytes[offset + 5] << 16) |
           ((ulong)bytes[offset + 6] << 8) |
           ((ulong)bytes[offset + 7]);
}

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

// HMAC-SHA512 function
void hmac_sha512(__private const uchar* key, int key_len,
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

// PBKDF2-HMAC-SHA512 implementation
__kernel void pbkdf2_hmac_sha512(
    __global const uchar* passwords,    // Input: mnemonic phrases (UTF-8)
    __global const int* password_lengths, // Length of each password
    __global const uchar* salt,         // Salt: "mnemonic" + passphrase
    __global const int* salt_lengths,   // Length of salt for each item
    __global uchar* output,             // Output: 64-byte seeds
    const int batch_size
) {
    int gid = get_global_id(0);
    if (gid >= batch_size) return;
    
    // Calculate offsets
    int password_offset = gid * 256; // Assume max 256 bytes per password
    int salt_offset = gid * 128;     // Assume max 128 bytes per salt
    int output_offset = gid * 64;
    
    int pwd_len = password_lengths[gid];
    int salt_len = salt_lengths[gid];
    
    // PBKDF2 variables
    uchar U[64], T[64];
    uchar salt_with_counter[132]; // salt + 4-byte counter
    uchar local_password[256]; // Local copy of password
    
    // Copy password to local memory
    for (int i = 0; i < pwd_len && i < 256; i++) {
        local_password[i] = passwords[password_offset + i];
    }
    
    // Initialize output
    for (int i = 0; i < 64; i++) {
        output[output_offset + i] = 0;
    }
    
    // PBKDF2 produces exactly 64 bytes (1 block for SHA-512)
    // Prepare salt with counter (big-endian 1)
    for (int i = 0; i < salt_len; i++) {
        salt_with_counter[i] = salt[salt_offset + i];
    }
    salt_with_counter[salt_len] = 0;
    salt_with_counter[salt_len + 1] = 0;
    salt_with_counter[salt_len + 2] = 0;
    salt_with_counter[salt_len + 3] = 1;
    
    // Initialize T = 0
    for (int i = 0; i < 64; i++) {
        T[i] = 0;
    }
    
    // Perform PBKDF2_ITERATIONS iterations
    for (int iter = 0; iter < PBKDF2_ITERATIONS; iter++) {
        if (iter == 0) {
            // U1 = HMAC(password, salt || counter)
            hmac_sha512(local_password, pwd_len,
                       salt_with_counter, salt_len + 4, U);
        } else {
            // Ui = HMAC(password, Ui-1)
            hmac_sha512(local_password, pwd_len, U, 64, U);
        }
        
        // T = T XOR U
        for (int i = 0; i < 64; i++) {
            T[i] ^= U[i];
        }
    }
    
    // Copy result to output
    for (int i = 0; i < 64; i++) {
        output[output_offset + i] = T[i];
    }
}