// Keccak256 OpenCL implementation for Ethereum address generation
// Based on the Keccak-f[1600] permutation

#define KECCAK_ROUNDS 24

// Keccak round constants
__constant ulong keccak_round_constants[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

// Rotation offsets for rho step
__constant uint keccak_rho_offsets[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

// Pi step permutation
__constant uint keccak_pi_lane[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

// Rotate left function is handled by macro in sha2.cl

// Keccak-f[1600] permutation
void keccak_f1600(ulong state[25]) {
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta step
        ulong C[5], D[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[y * 5 + x] ^= D[x];
            }
        }
        
        // Rho and Pi steps
        ulong current = state[1];
        for (int t = 0; t < 24; t++) {
            int index = keccak_pi_lane[t];
            ulong temp = state[index];
            state[index] = rotl64(current, keccak_rho_offsets[t]);
            current = temp;
        }
        
        // Chi step
        for (int y = 0; y < 5; y++) {
            ulong temp[5];
            for (int x = 0; x < 5; x++) {
                temp[x] = state[y * 5 + x];
            }
            for (int x = 0; x < 5; x++) {
                state[y * 5 + x] = temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]);
            }
        }
        
        // Iota step
        state[0] ^= keccak_round_constants[round];
    }
}

// Keccak256 hash function
void keccak256(const uchar* input, uint input_len, uchar* output) {
    ulong state[25] = {0};
    
    // Absorption phase
    uint rate = 136; // 1088 bits = 136 bytes for Keccak256
    uint offset = 0;
    
    while (input_len >= rate) {
        for (uint i = 0; i < rate / 8; i++) {
            ulong word = 0;
            for (int j = 0; j < 8; j++) {
                word |= ((ulong)input[offset + i * 8 + j]) << (j * 8);
            }
            state[i] ^= word;
        }
        keccak_f1600(state);
        input_len -= rate;
        offset += rate;
    }
    
    // Padding
    uchar padded[136] = {0};
    for (uint i = 0; i < input_len; i++) {
        padded[i] = input[offset + i];
    }
    padded[input_len] = 0x01; // Keccak padding
    padded[rate - 1] |= 0x80; // Final bit
    
    // Absorb final block
    for (uint i = 0; i < rate / 8; i++) {
        ulong word = 0;
        for (int j = 0; j < 8; j++) {
            word |= ((ulong)padded[i * 8 + j]) << (j * 8);
        }
        state[i] ^= word;
    }
    keccak_f1600(state);
    
    // Squeeze phase - extract 32 bytes (256 bits)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            output[i * 8 + j] = (state[i] >> (j * 8)) & 0xFF;
        }
    }
}

// Generate Ethereum address from public key
void ethereum_address_from_pubkey(const uchar* pubkey_uncompressed, uchar* address) {
    // Input: 65-byte uncompressed public key (0x04 + 32-byte x + 32-byte y)
    // Output: 20-byte Ethereum address
    
    uchar hash[32];
    // Hash the public key coordinates (skip the 0x04 prefix)
    keccak256(pubkey_uncompressed + 1, 64, hash);
    
    // Take the last 20 bytes as the address
    for (int i = 0; i < 20; i++) {
        address[i] = hash[12 + i];
    }
}