// OpenCL kernel for word indices to seed conversion and Ethereum address derivation

#include "mnemonic_constants.cl"
#include "sha2.cl"
#include "keccak256.cl"
#include "secp256k1.cl"

// HMAC-SHA512 implementation for PBKDF2 and BIP44
static void hmac_sha512(const unsigned char* key, int key_len, 
                       const unsigned char* data, int data_len, 
                       unsigned char* output) {
    unsigned char ipad[128], opad[128];
    unsigned char key_pad[64];
    
    // Prepare key
    if (key_len > 64) {
        sha512((unsigned long*)key, key_len, (unsigned long*)key_pad);
        key_len = 64;
    } else {
        for (int i = 0; i < key_len; i++) {
            key_pad[i] = key[i];
        }
        for (int i = key_len; i < 64; i++) {
            key_pad[i] = 0;
        }
    }
    
    // Create ipad and opad
    for (int i = 0; i < 64; i++) {
        ipad[i] = key_pad[i] ^ 0x36;
        opad[i] = key_pad[i] ^ 0x5c;
    }
    
    // Inner hash: SHA512(ipad || data)
    unsigned char inner_input[192]; // 64 + 128 max
    for (int i = 0; i < 64; i++) {
        inner_input[i] = ipad[i];
    }
    for (int i = 0; i < data_len && i < 128; i++) {
        inner_input[64 + i] = data[i];
    }
    
    unsigned char inner_hash[64];
    sha512((unsigned long*)inner_input, 64 + data_len, (unsigned long*)inner_hash);
    
    // Outer hash: SHA512(opad || inner_hash)
    unsigned char outer_input[128]; // 64 + 64
    for (int i = 0; i < 64; i++) {
        outer_input[i] = opad[i];
        outer_input[64 + i] = inner_hash[i];
    }
    
    sha512((unsigned long*)outer_input, 128, (unsigned long*)output);
}

// BIP44 key derivation functions
static void derive_hardened_child(unsigned char* private_key, unsigned char* chain_code, unsigned int index) {
    unsigned char data[37];
    data[0] = 0x00; // padding for private key
    for (int i = 0; i < 32; i++) {
        data[1 + i] = private_key[i];
    }
    
    // Add hardened index (0x80000000 + index)
    unsigned int hardened_index = 0x80000000 + index;
    data[33] = (hardened_index >> 24) & 0xFF;
    data[34] = (hardened_index >> 16) & 0xFF;
    data[35] = (hardened_index >> 8) & 0xFF;
    data[36] = hardened_index & 0xFF;
    
    unsigned char result[64];
    hmac_sha512(chain_code, 32, data, 37, result);
    
    // Add to private key (mod secp256k1 order)
    secp256k1_scalar key_scalar, tweak_scalar;
    int overflow;
    secp256k1_scalar_set_b32(&key_scalar, private_key, &overflow);
    secp256k1_scalar_set_b32(&tweak_scalar, result, &overflow);
    secp256k1_scalar_add(&key_scalar, &key_scalar, &tweak_scalar);
    secp256k1_scalar_get_b32(private_key, &key_scalar);
    
    // Update chain code
    for (int i = 0; i < 32; i++) {
        chain_code[i] = result[32 + i];
    }
}

static void derive_child(unsigned char* private_key, unsigned char* chain_code, unsigned int index) {
    // Generate public key for non-hardened derivation
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(&pubkey, private_key);
    
    unsigned char pubkey_serialized[33];
    size_t pubkey_len = 33;
    secp256k1_ec_pubkey_serialize(pubkey_serialized, pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);
    
    unsigned char data[37];
    for (int i = 0; i < 33; i++) {
        data[i] = pubkey_serialized[i];
    }
    
    // Add index
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;
    
    unsigned char result[64];
    hmac_sha512(chain_code, 32, data, 37, result);
    
    // Add to private key (mod secp256k1 order)
    secp256k1_scalar key_scalar, tweak_scalar;
    int overflow;
    secp256k1_scalar_set_b32(&key_scalar, private_key, &overflow);
    secp256k1_scalar_set_b32(&tweak_scalar, result, &overflow);
    secp256k1_scalar_add(&key_scalar, &key_scalar, &tweak_scalar);
    secp256k1_scalar_get_b32(private_key, &key_scalar);
    
    // Update chain code
    for (int i = 0; i < 32; i++) {
        chain_code[i] = result[32 + i];
    }
}

// Helper function to get BIP39 word by index
__constant const uchar* get_bip39_word(ushort index) {
    // Bounds check - BIP39 has 2048 words (indices 0-2047)
    if (index >= 2048) {
        return (const uchar*)"invalid";
    }
    // Return the actual BIP39 word from the constant memory word list
    return (const uchar*)words[index];
}

__kernel void word_indices_seed(
    __global const ushort* word_indices,
    __global uint* results,
    const uint batch_size,
    __global const uchar* target_address
) {
    uint idx = get_global_id(0);
    if (idx >= batch_size) return;
    
    // Get word indices for this thread (12 words)
    ushort indices[12];
    for (int i = 0; i < 12; i++) {
        indices[i] = word_indices[idx * 12 + i];
    }
    
    // Build mnemonic string from word indices
    uchar mnemonic[256]; // Sufficient space for 12 words
    uint mnemonic_index = 0;
    
    for (int word_idx = 0; word_idx < 12; word_idx++) {
        ushort word_index = indices[word_idx];
        
        // Get word from BIP39 word list (using word index)
        // This is a simplified approach - in practice, you'd have the full word list
        // For now, we'll use a placeholder approach
        __constant const uchar* word = get_bip39_word(word_index);
        
        // Copy word to mnemonic
        int word_len = 0;
        while (word[word_len] != 0 && word_len < 20) { // Max word length
            mnemonic[mnemonic_index++] = word[word_len++];
        }
        
        // Add space between words (except last word)
        if (word_idx < 11) {
            mnemonic[mnemonic_index++] = ' ';
        }
    }
    mnemonic[mnemonic_index] = 0; // null terminator
    
    // PBKDF2-HMAC-SHA512 for seed derivation
    uchar ipad_key[128];
    uchar opad_key[128];
    uchar salt[] = "mnemonic"; // BIP39 uses "mnemonic" + optional passphrase
    
    // Prepare HMAC keys
    for (int i = 0; i < 64; i++) {
        uchar key_byte = (i < mnemonic_index) ? mnemonic[i] : 0;
        ipad_key[i] = key_byte ^ 0x36;
        opad_key[i] = key_byte ^ 0x5c;
    }
    
    // PBKDF2 with 2048 iterations
    uchar seed[64];
    uchar u[64], temp[128];
    
    // Initial HMAC-SHA512(password, salt || 0x00000001)
    for (int i = 0; i < 8; i++) {
        temp[i] = salt[i];
    }
    temp[8] = 0x00; temp[9] = 0x00; temp[10] = 0x00; temp[11] = 0x01;
    
    // Concatenate ipad_key with salt+counter
    for (int i = 0; i < 64; i++) {
        temp[64 + i] = ipad_key[i];
    }
    for (int i = 0; i < 12; i++) {
        temp[76 + i] = temp[i]; // salt + counter
    }
    
    // First iteration
    sha512((ulong*)temp, 76, (ulong*)u);
    
    // Copy u to seed
    for (int i = 0; i < 64; i++) {
        seed[i] = u[i];
    }
    
    // Remaining 2047 iterations
    for (int iter = 1; iter < 2048; iter++) {
        // HMAC-SHA512(password, u)
        for (int i = 0; i < 64; i++) {
            temp[64 + i] = ipad_key[i];
            temp[128 + i] = u[i];
        }
        sha512((ulong*)(temp + 64), 128, (ulong*)u);
        
        // XOR with seed
        for (int i = 0; i < 64; i++) {
            seed[i] ^= u[i];
        }
    }
    
    // BIP44 key derivation: m/44'/60'/0'/0/2
    // Step 1: Generate master private key from seed
    unsigned char master_key[64];
    unsigned char chain_code[32];
    
    // HMAC-SHA512("Bitcoin seed", seed) -> master_key + chain_code
    unsigned char bitcoin_seed[] = "Bitcoin seed";
    hmac_sha512(bitcoin_seed, 12, seed, 64, master_key);
    
    // Split result: first 32 bytes = master private key, last 32 bytes = chain code
    for (int i = 0; i < 32; i++) {
        chain_code[i] = master_key[32 + i];
    }
    
    // Step 2: Derive child keys following BIP44 path m/44'/60'/0'/0/2
    unsigned char private_key[32];
    for (int i = 0; i < 32; i++) {
        private_key[i] = master_key[i];
    }
    
    // Derive m/44' (hardened)
    derive_hardened_child(private_key, chain_code, 44);
    
    // Derive m/44'/60' (hardened)
    derive_hardened_child(private_key, chain_code, 60);
    
    // Derive m/44'/60'/0' (hardened)
    derive_hardened_child(private_key, chain_code, 0);
    
    // Derive m/44'/60'/0'/0 (non-hardened)
    derive_child(private_key, chain_code, 0);
    
    // Derive m/44'/60'/0'/0/2 (non-hardened)
    derive_child(private_key, chain_code, 2);
    
    // Step 3: Generate public key from private key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(&pubkey, private_key)) {
        results[idx] = 0;
        return;
    }
    
    // Step 4: Serialize public key (uncompressed)
    unsigned char pubkey_serialized[65];
    size_t pubkey_len = 65;
    if (!secp256k1_ec_pubkey_serialize(pubkey_serialized, pubkey_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        results[idx] = 0;
        return;
    }
    
    // Step 5: Generate Ethereum address using Keccak-256
    unsigned char eth_address[20];
    keccak256(pubkey_serialized + 1, 64, eth_address); // Skip first byte (0x04)
    
    // Step 6: Compare with target address
    int match = 1;
    for (int i = 0; i < 20; i++) {
        if (eth_address[i] != target_address[i]) {
            match = 0;
            break;
        }
    }
    
    results[idx] = match;
}