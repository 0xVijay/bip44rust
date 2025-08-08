/*
 * secp256k1 OpenCL kernel for elliptic curve operations
 * This kernel implements secp256k1 public key generation from private keys
 */

#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable
#pragma OPENCL EXTENSION cl_khr_int64_extended_atomics : enable

// secp256k1 curve parameters
// Prime field modulus: p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
__constant uint secp256k1_p[8] = {
    0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

// Curve order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
__constant uint secp256k1_n[8] = {
    0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
};

// Generator point G coordinates
// Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
__constant uint secp256k1_gx[8] = {
    0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
    0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
};

// Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
__constant uint secp256k1_gy[8] = {
    0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
    0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
};

// Point structure for elliptic curve operations
typedef struct {
    uint x[8];  // X coordinate (256-bit)
    uint y[8];  // Y coordinate (256-bit)
    uint z[8];  // Z coordinate for Jacobian coordinates (256-bit)
    int infinity; // Point at infinity flag
} ec_point;

// 256-bit integer operations
void copy_256(const uint* src, uint* dst) {
    for (int i = 0; i < 8; i++) {
        dst[i] = src[i];
    }
}

void copy_256_const(const __constant uint* src, uint* dst) {
    for (int i = 0; i < 8; i++) {
        dst[i] = src[i];
    }
}

void zero_256(uint* dst) {
    for (int i = 0; i < 8; i++) {
        dst[i] = 0;
    }
}

void set_one_256(uint* dst) {
    dst[0] = 1;
    for (int i = 1; i < 8; i++) {
        dst[i] = 0;
    }
}

// Compare two 256-bit integers
int cmp_256(const uint* a, const uint* b) {
    for (int i = 7; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

int cmp_256_const(const uint* a, const __constant uint* b) {
    for (int i = 7; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

// Check if 256-bit integer is zero
int is_zero_256(const uint* a) {
    for (int i = 0; i < 8; i++) {
        if (a[i] != 0) return 0;
    }
    return 1;
}

// Add two 256-bit integers (with carry)
void add_256(const uint* a, const uint* b, uint* result) {
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong sum = (ulong)a[i] + (ulong)b[i] + carry;
        result[i] = (uint)sum;
        carry = sum >> 32;
    }
}

// Subtract two 256-bit integers (with borrow)
void sub_256(const uint* a, const uint* b, uint* result) {
    long borrow = 0;
    for (int i = 0; i < 8; i++) {
        long diff = (long)a[i] - (long)b[i] - borrow;
        if (diff < 0) {
            result[i] = (uint)(diff + 0x100000000L);
            borrow = 1;
        } else {
            result[i] = (uint)diff;
            borrow = 0;
        }
    }
}

// Subtract two 256-bit integers (with borrow) - constant version
void sub_256_const(const uint* a, __constant uint* b, uint* result) {
    long borrow = 0;
    for (int i = 0; i < 8; i++) {
        long diff = (long)a[i] - (long)b[i] - borrow;
        if (diff < 0) {
            result[i] = (uint)(diff + 0x100000000L);
            borrow = 1;
        } else {
            result[i] = (uint)diff;
            borrow = 0;
        }
    }
}

// Modular addition: (a + b) mod p
void mod_add(const uint* a, const uint* b, const uint* mod, uint* result) {
    uint temp[8];
    add_256(a, b, temp);
    
    // If temp >= mod, subtract mod
    if (cmp_256(temp, mod) >= 0) {
        sub_256(temp, mod, result);
    } else {
        copy_256(temp, result);
    }
}

// Modular subtraction: (a - b) mod p
void mod_sub(const uint* a, const uint* b, const uint* mod, uint* result) {
    if (cmp_256(a, b) >= 0) {
        sub_256(a, b, result);
    } else {
        uint temp[8];
        sub_256(mod, b, temp);
        add_256(a, temp, result);
        if (cmp_256(result, mod) >= 0) {
            sub_256(result, mod, result);
        }
    }
}

// Modular addition with constant modulus
void mod_add_const(const uint* a, const uint* b, const __constant uint* mod, uint* result) {
    uint temp[8];
    add_256(a, b, temp);
    
    // If temp >= mod, subtract mod
    if (cmp_256_const(temp, mod) >= 0) {
        uint local_mod[8];
        copy_256_const(mod, local_mod);
        sub_256(temp, local_mod, result);
    } else {
        copy_256(temp, result);
    }
}

// Modular subtraction with constant modulus
void mod_sub_const(const uint* a, const uint* b, const __constant uint* mod, uint* result) {
    if (cmp_256(a, b) >= 0) {
        sub_256(a, b, result);
    } else {
        uint temp[8];
        uint local_mod[8];
        copy_256_const(mod, local_mod);
        sub_256(local_mod, b, temp);
        add_256(a, temp, result);
        if (cmp_256_const(result, mod) >= 0) {
            sub_256(result, local_mod, result);
        }
    }
}

// Left shift by one bit
void lshift_256(const uint* a, uint* result) {
    uint carry = 0;
    for (int i = 0; i < 8; i++) {
        uint new_carry = (a[i] >> 31) & 1;
        result[i] = (a[i] << 1) | carry;
        carry = new_carry;
    }
}

// Right shift by one bit
void rshift_256(const uint* a, uint* result) {
    uint carry = 0;
    for (int i = 7; i >= 0; i--) {
        uint new_carry = a[i] & 1;
        result[i] = (a[i] >> 1) | (carry << 31);
        carry = new_carry;
    }
}

// Modular multiplication using Montgomery reduction (simplified)
void mod_mul(const uint* a, const uint* b, const uint* mod, uint* result) {
    uint temp[16] = {0}; // Double precision for intermediate result
    
    // Simple multiplication (not optimized for production)
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong prod = (ulong)a[i] * (ulong)b[j] + (ulong)temp[i + j] + carry;
            temp[i + j] = (uint)prod;
            carry = prod >> 32;
        }
        temp[i + 8] = (uint)carry;
    }
    
    // Reduction modulo p (simplified - not constant time)
    // This is a basic implementation; production code would use Montgomery reduction
    uint quotient[16], remainder[8];
    
    // Copy lower 8 words as initial remainder
    for (int i = 0; i < 8; i++) {
        remainder[i] = temp[i];
    }
    
    // Simple reduction by repeated subtraction (very inefficient)
    for (int bit = 255; bit >= 0; bit--) {
        lshift_256(remainder, remainder);
        if (bit < 8 * 32) {
            uint word_idx = bit / 32;
            uint bit_idx = bit % 32;
            if (word_idx < 8 && (temp[8 + word_idx] & (1U << bit_idx))) {
                remainder[0] |= 1;
            }
        }
        
        if (cmp_256(remainder, mod) >= 0) {
            sub_256(remainder, mod, remainder);
        }
    }
    
    copy_256(remainder, result);
}

// Modular multiplication with constant modulus
void mod_mul_const(const uint* a, const uint* b, const __constant uint* mod, uint* result) {
    uint temp[16] = {0}; // Double precision for intermediate result
    
    // Simple multiplication (not optimized for production)
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong prod = (ulong)a[i] * (ulong)b[j] + (ulong)temp[i + j] + carry;
            temp[i + j] = (uint)prod;
            carry = prod >> 32;
        }
        temp[i + 8] = (uint)carry;
    }
    
    // Reduction modulo p (simplified - not constant time)
    // This is a basic implementation; production code would use Montgomery reduction
    uint quotient[16], remainder[8];
    
    // Copy lower 8 words as initial remainder
    for (int i = 0; i < 8; i++) {
        remainder[i] = temp[i];
    }
    
    // Simple reduction by repeated subtraction (very inefficient)
    for (int bit = 255; bit >= 0; bit--) {
        lshift_256(remainder, remainder);
        if (bit < 8 * 32) {
            uint word_idx = bit / 32;
            uint bit_idx = bit % 32;
            if (word_idx < 8 && (temp[8 + word_idx] & (1U << bit_idx))) {
                remainder[0] |= 1;
            }
        }
        
        if (cmp_256_const(remainder, mod) >= 0) {
            // Need to copy constant to local for sub_256
            uint local_mod[8];
            copy_256_const(mod, local_mod);
            sub_256(remainder, local_mod, remainder);
        }
    }
    
    copy_256(remainder, result);
}

// Modular inverse using extended Euclidean algorithm
void mod_inv(const uint* a, const uint* mod, uint* result) {
    uint u[8], v[8], x1[8], x2[8], temp[8];
    
    copy_256(a, u);
    copy_256(mod, v);
    set_one_256(x1);
    zero_256(x2);
    
    while (!is_zero_256(u) && !is_zero_256(v)) {
        while ((u[0] & 1) == 0) {
            rshift_256(u, u);
            if ((x1[0] & 1) == 0) {
                rshift_256(x1, x1);
            } else {
                add_256(x1, mod, temp);
                rshift_256(temp, x1);
            }
        }
        
        while ((v[0] & 1) == 0) {
            rshift_256(v, v);
            if ((x2[0] & 1) == 0) {
                rshift_256(x2, x2);
            } else {
                add_256(x2, mod, temp);
                rshift_256(temp, x2);
            }
        }
        
        if (cmp_256(u, v) >= 0) {
            sub_256(u, v, u);
            mod_sub(x1, x2, mod, x1);
        } else {
            sub_256(v, u, v);
            mod_sub(x2, x1, mod, x2);
        }
    }
    
    if (is_zero_256(u)) {
        copy_256(x2, result);
    } else {
        copy_256(x1, result);
    }
}

// Modular inverse with constant modulus
void mod_inv_const(const uint* a, const __constant uint* mod, uint* result) {
    uint u[8], v[8], x1[8], x2[8], temp[8];
    uint local_mod[8];
    
    // Copy constant mod to local memory for operations
    copy_256_const(mod, local_mod);
    
    copy_256(a, u);
    copy_256_const(mod, v);
    set_one_256(x1);
    zero_256(x2);
    
    while (!is_zero_256(u) && !is_zero_256(v)) {
        while ((u[0] & 1) == 0) {
            rshift_256(u, u);
            if ((x1[0] & 1) == 0) {
                rshift_256(x1, x1);
            } else {
                add_256(x1, local_mod, temp);
                rshift_256(temp, x1);
            }
        }
        
        while ((v[0] & 1) == 0) {
            rshift_256(v, v);
            if ((x2[0] & 1) == 0) {
                rshift_256(x2, x2);
            } else {
                add_256(x2, local_mod, temp);
                rshift_256(temp, x2);
            }
        }
        
        if (cmp_256(u, v) >= 0) {
            sub_256(u, v, u);
            mod_sub(x1, x2, local_mod, x1);
        } else {
            sub_256(v, u, v);
            mod_sub(x2, x1, local_mod, x2);
        }
    }
    
    if (is_zero_256(u)) {
        copy_256(x2, result);
    } else {
        copy_256(x1, result);
    }
}

// Point doubling in Jacobian coordinates
void point_double(const ec_point* p, ec_point* result) {
    if (p->infinity) {
        result->infinity = 1;
        return;
    }
    
    uint s[8], m[8], t[8], temp[8], temp2[8];
    
    // S = 4 * X * Y^2
    mod_mul_const(p->y, p->y, secp256k1_p, temp);      // Y^2
    mod_mul_const(p->x, temp, secp256k1_p, temp2);     // X * Y^2
    lshift_256(temp2, temp);                      // 2 * X * Y^2
    lshift_256(temp, s);                          // 4 * X * Y^2
    if (cmp_256_const(s, secp256k1_p) >= 0) {
        sub_256_const(s, secp256k1_p, s);
    }
    
    // M = 3 * X^2 + a * Z^4 (for secp256k1, a = 0)
    mod_mul_const(p->x, p->x, secp256k1_p, temp);      // X^2
    lshift_256(temp, temp2);                      // 2 * X^2
    mod_add_const(temp, temp2, secp256k1_p, m);        // 3 * X^2
    
    // T = M^2 - 2 * S
    mod_mul_const(m, m, secp256k1_p, temp);            // M^2
    lshift_256(s, temp2);                         // 2 * S
    mod_sub_const(temp, temp2, secp256k1_p, t);
    
    // X3 = T
    copy_256(t, result->x);
    
    // Y3 = M * (S - T) - 8 * Y^4
    mod_sub_const(s, t, secp256k1_p, temp);             // S - T
    mod_mul_const(m, temp, secp256k1_p, temp2);        // M * (S - T)
    mod_mul_const(p->y, p->y, secp256k1_p, temp);      // Y^2
    mod_mul_const(temp, temp, secp256k1_p, temp);      // Y^4
    lshift_256(temp, temp);                       // 2 * Y^4
    lshift_256(temp, temp);                       // 4 * Y^4
    lshift_256(temp, temp);                       // 8 * Y^4
    if (cmp_256_const(temp, secp256k1_p) >= 0) {
        sub_256_const(temp, secp256k1_p, temp);
    }
    mod_sub_const(temp2, temp, secp256k1_p, result->y);
    
    // Z3 = 2 * Y * Z
    mod_mul_const(p->y, p->z, secp256k1_p, temp);
    lshift_256(temp, result->z);
    if (cmp_256_const(result->z, secp256k1_p) >= 0) {
        sub_256_const(result->z, secp256k1_p, result->z);
    }
    
    result->infinity = 0;
}

// Point addition in Jacobian coordinates
void point_add(const ec_point* p1, const ec_point* p2, ec_point* result) {
    if (p1->infinity) {
        *result = *p2;
        return;
    }
    if (p2->infinity) {
        *result = *p1;
        return;
    }
    
    uint u1[8], u2[8], s1[8], s2[8], h[8], r[8];
    uint temp[8], temp2[8], temp3[8];
    
    // U1 = X1 * Z2^2
    mod_mul_const(p2->z, p2->z, secp256k1_p, temp);
    mod_mul_const(p1->x, temp, secp256k1_p, u1);
    
    // U2 = X2 * Z1^2
    mod_mul_const(p1->z, p1->z, secp256k1_p, temp);
    mod_mul_const(p2->x, temp, secp256k1_p, u2);
    
    // S1 = Y1 * Z2^3
    mod_mul_const(p2->z, p2->z, secp256k1_p, temp);
    mod_mul_const(temp, p2->z, secp256k1_p, temp2);
    mod_mul_const(p1->y, temp2, secp256k1_p, s1);
    
    // S2 = Y2 * Z1^3
    mod_mul_const(p1->z, p1->z, secp256k1_p, temp);
    mod_mul_const(temp, p1->z, secp256k1_p, temp2);
    mod_mul_const(p2->y, temp2, secp256k1_p, s2);
    
    // H = U2 - U1
    mod_sub_const(u2, u1, secp256k1_p, h);
    
    // R = S2 - S1
    mod_sub_const(s2, s1, secp256k1_p, r);
    
    // Check if points are equal
    if (is_zero_256(h)) {
        if (is_zero_256(r)) {
            // Points are equal, use doubling
            point_double(p1, result);
            return;
        } else {
            // Points are inverses, result is point at infinity
            result->infinity = 1;
            return;
        }
    }
    
    // X3 = R^2 - H^3 - 2 * U1 * H^2
    mod_mul_const(r, r, secp256k1_p, temp);            // R^2
    mod_mul_const(h, h, secp256k1_p, temp2);           // H^2
    mod_mul_const(temp2, h, secp256k1_p, temp3);       // H^3
    mod_mul_const(u1, temp2, secp256k1_p, temp2);      // U1 * H^2
    lshift_256(temp2, temp2);                     // 2 * U1 * H^2
    if (cmp_256_const(temp2, secp256k1_p) >= 0) {
        sub_256_const(temp2, secp256k1_p, temp2);
    }
    mod_sub_const(temp, temp3, secp256k1_p, temp);
    mod_sub_const(temp, temp2, secp256k1_p, result->x);
    
    // Y3 = R * (U1 * H^2 - X3) - S1 * H^3
    mod_mul_const(h, h, secp256k1_p, temp2);           // H^2
    mod_mul_const(u1, temp2, secp256k1_p, temp);       // U1 * H^2
    mod_sub_const(temp, result->x, secp256k1_p, temp); // U1 * H^2 - X3
    mod_mul_const(r, temp, secp256k1_p, temp);         // R * (U1 * H^2 - X3)
    mod_mul_const(temp2, h, secp256k1_p, temp2);       // H^3
    mod_mul_const(s1, temp2, secp256k1_p, temp2);      // S1 * H^3
    mod_sub_const(temp, temp2, secp256k1_p, result->y);
    
    // Z3 = Z1 * Z2 * H
    mod_mul_const(p1->z, p2->z, secp256k1_p, temp);
    mod_mul_const(temp, h, secp256k1_p, result->z);
    
    result->infinity = 0;
}

// Scalar multiplication using double-and-add
void point_mul(const uint* scalar, const ec_point* point, ec_point* result) {
    ec_point temp, acc;
    
    // Initialize result as point at infinity
    result->infinity = 1;
    temp = *point;
    
    // Process each bit of the scalar
    for (int i = 0; i < 256; i++) {
        uint word_idx = i / 32;
        uint bit_idx = i % 32;
        
        if (scalar[word_idx] & (1U << bit_idx)) {
            if (result->infinity) {
                *result = temp;
            } else {
                point_add(result, &temp, &acc);
                *result = acc;
            }
        }
        
        if (i < 255) {
            point_double(&temp, &acc);
            temp = acc;
        }
    }
}

// Convert Jacobian coordinates to affine coordinates
void jacobian_to_affine(const ec_point* jac, ec_point* affine) {
    if (jac->infinity) {
        affine->infinity = 1;
        return;
    }
    
    uint z_inv[8], z_inv_squared[8], z_inv_cubed[8];
    
    // Calculate Z^(-1)
    mod_inv_const(jac->z, secp256k1_p, z_inv);
    
    // Calculate Z^(-2)
    mod_mul_const(z_inv, z_inv, secp256k1_p, z_inv_squared);
    
    // Calculate Z^(-3)
    mod_mul_const(z_inv_squared, z_inv, secp256k1_p, z_inv_cubed);
    
    // X = X * Z^(-2)
    mod_mul_const(jac->x, z_inv_squared, secp256k1_p, affine->x);
    
    // Y = Y * Z^(-3)
    mod_mul_const(jac->y, z_inv_cubed, secp256k1_p, affine->y);
    
    // Z = 1 (affine coordinates)
    set_one_256(affine->z);
    affine->infinity = 0;
}

// Convert private key bytes to 256-bit integer (little-endian)
void bytes_to_scalar(const __global uchar* bytes, uint* scalar) {
    for (int i = 0; i < 8; i++) {
        scalar[i] = 0;
        for (int j = 0; j < 4; j++) {
            scalar[i] |= ((uint)bytes[i * 4 + j]) << (j * 8);
        }
    }
}

// Convert 256-bit integer to bytes (little-endian)
void scalar_to_bytes(const uint* scalar, __global uchar* bytes) {
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            bytes[i * 4 + j] = (uchar)(scalar[i] >> (j * 8));
        }
    }
}

// Main kernel for generating public keys from private keys
__kernel void generate_public_keys_kernel(
    __global const uchar* private_keys,  // Input private keys (32 bytes each)
    __global uchar* public_keys,         // Output public keys (65 bytes each, uncompressed)
    __global int* success_flags          // Success flags
) {
    int gid = get_global_id(0);
    
    __global const uchar* priv_key = private_keys + gid * 32;
    __global uchar* pub_key = public_keys + gid * 65;
    
    uint scalar[8];
    ec_point generator, result, affine_result;
    
    // Convert private key to scalar
    bytes_to_scalar(priv_key, scalar);
    
    // Check if private key is valid (0 < key < n)
    if (is_zero_256(scalar) || cmp_256_const(scalar, secp256k1_n) >= 0) {
        success_flags[gid] = 0;
        return;
    }
    
    // Initialize generator point
    copy_256_const(secp256k1_gx, generator.x);
    copy_256_const(secp256k1_gy, generator.y);
    set_one_256(generator.z);
    generator.infinity = 0;
    
    // Perform scalar multiplication: result = scalar * G
    point_mul(scalar, &generator, &result);
    
    // Convert to affine coordinates
    jacobian_to_affine(&result, &affine_result);
    
    if (affine_result.infinity) {
        success_flags[gid] = 0;
        return;
    }
    
    // Format as uncompressed public key (0x04 + X + Y)
    pub_key[0] = 0x04;
    
    // Convert X coordinate to bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            pub_key[1 + (7-i) * 4 + (3-j)] = (uchar)(affine_result.x[i] >> (j * 8));
        }
    }
    
    // Convert Y coordinate to bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            pub_key[33 + (7-i) * 4 + (3-j)] = (uchar)(affine_result.y[i] >> (j * 8));
        }
    }
    
    success_flags[gid] = 1;
}

// Kernel for generating compressed public keys
__kernel void generate_compressed_public_keys_kernel(
    __global const uchar* private_keys,  // Input private keys (32 bytes each)
    __global uchar* public_keys,         // Output public keys (33 bytes each, compressed)
    __global int* success_flags          // Success flags
) {
    int gid = get_global_id(0);
    
    __global const uchar* priv_key = private_keys + gid * 32;
    __global uchar* pub_key = public_keys + gid * 33;
    
    uint scalar[8];
    ec_point generator, result, affine_result;
    
    // Convert private key to scalar
    bytes_to_scalar(priv_key, scalar);
    
    // Check if private key is valid
    if (is_zero_256(scalar) || cmp_256_const(scalar, secp256k1_n) >= 0) {
        success_flags[gid] = 0;
        return;
    }
    
    // Initialize generator point
    copy_256_const(secp256k1_gx, generator.x);
    copy_256_const(secp256k1_gy, generator.y);
    set_one_256(generator.z);
    generator.infinity = 0;
    
    // Perform scalar multiplication
    point_mul(scalar, &generator, &result);
    
    // Convert to affine coordinates
    jacobian_to_affine(&result, &affine_result);
    
    if (affine_result.infinity) {
        success_flags[gid] = 0;
        return;
    }
    
    // Format as compressed public key
    // 0x02 if Y is even, 0x03 if Y is odd
    pub_key[0] = (affine_result.y[0] & 1) ? 0x03 : 0x02;
    
    // Convert X coordinate to bytes (big-endian)
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            pub_key[1 + (7-i) * 4 + (3-j)] = (uchar)(affine_result.x[i] >> (j * 8));
        }
    }
    
    success_flags[gid] = 1;
}