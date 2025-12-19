#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "../include/kdf.h"
#include "../include/csprng.h"
#include "../include/mac/hmac.h"
#include "../include/hash.h"

#define PBKDF2_MAX_ITERATIONS 1000000
#define PBKDF2_DEFAULT_ITERATIONS 100000
#define PBKDF2_MIN_ITERATIONS 1000

// Используем OpenSSL для PBKDF2 (гарантирует совместимость с RFC 6070)
int pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len,
                      const unsigned char* salt, size_t salt_len,
                      unsigned int iterations,
                      unsigned char* derived_key, size_t dklen) {
    
    if (iterations < PBKDF2_MIN_ITERATIONS) {
        fprintf(stderr, "Warning: Iteration count (%u) is below minimum recommended (%d)\n",
                iterations, PBKDF2_MIN_ITERATIONS);
    }
    
    if (iterations > PBKDF2_MAX_ITERATIONS) {
        fprintf(stderr, "Error: Iteration count (%u) exceeds maximum (%d)\n",
                iterations, PBKDF2_MAX_ITERATIONS);
        return 0;
    }
    
    // Используем OpenSSL PKCS5_PBKDF2_HMAC для совместимости с RFC 6070
    int result = PKCS5_PBKDF2_HMAC((const char*)password, password_len,
                                  salt, salt_len,
                                  iterations,
                                  EVP_sha256(),
                                  dklen, derived_key);
    
    if (!result) {
        fprintf(stderr, "Error: PBKDF2 computation failed\n");
        return 0;
    }
    
    return 1;
}

// High-level PBKDF2 function with hex output
char* pbkdf2_derive_hex(const char* password, const char* salt_hex,
                        unsigned int iterations, size_t key_len) {
    
    if (!password || !salt_hex) {
        fprintf(stderr, "Error: Password and salt cannot be NULL\n");
        return NULL;
    }
    
    size_t salt_len = strlen(salt_hex) / 2;
    if (strlen(salt_hex) % 2 != 0) {
        fprintf(stderr, "Error: Salt hex string must have even length\n");
        return NULL;
    }
    
    unsigned char* salt = malloc(salt_len);
    if (!salt) {
        fprintf(stderr, "Error: Memory allocation failed for salt\n");
        return NULL;
    }
    
    // Convert hex salt to binary
    for (size_t i = 0; i < salt_len; i++) {
        if (sscanf(salt_hex + i * 2, "%2hhx", &salt[i]) != 1) {
            fprintf(stderr, "Error: Invalid hex character in salt\n");
            free(salt);
            return NULL;
        }
    }
    
    unsigned char* derived_key = malloc(key_len);
    if (!derived_key) {
        fprintf(stderr, "Error: Memory allocation failed for derived key\n");
        free(salt);
        return NULL;
    }
    
    // Measure performance
    clock_t start = clock();
    
    int result = pbkdf2_hmac_sha256((const unsigned char*)password, strlen(password),
                                   salt, salt_len,
                                   iterations,
                                   derived_key, key_len);
    
    clock_t end = clock();
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    if (!result) {
        free(salt);
        free(derived_key);
        return NULL;
    }
    
    // Show performance warning for low iteration counts
    if (iterations < 100000 && time_taken < 0.1) {
        fprintf(stderr, "⚠️  Warning: Low iteration count. Consider at least 100,000 iterations for security.\n");
        fprintf(stderr, "   Derivation time: %.3f seconds\n", time_taken);
    }
    
    // Convert to hex
    char* hex_result = malloc(key_len * 2 + 1);
    if (!hex_result) {
        fprintf(stderr, "Error: Memory allocation failed for hex result\n");
        free(salt);
        free(derived_key);
        return NULL;
    }
    
    for (size_t i = 0; i < key_len; i++) {
        sprintf(hex_result + i * 2, "%02x", derived_key[i]);
    }
    hex_result[key_len * 2] = '\0';
    
    // Cleanup sensitive data
    memset(derived_key, 0, key_len);
    memset(salt, 0, salt_len);
    free(salt);
    free(derived_key);
    
    return hex_result;
}

// Hierarchical key derivation (simplified HKDF)
int derive_key_from_master(const unsigned char* master_key, size_t master_key_len,
                          const char* context, size_t context_len,
                          unsigned char* derived_key, size_t derived_key_len) {
    
    if (!master_key || !context || !derived_key) {
        fprintf(stderr, "Error: Invalid parameters for key derivation\n");
        return 0;
    }
    
    // Simple HKDF-expand: HMAC(master_key, context || counter)
    size_t hash_len = 32; // SHA-256 output size
    size_t n = (derived_key_len + hash_len - 1) / hash_len;
    
    unsigned char counter = 1;
    size_t offset = 0;
    
    for (size_t i = 0; i < n; i++) {
        size_t data_len = context_len + 1;
        unsigned char* data = malloc(data_len);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return 0;
        }
        
        memcpy(data, context, context_len);
        data[context_len] = counter;
        
        char* hmac_hex = hmac_compute_hex(master_key, master_key_len,
                                         data, data_len,
                                         HASH_SHA256);
        free(data);
        
        if (!hmac_hex) {
            fprintf(stderr, "Error: HMAC computation failed\n");
            return 0;
        }
        
        size_t copy_len = (derived_key_len - offset) > hash_len ? 
                         hash_len : (derived_key_len - offset);
        
        for (size_t j = 0; j < copy_len; j++) {
            sscanf(hmac_hex + j * 2, "%2hhx", &derived_key[offset + j]);
        }
        
        free(hmac_hex);
        offset += copy_len;
        counter++;
    }
    
    return 1;
}

// Generate random salt
unsigned char* generate_random_salt(size_t salt_len) {
    if (salt_len == 0) {
        fprintf(stderr, "Error: Salt length must be greater than 0\n");
        return NULL;
    }
    
    unsigned char* salt = malloc(salt_len);
    if (!salt) {
        fprintf(stderr, "Error: Memory allocation failed for salt\n");
        return NULL;
    }
    
    if (generate_random_bytes(salt, salt_len) != 0) {
        fprintf(stderr, "Error: Failed to generate random salt\n");
        free(salt);
        return NULL;
    }
    
    return salt;
}

char* generate_random_salt_hex(size_t salt_len) {
    unsigned char* salt = generate_random_salt(salt_len);
    if (!salt) {
        return NULL;
    }
    
    char* hex_salt = malloc(salt_len * 2 + 1);
    if (!hex_salt) {
        fprintf(stderr, "Error: Memory allocation failed for hex salt\n");
        free(salt);
        return NULL;
    }
    
    for (size_t i = 0; i < salt_len; i++) {
        sprintf(hex_salt + i * 2, "%02x", salt[i]);
    }
    hex_salt[salt_len * 2] = '\0';
    
    // Cleanup sensitive data
    memset(salt, 0, salt_len);
    free(salt);
    
    return hex_salt;
}