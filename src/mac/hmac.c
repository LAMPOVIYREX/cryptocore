#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "../../include/mac/hmac.h"
#include "../../include/hash/sha256.h"
#include "../../include/hash/sha3_256.h"

static size_t get_hash_block_size(hash_algorithm_t algo) {
    switch(algo) {
        case HASH_SHA256:
        case HASH_SHA3_256:
            return 64; // SHA-256 and SHA3-256 block size
        default:
            return 64;
    }
}

static size_t get_hash_output_size(hash_algorithm_t algo) {
    switch(algo) {
        case HASH_SHA256:
        case HASH_SHA3_256:
            return 32; // 256 bits = 32 bytes
        default:
            return 32;
    }
}

// Helper function to compute hash directly
static void compute_hash_direct(hash_algorithm_t algo, 
                               const unsigned char* data, size_t len,
                               unsigned char* output) {
    switch(algo) {
        case HASH_SHA256: {
            sha256(data, len, output);
            break;
        }
        case HASH_SHA3_256: {
            EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
            const EVP_MD* md = EVP_sha3_256();
            unsigned int out_len;
            
            EVP_DigestInit_ex(mdctx, md, NULL);
            EVP_DigestUpdate(mdctx, data, len);
            EVP_DigestFinal_ex(mdctx, output, &out_len);
            EVP_MD_CTX_free(mdctx);
            break;
        }
        default:
            memset(output, 0, get_hash_output_size(algo));
    }
}

CRYPTOCORE_HMAC_CTX* hmac_init(const unsigned char* key, size_t key_len, hash_algorithm_t hash_algo) {
    CRYPTOCORE_HMAC_CTX* ctx = malloc(sizeof(CRYPTOCORE_HMAC_CTX));
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(CRYPTOCORE_HMAC_CTX));
    ctx->hash_algo = hash_algo;
    ctx->block_size = get_hash_block_size(hash_algo);
    
    // Process key according to RFC 2104
    unsigned char* processed_key = malloc(ctx->block_size);
    if (!processed_key) {
        free(ctx);
        return NULL;
    }
    
    memset(processed_key, 0, ctx->block_size);
    
    if (key_len > ctx->block_size) {
        // Hash key if it's longer than block size
        ctx->key_len = get_hash_output_size(hash_algo);
        unsigned char hashed_key[ctx->key_len];
        compute_hash_direct(hash_algo, key, key_len, hashed_key);
        // Копируем весь хеш в processed_key
        memcpy(processed_key, hashed_key, ctx->key_len);
        // Очищаем временный буфер
        memset(hashed_key, 0, ctx->key_len);
    } else {
        // Copy key as-is if shorter or equal to block size
        ctx->key_len = key_len;
        memcpy(processed_key, key, key_len);
        // Note: RFC 2104 says to pad with zeros, which memset already did
    }
    
    // Store the processed key
    ctx->key = malloc(ctx->block_size);
    if (!ctx->key) {
        free(processed_key);
        free(ctx);
        return NULL;
    }
    memcpy(ctx->key, processed_key, ctx->block_size);
    
    // Create ipad and opad
    ctx->ipad = malloc(ctx->block_size);
    ctx->opad = malloc(ctx->block_size);
    if (!ctx->ipad || !ctx->opad) {
        if (ctx->ipad) free(ctx->ipad);
        if (ctx->opad) free(ctx->opad);
        free(ctx->key);
        free(processed_key);
        free(ctx);
        return NULL;
    }
    
    // XOR with ipad (0x36) and opad (0x5c)
    for (size_t i = 0; i < ctx->block_size; i++) {
        ctx->ipad[i] = processed_key[i] ^ 0x36;
        ctx->opad[i] = processed_key[i] ^ 0x5c;
    }
    
    free(processed_key);
    
    // Initialize hash contexts for streaming
    if (hash_algo == HASH_SHA256) {
        ctx->sha256_inner_ctx = malloc(sizeof(CRYPTOCORE_SHA256_CTX));
        if (ctx->sha256_inner_ctx) {
            sha256_init((CRYPTOCORE_SHA256_CTX*)ctx->sha256_inner_ctx);
            sha256_update((CRYPTOCORE_SHA256_CTX*)ctx->sha256_inner_ctx, ctx->ipad, ctx->block_size);
        }
        
        ctx->sha256_outer_ctx = malloc(sizeof(CRYPTOCORE_SHA256_CTX));
        if (ctx->sha256_outer_ctx) {
            sha256_init((CRYPTOCORE_SHA256_CTX*)ctx->sha256_outer_ctx);
            // opad will be added in hmac_final
        }
    } else if (hash_algo == HASH_SHA3_256) {
        ctx->sha3_inner_ctx = EVP_MD_CTX_new();
        ctx->sha3_outer_ctx = EVP_MD_CTX_new();
        
        if (ctx->sha3_inner_ctx && ctx->sha3_outer_ctx) {
            const EVP_MD* md = EVP_sha3_256();
            EVP_DigestInit_ex(ctx->sha3_inner_ctx, md, NULL);
            EVP_DigestUpdate(ctx->sha3_inner_ctx, ctx->ipad, ctx->block_size);
            
            EVP_DigestInit_ex(ctx->sha3_outer_ctx, md, NULL);
            // opad will be added in hmac_final
        }
    }
    
    return ctx;
}

void hmac_update(CRYPTOCORE_HMAC_CTX* ctx, const unsigned char* data, size_t data_len) {
    if (!ctx || !data || data_len == 0) return;
    
    if (ctx->hash_algo == HASH_SHA256 && ctx->sha256_inner_ctx) {
        sha256_update((CRYPTOCORE_SHA256_CTX*)ctx->sha256_inner_ctx, data, data_len);
    } else if (ctx->hash_algo == HASH_SHA3_256 && ctx->sha3_inner_ctx) {
        EVP_DigestUpdate(ctx->sha3_inner_ctx, data, data_len);
    }
}

void hmac_final(CRYPTOCORE_HMAC_CTX* ctx, unsigned char* output) {
    if (!ctx || !output) return;
    
    size_t hash_size = get_hash_output_size(ctx->hash_algo);
    unsigned char inner_hash[hash_size];
    
    // Complete inner hash
    if (ctx->hash_algo == HASH_SHA256 && ctx->sha256_inner_ctx) {
        sha256_final((CRYPTOCORE_SHA256_CTX*)ctx->sha256_inner_ctx, inner_hash);
        
        // Start outer hash with opad
        sha256_update((CRYPTOCORE_SHA256_CTX*)ctx->sha256_outer_ctx, ctx->opad, ctx->block_size);
        sha256_update((CRYPTOCORE_SHA256_CTX*)ctx->sha256_outer_ctx, inner_hash, hash_size);
        sha256_final((CRYPTOCORE_SHA256_CTX*)ctx->sha256_outer_ctx, output);
    } else if (ctx->hash_algo == HASH_SHA3_256 && ctx->sha3_inner_ctx) {
        unsigned int hash_len;
        EVP_DigestFinal_ex(ctx->sha3_inner_ctx, inner_hash, &hash_len);
        
        // Start outer hash with opad
        EVP_DigestUpdate(ctx->sha3_outer_ctx, ctx->opad, ctx->block_size);
        EVP_DigestUpdate(ctx->sha3_outer_ctx, inner_hash, hash_len);
        EVP_DigestFinal_ex(ctx->sha3_outer_ctx, output, &hash_len);
    }
    
    // Clean inner hash from memory
    memset(inner_hash, 0, hash_size);
}

void hmac_cleanup(CRYPTOCORE_HMAC_CTX* ctx) {
    if (ctx) {
        if (ctx->key) {
            memset(ctx->key, 0, ctx->block_size);
            free(ctx->key);
        }
        if (ctx->ipad) {
            memset(ctx->ipad, 0, ctx->block_size);
            free(ctx->ipad);
        }
        if (ctx->opad) {
            memset(ctx->opad, 0, ctx->block_size);
            free(ctx->opad);
        }
        if (ctx->sha256_inner_ctx) {
            free(ctx->sha256_inner_ctx);
        }
        if (ctx->sha256_outer_ctx) {
            free(ctx->sha256_outer_ctx);
        }
        if (ctx->sha3_inner_ctx) {
            EVP_MD_CTX_free(ctx->sha3_inner_ctx);
        }
        if (ctx->sha3_outer_ctx) {
            EVP_MD_CTX_free(ctx->sha3_outer_ctx);
        }
        free(ctx);
    }
}

// Simplified HMAC computation
char* hmac_compute_hex(const unsigned char* key, size_t key_len, 
                      const unsigned char* data, size_t data_len, 
                      hash_algorithm_t hash_algo) {
    
    CRYPTOCORE_HMAC_CTX* ctx = hmac_init(key, key_len, hash_algo);
    if (!ctx) return NULL;
    
    size_t hash_size = get_hash_output_size(hash_algo);
    unsigned char hmac[hash_size];
    
    // Use streaming update for large data
    hmac_update(ctx, data, data_len);
    hmac_final(ctx, hmac);
    
    // Convert to hex
    char* hex_str = malloc(hash_size * 2 + 1);
    if (!hex_str) {
        hmac_cleanup(ctx);
        return NULL;
    }
    
    for (size_t i = 0; i < hash_size; i++) {
        sprintf(hex_str + i * 2, "%02x", hmac[i]);
    }
    hex_str[hash_size * 2] = '\0';
    
    hmac_cleanup(ctx);
    return hex_str;
}

char* hmac_compute_file_hex(const unsigned char* key, size_t key_len,
                           const char* filename, hash_algorithm_t hash_algo) {
    
    FILE* file = fopen(filename, "rb");
    if (!file) return NULL;
    
    CRYPTOCORE_HMAC_CTX* ctx = hmac_init(key, key_len, hash_algo);
    if (!ctx) {
        fclose(file);
        return NULL;
    }
    
    // Process file in chunks
    unsigned char buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        hmac_update(ctx, buffer, bytes_read);
    }
    
    size_t hash_size = get_hash_output_size(hash_algo);
    unsigned char hmac[hash_size];
    hmac_final(ctx, hmac);
    
    hmac_cleanup(ctx);
    fclose(file);
    
    // Convert to hex
    char* hex_str = malloc(hash_size * 2 + 1);
    if (!hex_str) return NULL;
    
    for (size_t i = 0; i < hash_size; i++) {
        sprintf(hex_str + i * 2, "%02x", hmac[i]);
    }
    hex_str[hash_size * 2] = '\0';
    
    return hex_str;
}

int hmac_verify(const unsigned char* key, size_t key_len,
                const unsigned char* data, size_t data_len,
                const unsigned char* expected_hmac, size_t hmac_len,
                hash_algorithm_t hash_algo) {
    
    char* computed_hex = hmac_compute_hex(key, key_len, data, data_len, hash_algo);
    if (!computed_hex) return 0;
    
    // Convert expected to hex for comparison
    char expected_hex[hmac_len * 2 + 1];
    for (size_t i = 0; i < hmac_len && i * 2 < sizeof(expected_hex) - 1; i++) {
        sprintf(expected_hex + i * 2, "%02x", expected_hmac[i]);
    }
    expected_hex[hmac_len * 2] = '\0';
    
    // Constant-time comparison to prevent timing attacks
    int result = 1;
    for (size_t i = 0; i < hmac_len * 2; i++) {
        result &= (computed_hex[i] == expected_hex[i]);
    }
    
    free(computed_hex);
    return result;
}

int hmac_verify_file(const unsigned char* key, size_t key_len,
                     const char* filename,
                     const unsigned char* expected_hmac, size_t hmac_len,
                     hash_algorithm_t hash_algo) {
    
    char* computed_hex = hmac_compute_file_hex(key, key_len, filename, hash_algo);
    if (!computed_hex) return 0;
    
    char expected_hex[hmac_len * 2 + 1];
    for (size_t i = 0; i < hmac_len && i * 2 < sizeof(expected_hex) - 1; i++) {
        sprintf(expected_hex + i * 2, "%02x", expected_hmac[i]);
    }
    expected_hex[hmac_len * 2] = '\0';
    
    // Constant-time comparison
    int result = 1;
    for (size_t i = 0; i < hmac_len * 2; i++) {
        result &= (computed_hex[i] == expected_hex[i]);
    }
    
    free(computed_hex);
    return result;
}