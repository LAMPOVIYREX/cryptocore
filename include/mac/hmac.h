#ifndef HMAC_H
#define HMAC_H

#include <stdlib.h>
#include <openssl/evp.h>
#include "../hash.h"

// Renamed from HMAC_CTX to CRYPTOCORE_HMAC_CTX to avoid conflict with OpenSSL
typedef struct {
    unsigned char* key;
    size_t key_len;
    hash_algorithm_t hash_algo;
    unsigned char* ipad;
    unsigned char* opad;
    size_t block_size;
    
    // Contexts for streaming HMAC
    void* sha256_inner_ctx;  // SHA256_CTX for inner hash
    void* sha256_outer_ctx;  // SHA256_CTX for outer hash
    EVP_MD_CTX* sha3_inner_ctx;  // SHA3-256 inner context
    EVP_MD_CTX* sha3_outer_ctx;  // SHA3-256 outer context
} CRYPTOCORE_HMAC_CTX;

CRYPTOCORE_HMAC_CTX* hmac_init(const unsigned char* key, size_t key_len, hash_algorithm_t hash_algo);
void hmac_update(CRYPTOCORE_HMAC_CTX* ctx, const unsigned char* data, size_t data_len);
void hmac_final(CRYPTOCORE_HMAC_CTX* ctx, unsigned char* output);
void hmac_cleanup(CRYPTOCORE_HMAC_CTX* ctx);

char* hmac_compute_hex(const unsigned char* key, size_t key_len, 
                      const unsigned char* data, size_t data_len, 
                      hash_algorithm_t hash_algo);

char* hmac_compute_file_hex(const unsigned char* key, size_t key_len,
                           const char* filename, hash_algorithm_t hash_algo);

int hmac_verify(const unsigned char* key, size_t key_len,
                const unsigned char* data, size_t data_len,
                const unsigned char* expected_hmac, size_t hmac_len,
                hash_algorithm_t hash_algo);

int hmac_verify_file(const unsigned char* key, size_t key_len,
                     const char* filename,
                     const unsigned char* expected_hmac, size_t hmac_len,
                     hash_algorithm_t hash_algo);

#endif