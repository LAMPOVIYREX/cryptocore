#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "../include/hash.h"
#include "../include/hash/sha256.h"
#include "../include/hash/sha3_256.h"

hash_algorithm_t parse_hash_algorithm(const char *algorithm_str) {
    if (strcmp(algorithm_str, "sha256") == 0) return HASH_SHA256;
    if (strcmp(algorithm_str, "sha3-256") == 0) return HASH_SHA3_256;
    if (strcmp(algorithm_str, "sha3_256") == 0) return HASH_SHA3_256;
    return HASH_UNKNOWN;
}

char* compute_hash(hash_algorithm_t algorithm, const char *filename) {
    switch (algorithm) {
        case HASH_SHA256:
            return sha256_file(filename);
        case HASH_SHA3_256:
            return sha3_256_file(filename);
        default:
            return NULL;
    }
}

// Новая функция для вычисления хеша из stdin
char* compute_hash_from_stdin(hash_algorithm_t algorithm) {
    if (algorithm == HASH_SHA256) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        
        unsigned char buffer[4096];
        size_t bytes_read;
        
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            sha256_update(&ctx, buffer, bytes_read);
        }
        
        unsigned char hash[SHA256_BLOCK_SIZE];
        sha256_final(&ctx, hash);
        
        char *hex_str = malloc(SHA256_BLOCK_SIZE * 2 + 1);
        if (!hex_str) return NULL;
        
        for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
            sprintf(hex_str + i * 2, "%02x", hash[i]);
        }
        
        hex_str[SHA256_BLOCK_SIZE * 2] = '\0';
        return hex_str;
        
    } else if (algorithm == HASH_SHA3_256) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        const EVP_MD *md = EVP_sha3_256();
        unsigned char hash[32];
        unsigned int hash_len;
        char *hex_str = malloc(65);
        
        if (!mdctx || !hex_str) {
            if (mdctx) EVP_MD_CTX_free(mdctx);
            return NULL;
        }
        
        EVP_DigestInit_ex(mdctx, md, NULL);
        
        unsigned char buffer[4096];
        size_t bytes_read;
        
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
            EVP_DigestUpdate(mdctx, buffer, bytes_read);
        }
        
        EVP_DigestFinal_ex(mdctx, hash, &hash_len);
        EVP_MD_CTX_free(mdctx);
        
        for (int i = 0; i < 32; i++) {
            sprintf(hex_str + i * 2, "%02x", hash[i]);
        }
        
        hex_str[64] = '\0';
        return hex_str;
    }
    
    return NULL;
}

// Функция для вычисления хеша из данных в памяти
char* compute_hash_from_data(hash_algorithm_t algorithm, const unsigned char *data, size_t len) {
    if (algorithm == HASH_SHA256) {
        return sha256_hex(data, len);
    } else if (algorithm == HASH_SHA3_256) {
        return sha3_256_hex(data, len);
    }
    return NULL;
}