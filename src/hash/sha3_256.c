#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "../../include/hash/sha3_256.h"

char* sha3_256_hex(const unsigned char *data, size_t len) {
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
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    for (int i = 0; i < 32; i++) {
        sprintf(hex_str + i * 2, "%02x", hash[i]);
    }
    
    hex_str[64] = '\0';
    return hex_str;
}

char* sha3_256_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha3_256();
    unsigned char hash[32];
    unsigned int hash_len;
    char *hex_str = malloc(65);
    
    if (!mdctx || !hex_str) {
        fclose(file);
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return NULL;
    }
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    
    unsigned char buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }
    
    fclose(file);
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    
    for (int i = 0; i < 32; i++) {
        sprintf(hex_str + i * 2, "%02x", hash[i]);
    }
    
    hex_str[64] = '\0';
    return hex_str;
}