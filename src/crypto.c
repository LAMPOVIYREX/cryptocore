#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "../include/crypto.h"
#include "../include/modes/ecb.h"

#define AES_BLOCK_SIZE 16

unsigned char* aes_ecb_encrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;
    
    // Copy input data for padding
    unsigned char* padded_data = malloc(input_len);
    if (padded_data == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }
    memcpy(padded_data, input, input_len);
    size_t padded_len = input_len;
    
    // Apply PKCS#7 padding
    pkcs7_pad(&padded_data, &padded_len);
    
    // Allocate output buffer
    unsigned char* output = malloc(padded_len + AES_BLOCK_SIZE);
    if (output == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(padded_data);
        return NULL;
    }
    
    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        free(padded_data);
        free(output);
        return NULL;
    }
    
    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        fprintf(stderr, "Error: Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(padded_data);
        free(output);
        return NULL;
    }
    
    // Disable padding since we handle it manually
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Perform encryption
    if (1 != EVP_EncryptUpdate(ctx, output, &len, padded_data, padded_len)) {
        fprintf(stderr, "Error: Encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(padded_data);
        free(output);
        return NULL;
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) {
        fprintf(stderr, "Error: Encryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(padded_data);
        free(output);
        return NULL;
    }
    ciphertext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    free(padded_data);
    
    *output_len = ciphertext_len;
    return output;
}

unsigned char* aes_ecb_decrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;
    
    if (input_len % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Input length must be multiple of block size\n");
        return NULL;
    }
    
    // Allocate output buffer
    unsigned char* output = malloc(input_len);
    if (output == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }
    
    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        free(output);
        return NULL;
    }
    
    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        fprintf(stderr, "Error: Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    
    // Disable padding since we handle it manually
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    // Perform decryption
    if (1 != EVP_DecryptUpdate(ctx, output, &len, input, input_len)) {
        fprintf(stderr, "Error: Decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len = len;
    
    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, output + len, &len)) {
        fprintf(stderr, "Error: Decryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        return NULL;
    }
    plaintext_len += len;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    
    // Remove PKCS#7 padding - исправленная строка
    size_t plaintext_size = (size_t)plaintext_len;
    if (!pkcs7_unpad(&output, &plaintext_size)) {
        fprintf(stderr, "Error: Failed to remove padding\n");
        free(output);
        return NULL;
    }
    
    *output_len = plaintext_size;
    return output;
}