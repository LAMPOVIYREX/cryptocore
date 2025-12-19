#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "../include/crypto.h"
#include "../include/common.h"
#include "../include/csprng.h"



// Utility functions
int requires_padding(cipher_mode_t mode) {
    return (mode == CIPHER_MODE_ECB || mode == CIPHER_MODE_CBC);
}

void generate_random_iv(unsigned char* iv, size_t len) {
    if (generate_random_bytes(iv, len) != 0) {
        fprintf(stderr, "Error: Failed to generate cryptographically secure IV\n");
        memset(iv, 0, len);  
    }
}

// Padding functions
void pkcs7_pad(unsigned char** data, size_t* data_len) {
    size_t padding_len = AES_BLOCK_SIZE - (*data_len % AES_BLOCK_SIZE);
    if (padding_len == 0) padding_len = AES_BLOCK_SIZE;
    
    size_t new_len = *data_len + padding_len;
    unsigned char* new_data = realloc(*data, new_len);
    if (new_data == NULL) return;
    
    for (size_t i = *data_len; i < new_len; i++) {
        new_data[i] = (unsigned char)padding_len;
    }
    
    *data = new_data;
    *data_len = new_len;
}

int pkcs7_unpad(unsigned char** data, size_t* data_len) {
    if (*data_len == 0 || *data_len % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Invalid data length for unpadding\n");
        return 0;
    }
    
    unsigned char padding_byte = (*data)[*data_len - 1];
    if (padding_byte == 0 || padding_byte > AES_BLOCK_SIZE) {
        fprintf(stderr, "Error: Invalid padding byte\n");
        return 0;
    }
    
    for (size_t i = *data_len - padding_byte; i < *data_len; i++) {
        if ((*data)[i] != padding_byte) {
            fprintf(stderr, "Error: Padding validation failed\n");
            return 0;
        }
    }
    
    *data_len -= padding_byte;
    return 1;
}

// AES block encryption/decryption helper
void aes_encrypt_block(const unsigned char* input, unsigned char* output, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    int out_len;
    EVP_EncryptUpdate(ctx, output, &out_len, input, AES_BLOCK_SIZE);
    EVP_CIPHER_CTX_free(ctx);
}

void aes_decrypt_block(const unsigned char* input, unsigned char* output, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    int out_len;
    EVP_DecryptUpdate(ctx, output, &out_len, input, AES_BLOCK_SIZE);
    EVP_CIPHER_CTX_free(ctx);
}

// CBC Mode
unsigned char* aes_cbc_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    unsigned char* padded_data = malloc(input_len);
    if (!padded_data) return NULL;
    memcpy(padded_data, input, input_len);
    size_t padded_len = input_len;
    
    pkcs7_pad(&padded_data, &padded_len);
    
    unsigned char* output = malloc(padded_len);
    if (!output) {
        free(padded_data);
        return NULL;
    }
    
    unsigned char block[AES_BLOCK_SIZE];
    unsigned char prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        // XOR with previous ciphertext block (or IV for first block)
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = padded_data[i + j] ^ prev_block[j];
        }
        
        // Encrypt the block
        aes_encrypt_block(block, output + i, key);
        memcpy(prev_block, output + i, AES_BLOCK_SIZE);
    }
    
    free(padded_data);
    *output_len = padded_len;
    return output;
}

unsigned char* aes_cbc_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    if (input_len % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Input length must be multiple of block size for CBC decryption\n");
        return NULL;
    }
    
    unsigned char* output = malloc(input_len);
    if (!output) return NULL;
    
    unsigned char block[AES_BLOCK_SIZE];
    unsigned char prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
        // Decrypt the block
        aes_decrypt_block(input + i, block, key);
        
        // XOR with previous ciphertext block (or IV for first block)
        for (size_t j = 0; j < AES_BLOCK_SIZE; j++) {
            output[i + j] = block[j] ^ prev_block[j];
        }
        
        memcpy(prev_block, input + i, AES_BLOCK_SIZE);
    }
    
    // Remove padding
    if (!pkcs7_unpad(&output, &input_len)) {
        free(output);
        return NULL;
    }
    
    *output_len = input_len;
    return output;
}

// CFB Mode - CFB-128 implementation (fixed)
unsigned char* aes_cfb_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    unsigned char* output = malloc(input_len);
    if (!output) return NULL;
    
    unsigned char feedback[AES_BLOCK_SIZE];
    unsigned char encrypted_block[AES_BLOCK_SIZE];
    
    // Initialize feedback register with IV
    memcpy(feedback, iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
        // Encrypt the current feedback register
        aes_encrypt_block(feedback, encrypted_block, key);
        
        size_t block_size = (input_len - i < AES_BLOCK_SIZE) ? input_len - i : AES_BLOCK_SIZE;
        
        // XOR plaintext with encrypted block to get ciphertext
        for (size_t j = 0; j < block_size; j++) {
            output[i + j] = input[i + j] ^ encrypted_block[j];
        }
        
        // Update feedback register with ciphertext (for CFB-128)
        if (block_size == AES_BLOCK_SIZE) {
            memcpy(feedback, output + i, AES_BLOCK_SIZE);
        } else {
            // For partial final block, shift and insert new ciphertext bytes
            memmove(feedback, feedback + block_size, AES_BLOCK_SIZE - block_size);
            memcpy(feedback + AES_BLOCK_SIZE - block_size, output + i, block_size);
        }
    }
    
    *output_len = input_len;
    return output;
}

unsigned char* aes_cfb_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    unsigned char* output = malloc(input_len);
    if (!output) return NULL;
    
    unsigned char feedback[AES_BLOCK_SIZE];
    unsigned char encrypted_block[AES_BLOCK_SIZE];
    
    // Initialize feedback register with IV
    memcpy(feedback, iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
        // Encrypt the current feedback register
        aes_encrypt_block(feedback, encrypted_block, key);
        
        size_t block_size = (input_len - i < AES_BLOCK_SIZE) ? input_len - i : AES_BLOCK_SIZE;
        
        // XOR ciphertext with encrypted block to get plaintext
        for (size_t j = 0; j < block_size; j++) {
            output[i + j] = input[i + j] ^ encrypted_block[j];
        }
        
        // Update feedback register with ciphertext (not plaintext)
        if (block_size == AES_BLOCK_SIZE) {
            memcpy(feedback, input + i, AES_BLOCK_SIZE);
        } else {
            // For partial final block, shift and insert new ciphertext bytes
            memmove(feedback, feedback + block_size, AES_BLOCK_SIZE - block_size);
            memcpy(feedback + AES_BLOCK_SIZE - block_size, input + i, block_size);
        }
    }
    
    *output_len = input_len;
    return output;
}

// OFB Mode
unsigned char* aes_ofb_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    unsigned char* output = malloc(input_len);
    if (!output) return NULL;
    
    unsigned char feedback[AES_BLOCK_SIZE];
    unsigned char keystream[AES_BLOCK_SIZE];
    memcpy(feedback, iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
        // Generate keystream by encrypting feedback register
        aes_encrypt_block(feedback, keystream, key);
        
        size_t block_size = (input_len - i < AES_BLOCK_SIZE) ? input_len - i : AES_BLOCK_SIZE;
        
        // XOR plaintext with keystream to produce ciphertext
        for (size_t j = 0; j < block_size; j++) {
            output[i + j] = input[i + j] ^ keystream[j];
        }
        
        // Update feedback register with keystream (not ciphertext)
        memcpy(feedback, keystream, AES_BLOCK_SIZE);
    }
    
    *output_len = input_len;
    return output;
}

unsigned char* aes_ofb_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    // OFB decryption is identical to encryption
    return aes_ofb_encrypt(input, input_len, key, iv, output_len);
}

// CTR Mode
unsigned char* aes_ctr_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    unsigned char* output = malloc(input_len);
    if (!output) return NULL;
    
    unsigned char counter[AES_BLOCK_SIZE];
    unsigned char keystream[AES_BLOCK_SIZE];
    memcpy(counter, iv, AES_BLOCK_SIZE);
    
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
        // Generate keystream by encrypting counter
        aes_encrypt_block(counter, keystream, key);
        
        size_t block_size = (input_len - i < AES_BLOCK_SIZE) ? input_len - i : AES_BLOCK_SIZE;
        
        // XOR plaintext with keystream to produce ciphertext
        for (size_t j = 0; j < block_size; j++) {
            output[i + j] = input[i + j] ^ keystream[j];
        }
        
        // Increment counter (big-endian)
        for (int j = AES_BLOCK_SIZE - 1; j >= 0; j--) {
            if (++counter[j] != 0) break;
        }
    }
    
    *output_len = input_len;
    return output;
}

unsigned char* aes_ctr_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len) {
    // CTR decryption is identical to encryption
    return aes_ctr_encrypt(input, input_len, key, iv, output_len);
}