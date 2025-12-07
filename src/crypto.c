#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "../include/crypto.h"
#include "../include/common.h"



// Keep existing ECB functions but update them to use new helper functions
unsigned char* aes_ecb_encrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len) {
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
    
    for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        aes_encrypt_block(padded_data + i, output + i, key);
    }
    
    free(padded_data);
    *output_len = padded_len;
    return output;
}

unsigned char* aes_ecb_decrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len) {
    if (input_len % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Input length must be multiple of block size for ECB decryption\n");
        return NULL;
    }
    
    unsigned char* output = malloc(input_len);
    if (!output) return NULL;
    
    for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
        aes_decrypt_block(input + i, output + i, key);
    }
    
    if (!pkcs7_unpad(&output, &input_len)) {
        fprintf(stderr, "Error: PKCS#7 unpadding failed in ECB mode\n");
        free(output);
        return NULL;
    }
    
    *output_len = input_len;
    return output;
}