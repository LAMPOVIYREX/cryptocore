#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include "types.h"

#define AES_BLOCK_SIZE 16

// Padding functions
void pkcs7_pad(unsigned char** data, size_t* data_len);
int pkcs7_unpad(unsigned char** data, size_t* data_len);

// AES block operations
void aes_encrypt_block(const unsigned char* input, unsigned char* output, const unsigned char* key);
void aes_decrypt_block(const unsigned char* input, unsigned char* output, const unsigned char* key);

// Utility
int requires_padding(cipher_mode_t mode);
void generate_random_iv(unsigned char* iv, size_t len);

#endif