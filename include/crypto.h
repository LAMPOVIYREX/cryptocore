#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdlib.h>
#include "types.h"

// ECB mode
unsigned char* aes_ecb_encrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len);
unsigned char* aes_ecb_decrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len);

// Other modes
unsigned char* aes_cbc_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);
unsigned char* aes_cbc_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);

unsigned char* aes_cfb_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);
unsigned char* aes_cfb_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);

unsigned char* aes_ofb_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);
unsigned char* aes_ofb_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);

unsigned char* aes_ctr_encrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);
unsigned char* aes_ctr_decrypt(const unsigned char* input, size_t input_len,
                              const unsigned char* key, const unsigned char* iv,
                              size_t* output_len);

#endif