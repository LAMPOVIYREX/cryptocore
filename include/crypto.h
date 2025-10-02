#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdlib.h>

unsigned char* aes_ecb_encrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len);
unsigned char* aes_ecb_decrypt(const unsigned char* input, size_t input_len, 
                              const unsigned char* key, size_t* output_len);

#endif