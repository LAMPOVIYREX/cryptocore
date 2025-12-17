#ifndef AEAD_H
#define AEAD_H

#include <stdlib.h>
#include "types.h"
#include "mac/hmac.h"

typedef struct {
    cipher_mode_t encryption_mode;
    hash_algorithm_t mac_algorithm;
    unsigned char* enc_key;
    unsigned char* mac_key;
    size_t key_len;
} AEAD_CTX;

AEAD_CTX* aead_init(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                   const unsigned char* key, size_t key_len);

int aead_encrypt(AEAD_CTX* ctx,
                const unsigned char* plaintext, size_t plaintext_len,
                const unsigned char* aad, size_t aad_len,
                unsigned char* iv, size_t iv_len,
                unsigned char** ciphertext, size_t* ciphertext_len,
                unsigned char** tag, size_t* tag_len);

int aead_decrypt(AEAD_CTX* ctx,
                const unsigned char* ciphertext, size_t ciphertext_len,
                const unsigned char* aad, size_t aad_len,
                const unsigned char* iv, size_t iv_len,
                const unsigned char* tag, size_t tag_len,
                unsigned char** plaintext, size_t* plaintext_len);

void aead_cleanup(AEAD_CTX* ctx);

// High-level functions
int encrypt_then_mac(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                     const unsigned char* key, size_t key_len,
                     const unsigned char* plaintext, size_t plaintext_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char** output, size_t* output_len);

int decrypt_then_verify(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                        const unsigned char* key, size_t key_len,
                        const unsigned char* input, size_t input_len,
                        const unsigned char* aad, size_t aad_len,
                        unsigned char** output, size_t* output_len);

#endif