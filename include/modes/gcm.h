#ifndef GCM_H
#define GCM_H

#include <stdlib.h>

#define GCM_IV_SIZE 12  // Recommended nonce size
#define GCM_TAG_SIZE 16 // 128-bit tag

typedef struct {
    unsigned char* key;
    size_t key_len;
    unsigned char* nonce;
    size_t nonce_len;
} GCM_CTX;

GCM_CTX* gcm_init(const unsigned char* key, size_t key_len);
void gcm_set_nonce(GCM_CTX* ctx, const unsigned char* nonce, size_t nonce_len);
void gcm_generate_nonce(GCM_CTX* ctx);

int gcm_encrypt(GCM_CTX* ctx, 
                const unsigned char* plaintext, size_t plaintext_len,
                const unsigned char* aad, size_t aad_len,
                unsigned char* ciphertext,
                unsigned char* tag);

int gcm_decrypt(GCM_CTX* ctx,
                const unsigned char* ciphertext, size_t ciphertext_len,
                const unsigned char* aad, size_t aad_len,
                const unsigned char* tag,
                unsigned char* plaintext);

void gcm_cleanup(GCM_CTX* ctx);

// Helper functions
int gcm_encrypt_full(const unsigned char* key, size_t key_len,
                     const unsigned char* nonce, size_t nonce_len,
                     const unsigned char* plaintext, size_t plaintext_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char** output, size_t* output_len);

int gcm_decrypt_full(const unsigned char* key, size_t key_len,
                     const unsigned char* input, size_t input_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char** output, size_t* output_len);

#endif