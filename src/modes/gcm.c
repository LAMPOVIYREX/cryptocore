#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "../../include/modes/gcm.h"
#include "../../include/csprng.h"
#include "../../include/common.h"

// Simplified GCM implementation focusing on correctness

GCM_CTX* gcm_init(const unsigned char* key, size_t key_len) {
    if (key_len != 16) return NULL;
    
    GCM_CTX* ctx = malloc(sizeof(GCM_CTX));
    if (!ctx) return NULL;
    
    ctx->key_len = key_len;
    ctx->key = malloc(key_len);
    if (!ctx->key) {
        free(ctx);
        return NULL;
    }
    memcpy(ctx->key, key, key_len);
    
    ctx->nonce = NULL;
    ctx->nonce_len = 0;
    
    return ctx;
}

void gcm_set_nonce(GCM_CTX* ctx, const unsigned char* nonce, size_t nonce_len) {
    if (ctx->nonce) free(ctx->nonce);
    ctx->nonce_len = nonce_len;
    ctx->nonce = malloc(nonce_len);
    if (ctx->nonce) {
        memcpy(ctx->nonce, nonce, nonce_len);
    }
}

void gcm_generate_nonce(GCM_CTX* ctx) {
    if (ctx->nonce) free(ctx->nonce);
    ctx->nonce_len = GCM_IV_SIZE;
    ctx->nonce = malloc(GCM_IV_SIZE);
    generate_random_bytes(ctx->nonce, GCM_IV_SIZE);
}

int gcm_encrypt(GCM_CTX* ctx, 
                const unsigned char* plaintext, size_t plaintext_len,
                const unsigned char* aad, size_t aad_len,
                unsigned char* ciphertext,
                unsigned char* tag) {
    
    if (!ctx->nonce || ctx->nonce_len != GCM_IV_SIZE) {
        return 0;
    }
    
    // Use OpenSSL for GCM (simplified)
    EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx) return 0;
    
    int len;
    int ciphertext_len;
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_gcm(), NULL, ctx->key, ctx->nonce) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    
    // Set IV length
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL);
    
    // Add AAD if provided
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(evp_ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(evp_ctx);
            return 0;
        }
    }
    
    // Encrypt plaintext
    if (EVP_EncryptUpdate(evp_ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(evp_ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    ciphertext_len += len;
    
    // Get tag
    if (EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    
    EVP_CIPHER_CTX_free(evp_ctx);
    return 1;
}

int gcm_decrypt(GCM_CTX* ctx,
                const unsigned char* ciphertext, size_t ciphertext_len,
                const unsigned char* aad, size_t aad_len,
                const unsigned char* tag,
                unsigned char* plaintext) {
    
    if (!ctx->nonce || ctx->nonce_len != GCM_IV_SIZE) {
        return 0;
    }
    
    EVP_CIPHER_CTX* evp_ctx = EVP_CIPHER_CTX_new();
    if (!evp_ctx) return 0;
    
    int len;
    int plaintext_len;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(evp_ctx, EVP_aes_128_gcm(), NULL, ctx->key, ctx->nonce) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    
    // Set IV length
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL);
    
    // Set expected tag
    EVP_CIPHER_CTX_ctrl(evp_ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag);
    
    // Add AAD if provided
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(evp_ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(evp_ctx);
            return 0;
        }
    }
    
    // Decrypt ciphertext
    if (EVP_DecryptUpdate(evp_ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    plaintext_len = len;
    
    // Finalize decryption (verifies tag)
    if (EVP_DecryptFinal_ex(evp_ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(evp_ctx);
        return 0;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(evp_ctx);
    return 1;
}

void gcm_cleanup(GCM_CTX* ctx) {
    if (ctx) {
        if (ctx->key) {
            memset(ctx->key, 0, ctx->key_len);
            free(ctx->key);
        }
        if (ctx->nonce) {
            memset(ctx->nonce, 0, ctx->nonce_len);
            free(ctx->nonce);
        }
        free(ctx);
    }
}

int gcm_encrypt_full(const unsigned char* key, size_t key_len,
                     const unsigned char* nonce, size_t nonce_len,
                     const unsigned char* plaintext, size_t plaintext_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char** output, size_t* output_len) {
    
    GCM_CTX* ctx = gcm_init(key, key_len);
    if (!ctx) return 0;
    
    gcm_set_nonce(ctx, nonce, nonce_len);
    
    *output_len = nonce_len + plaintext_len + GCM_TAG_SIZE;
    *output = malloc(*output_len);
    if (!*output) {
        gcm_cleanup(ctx);
        return 0;
    }
    
    // Copy nonce to output
    memcpy(*output, nonce, nonce_len);
    
    unsigned char* ciphertext = *output + nonce_len;
    unsigned char tag[GCM_TAG_SIZE];
    
    if (!gcm_encrypt(ctx, plaintext, plaintext_len, aad, aad_len, ciphertext, tag)) {
        free(*output);
        gcm_cleanup(ctx);
        return 0;
    }
    
    // Copy tag to output
    memcpy(*output + nonce_len + plaintext_len, tag, GCM_TAG_SIZE);
    
    gcm_cleanup(ctx);
    return 1;
}

int gcm_decrypt_full(const unsigned char* key, size_t key_len,
                     const unsigned char* input, size_t input_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char** output, size_t* output_len) {
    
    if (input_len < GCM_IV_SIZE + GCM_TAG_SIZE) {
        return 0;
    }
    
    size_t nonce_len = GCM_IV_SIZE;
    size_t ciphertext_len = input_len - nonce_len - GCM_TAG_SIZE;
    
    const unsigned char* nonce = input;
    const unsigned char* ciphertext = input + nonce_len;
    const unsigned char* tag = input + nonce_len + ciphertext_len;
    
    GCM_CTX* ctx = gcm_init(key, key_len);
    if (!ctx) return 0;
    
    gcm_set_nonce(ctx, nonce, nonce_len);
    
    *output = malloc(ciphertext_len);
    if (!*output) {
        gcm_cleanup(ctx);
        return 0;
    }
    
    int result = gcm_decrypt(ctx, ciphertext, ciphertext_len, aad, aad_len, tag, *output);
    if (result) {
        *output_len = ciphertext_len;
    } else {
        free(*output);
        *output = NULL;
    }
    
    gcm_cleanup(ctx);
    return result;
}