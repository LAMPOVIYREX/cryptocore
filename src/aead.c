#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "../include/aead.h"
#include "../include/crypto.h"
#include "../include/common.h"
#include "../include/csprng.h"

static void derive_keys(const unsigned char* master_key, size_t key_len,
                       unsigned char** enc_key, unsigned char** mac_key) {
    // Simple key derivation using HKDF-expand-like approach
    *enc_key = malloc(key_len);
    *mac_key = malloc(key_len);
    
    if (!*enc_key || !*mac_key) return;
    
    // Derive encryption key: HMAC-SHA256(master_key, "enc")
    unsigned char enc_label[] = "enc";
    char* enc_key_hex = hmac_compute_hex(master_key, key_len, 
                                        enc_label, sizeof(enc_label)-1, 
                                        HASH_SHA256);
    if (enc_key_hex) {
        for (size_t i = 0; i < key_len && i*2 < strlen(enc_key_hex); i++) {
            sscanf(enc_key_hex + i*2, "%2hhx", &(*enc_key)[i]);
        }
        free(enc_key_hex);
    }
    
    // Derive MAC key: HMAC-SHA256(master_key, "mac")
    unsigned char mac_label[] = "mac";
    char* mac_key_hex = hmac_compute_hex(master_key, key_len,
                                        mac_label, sizeof(mac_label)-1,
                                        HASH_SHA256);
    if (mac_key_hex) {
        for (size_t i = 0; i < key_len && i*2 < strlen(mac_key_hex); i++) {
            sscanf(mac_key_hex + i*2, "%2hhx", &(*mac_key)[i]);
        }
        free(mac_key_hex);
    }
}

AEAD_CTX* aead_init(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                   const unsigned char* key, size_t key_len) {
    
    AEAD_CTX* ctx = malloc(sizeof(AEAD_CTX));
    if (!ctx) return NULL;
    
    ctx->encryption_mode = enc_mode;
    ctx->mac_algorithm = mac_algo;
    ctx->key_len = key_len;
    
    // Derive separate keys for encryption and MAC
    derive_keys(key, key_len, &ctx->enc_key, &ctx->mac_key);
    
    if (!ctx->enc_key || !ctx->mac_key) {
        if (ctx->enc_key) free(ctx->enc_key);
        if (ctx->mac_key) free(ctx->mac_key);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

int aead_encrypt(AEAD_CTX* ctx,
                const unsigned char* plaintext, size_t plaintext_len,
                const unsigned char* aad, size_t aad_len,
                unsigned char* iv, size_t iv_len,
                unsigned char** ciphertext, size_t* ciphertext_len,
                unsigned char** tag, size_t* tag_len) {
    
    // Mark iv_len as unused to suppress warning
    (void)iv_len;
    
    // Encrypt the plaintext
    unsigned char* encrypted = NULL;
    size_t encrypted_len = 0;
    
    switch(ctx->encryption_mode) {
        case CIPHER_MODE_CBC:
            encrypted = aes_cbc_encrypt(plaintext, plaintext_len, 
                                       ctx->enc_key, iv, &encrypted_len);
            break;
        case CIPHER_MODE_CTR:
            encrypted = aes_ctr_encrypt(plaintext, plaintext_len,
                                       ctx->enc_key, iv, &encrypted_len);
            break;
        default:
            return 0;
    }
    
    if (!encrypted) return 0;
    
    // Compute MAC: HMAC(K_m, C || AAD)
    size_t mac_input_len = encrypted_len + aad_len;
    unsigned char* mac_input = malloc(mac_input_len);
    if (!mac_input) {
        free(encrypted);
        return 0;
    }
    
    memcpy(mac_input, encrypted, encrypted_len);
    memcpy(mac_input + encrypted_len, aad, aad_len);
    
    char* tag_hex = hmac_compute_hex(ctx->mac_key, ctx->key_len,
                                    mac_input, mac_input_len,
                                    ctx->mac_algorithm);
    free(mac_input);
    
    if (!tag_hex) {
        free(encrypted);
        return 0;
    }
    
    // Convert hex tag to binary
    *tag_len = 32; // SHA-256 output size
    *tag = malloc(*tag_len);
    for (size_t i = 0; i < *tag_len; i++) {
        sscanf(tag_hex + i*2, "%2hhx", &(*tag)[i]);
    }
    free(tag_hex);
    
    *ciphertext = encrypted;
    *ciphertext_len = encrypted_len;
    
    return 1;
}

int aead_decrypt(AEAD_CTX* ctx,
                const unsigned char* ciphertext, size_t ciphertext_len,
                const unsigned char* aad, size_t aad_len,
                const unsigned char* iv, size_t iv_len,
                const unsigned char* tag, size_t tag_len,
                unsigned char** plaintext, size_t* plaintext_len) {
    
    // Mark iv_len as unused to suppress warning
    (void)iv_len;
    
    // Verify MAC first
    size_t mac_input_len = ciphertext_len + aad_len;
    unsigned char* mac_input = malloc(mac_input_len);
    if (!mac_input) return 0;
    
    memcpy(mac_input, ciphertext, ciphertext_len);
    memcpy(mac_input + ciphertext_len, aad, aad_len);
    
    char* computed_tag_hex = hmac_compute_hex(ctx->mac_key, ctx->key_len,
                                             mac_input, mac_input_len,
                                             ctx->mac_algorithm);
    free(mac_input);
    
    if (!computed_tag_hex) return 0;
    
    // Convert computed tag to binary
    unsigned char computed_tag[32];
    for (size_t i = 0; i < 32; i++) {
        sscanf(computed_tag_hex + i*2, "%2hhx", &computed_tag[i]);
    }
    free(computed_tag_hex);
    
    // Compare tags (constant-time)
    int tag_valid = 1;
    for (size_t i = 0; i < tag_len && i < 32; i++) {
        tag_valid &= (computed_tag[i] == tag[i]);
    }
    
    if (!tag_valid) return 0;
    
    // Decrypt if tag is valid
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    switch(ctx->encryption_mode) {
        case CIPHER_MODE_CBC:
            decrypted = aes_cbc_decrypt(ciphertext, ciphertext_len,
                                       ctx->enc_key, iv, &decrypted_len);
            break;
        case CIPHER_MODE_CTR:
            decrypted = aes_ctr_decrypt(ciphertext, ciphertext_len,
                                       ctx->enc_key, iv, &decrypted_len);
            break;
        default:
            return 0;
    }
    
    if (!decrypted) return 0;
    
    *plaintext = decrypted;
    *plaintext_len = decrypted_len;
    return 1;
}

void aead_cleanup(AEAD_CTX* ctx) {
    if (ctx) {
        if (ctx->enc_key) {
            memset(ctx->enc_key, 0, ctx->key_len);
            free(ctx->enc_key);
        }
        if (ctx->mac_key) {
            memset(ctx->mac_key, 0, ctx->key_len);
            free(ctx->mac_key);
        }
        free(ctx);
    }
}

int encrypt_then_mac(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                     const unsigned char* key, size_t key_len,
                     const unsigned char* plaintext, size_t plaintext_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char** output, size_t* output_len) {
    
    // Generate random IV
    unsigned char iv[16];
    generate_random_bytes(iv, 16);
    
    AEAD_CTX* ctx = aead_init(enc_mode, mac_algo, key, key_len);
    if (!ctx) return 0;
    
    unsigned char* ciphertext = NULL;
    size_t ciphertext_len = 0;
    unsigned char* tag = NULL;
    size_t tag_len = 0;
    
    if (!aead_encrypt(ctx, plaintext, plaintext_len, aad, aad_len,
                     iv, 16, &ciphertext, &ciphertext_len, &tag, &tag_len)) {
        aead_cleanup(ctx);
        return 0;
    }
    
    // Output format: IV (16) || Ciphertext || Tag
    *output_len = 16 + ciphertext_len + tag_len;
    *output = malloc(*output_len);
    if (!*output) {
        free(ciphertext);
        free(tag);
        aead_cleanup(ctx);
        return 0;
    }
    
    memcpy(*output, iv, 16);
    memcpy(*output + 16, ciphertext, ciphertext_len);
    memcpy(*output + 16 + ciphertext_len, tag, tag_len);
    
    free(ciphertext);
    free(tag);
    aead_cleanup(ctx);
    return 1;
}

int decrypt_then_verify(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                        const unsigned char* key, size_t key_len,
                        const unsigned char* input, size_t input_len,
                        const unsigned char* aad, size_t aad_len,
                        unsigned char** output, size_t* output_len) {
    
    if (input_len < 16 + 32) { // IV + minimum tag size
        return 0;
    }
    
    const unsigned char* iv = input;
    const unsigned char* ciphertext = input + 16;
    size_t ciphertext_len = input_len - 16 - 32;
    const unsigned char* tag = input + 16 + ciphertext_len;
    
    AEAD_CTX* ctx = aead_init(enc_mode, mac_algo, key, key_len);
    if (!ctx) return 0;
    
    unsigned char* plaintext = NULL;
    size_t plaintext_len = 0;
    
    int result = aead_decrypt(ctx, ciphertext, ciphertext_len, aad, aad_len,
                             iv, 16, tag, 32, &plaintext, &plaintext_len);
    
    if (result) {
        *output = plaintext;
        *output_len = plaintext_len;
    }
    
    aead_cleanup(ctx);
    return result;
}