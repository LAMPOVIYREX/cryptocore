#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/crypto.h"
#include "../src/file_io.h"
#include "../src/csprng.h"

void test_roundtrip_mode(const char* mode_name, cipher_mode_t mode, int requires_iv) {
    printf("Testing %s mode... ", mode_name);
    
    // Generate random key and IV
    unsigned char key[16];
    unsigned char iv[16];
    
    assert(generate_random_bytes(key, 16) == 0);
    if (requires_iv) {
        assert(generate_random_bytes(iv, 16) == 0);
    }
    
    // Create test data
    unsigned char test_data_15[] = "15 bytes test!!";
    
    size_t encrypted_len, decrypted_len;
    unsigned char* encrypted;
    unsigned char* decrypted;
    
    // Test with 15 bytes
    if (requires_iv) {
        encrypted = NULL;
        if (mode == CIPHER_MODE_CBC) {
            encrypted = aes_cbc_encrypt(test_data_15, 15, key, iv, &encrypted_len);
        } else if (mode == CIPHER_MODE_CFB) {
            encrypted = aes_cfb_encrypt(test_data_15, 15, key, iv, &encrypted_len);
        } else if (mode == CIPHER_MODE_OFB) {
            encrypted = aes_ofb_encrypt(test_data_15, 15, key, iv, &encrypted_len);
        } else if (mode == CIPHER_MODE_CTR) {
            encrypted = aes_ctr_encrypt(test_data_15, 15, key, iv, &encrypted_len);
        }
    } else {
        // ECB mode
        encrypted = aes_ecb_encrypt(test_data_15, 15, key, &encrypted_len);
    }
    
    assert(encrypted != NULL);
    
    // Decrypt
    if (requires_iv) {
        decrypted = NULL;
        if (mode == CIPHER_MODE_CBC) {
            decrypted = aes_cbc_decrypt(encrypted, encrypted_len, key, iv, &decrypted_len);
        } else if (mode == CIPHER_MODE_CFB) {
            decrypted = aes_cfb_decrypt(encrypted, encrypted_len, key, iv, &decrypted_len);
        } else if (mode == CIPHER_MODE_OFB) {
            decrypted = aes_ofb_decrypt(encrypted, encrypted_len, key, iv, &decrypted_len);
        } else if (mode == CIPHER_MODE_CTR) {
            decrypted = aes_ctr_decrypt(encrypted, encrypted_len, key, iv, &decrypted_len);
        }
    } else {
        // ECB mode
        decrypted = aes_ecb_decrypt(encrypted, encrypted_len, key, &decrypted_len);
    }
    
    assert(decrypted != NULL);
    assert(decrypted_len == 15);
    assert(memcmp(test_data_15, decrypted, 15) == 0);
    
    free(encrypted);
    free(decrypted);
    
    printf("✓\n");
}

int main() {
    printf("=== CryptoCore Round-trip Tests ===\n\n");
    
    test_roundtrip_mode("ECB", CIPHER_MODE_ECB, 0);
    test_roundtrip_mode("CBC", CIPHER_MODE_CBC, 1);
    test_roundtrip_mode("CFB", CIPHER_MODE_CFB, 1);
    test_roundtrip_mode("OFB", CIPHER_MODE_OFB, 1);
    test_roundtrip_mode("CTR", CIPHER_MODE_CTR, 1);
    
    printf("\n=== All round-trip tests passed! ===\n");
    return 0;
}