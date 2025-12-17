#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../include/modes/gcm.h"

void hex_to_binary(const char* hex, unsigned char* binary, size_t* len) {
    size_t hex_len = strlen(hex);
    *len = hex_len / 2;
    
    for (size_t i = 0; i < *len; i++) {
        sscanf(hex + i * 2, "%2hhx", &binary[i]);
    }
}

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// В функции test_gcm_basic() исправьте:
void test_gcm_basic() {
    printf("=== Basic GCM Tests ===\n\n");
    
    // Test Case 1: Basic encryption/decryption
    printf("Test 1: Basic encryption/decryption... ");
    
    unsigned char key[16];
    memset(key, 0, 16);
    
    unsigned char iv[12];
    memset(iv, 0, 12);
    
    unsigned char plaintext[] = "Hello GCM World! This is a test.";
    unsigned char aad[] = "Additional authenticated data";
    
    unsigned char* encrypted = NULL;
    size_t encrypted_len = 0;
    
    if (gcm_encrypt_full(key, 16, iv, 12,
                        plaintext, strlen((char*)plaintext),
                        aad, strlen((char*)aad),
                        &encrypted, &encrypted_len)) {
        
        printf("Encryption OK (len=%zu)... ", encrypted_len);
        
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        
        if (gcm_decrypt_full(key, 16, encrypted, encrypted_len,
                            aad, strlen((char*)aad),
                            &decrypted, &decrypted_len)) {
            
            if (decrypted_len == strlen((char*)plaintext) && 
                memcmp(plaintext, decrypted, decrypted_len) == 0) {
                printf("✅ PASS\n");
            } else {
                printf("❌ FAIL - Decryption mismatch\n");
                printf("  Original: %s\n", plaintext);
                printf("  Decrypted: %.*s\n", (int)decrypted_len, decrypted);
            }
            
            free(decrypted);
        } else {
            printf("❌ FAIL - Decryption failed\n");
        }
        
        free(encrypted);
    } else {
        printf("❌ FAIL - Encryption failed\n");
    }
    
    // Test Case 2: Empty data
    printf("\nTest 2: Empty data... ");
    
    unsigned char* empty = (unsigned char*)"";
    unsigned char iv2[12] = {1,2,3,4,5,6,7,8,9,10,11,12}; // Different IV!
    
    if (gcm_encrypt_full(key, 16, iv2, 12,
                        empty, 0,
                        empty, 0,
                        &encrypted, &encrypted_len)) {
        
        if (encrypted_len == 12 + 16) { // nonce(12) + tag(16)
            printf("✅ PASS (empty handled correctly)\n");
        } else {
            printf("❌ FAIL (wrong size: expected 28, got %zu)\n", encrypted_len);
        }
        
        free(encrypted);
    } else {
        printf("❌ FAIL - Empty encryption failed\n");
    }
    
    // Test Case 3: Different IV
    printf("\nTest 3: Different IV... ");
    
    unsigned char iv3[12];
    for (int i = 0; i < 12; i++) iv3[i] = i * 3; // Make it really different
    
    unsigned char plaintext2[] = "Test with different IV";
    
    if (gcm_encrypt_full(key, 16, iv3, 12,
                        plaintext2, strlen((char*)plaintext2),
                        aad, strlen((char*)aad),
                        &encrypted, &encrypted_len)) {
        
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        
        if (gcm_decrypt_full(key, 16, encrypted, encrypted_len,
                            aad, strlen((char*)aad),
                            &decrypted, &decrypted_len)) {
            
            if (memcmp(plaintext2, decrypted, decrypted_len) == 0) {
                printf("✅ PASS\n");
            } else {
                printf("❌ FAIL\n");
            }
            
            free(decrypted);
        } else {
            printf("❌ FAIL - Decryption failed\n");
        }
        
        free(encrypted);
    } else {
        printf("❌ FAIL - Encryption failed\n");
    }
}

void test_gcm_failures() {
    printf("\n=== GCM Failure Cases ===\n");
    
    unsigned char key[16];
    memset(key, 0x11, 16);
    
    unsigned char iv[12];
    memset(iv, 0x22, 12);
    
    unsigned char plaintext[] = "Message to authenticate";
    unsigned char correct_aad[] = "Correct AAD";
    unsigned char wrong_aad[] = "Wrong AAD";
    
    // Test 1: Wrong AAD
    printf("\n1. Testing wrong AAD... ");
    
    unsigned char* encrypted = NULL;
    size_t encrypted_len = 0;
    
    if (gcm_encrypt_full(key, 16, iv, 12,
                        plaintext, strlen((char*)plaintext),
                        correct_aad, strlen((char*)correct_aad),
                        &encrypted, &encrypted_len)) {
        
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        
        // Try to decrypt with wrong AAD
        int result = gcm_decrypt_full(key, 16, encrypted, encrypted_len,
                                     wrong_aad, strlen((char*)wrong_aad),
                                     &decrypted, &decrypted_len);
        
        if (!result) {
            printf("✅ Correctly rejected wrong AAD\n");
        } else {
            printf("❌ Wrong AAD should have been rejected\n");
            free(decrypted);
        }
        
        free(encrypted);
    }
    
    // Test 2: Tampered ciphertext
    printf("2. Testing tampered ciphertext... ");
    
    unsigned char key2[16];
    for (int i = 0; i < 16; i++) key2[i] = i;
    
    unsigned char iv2[12];
    for (int i = 0; i < 12; i++) iv2[i] = i * 2;
    
    if (gcm_encrypt_full(key2, 16, iv2, 12,
                        plaintext, strlen((char*)plaintext),
                        correct_aad, strlen((char*)correct_aad),
                        &encrypted, &encrypted_len)) {
        
        // Tamper with ciphertext (flip one byte)
        if (encrypted_len > 12 + 5) {
            encrypted[12 + 5] ^= 0x01; // Flip a byte in ciphertext
            
            unsigned char* decrypted = NULL;
            size_t decrypted_len = 0;
            
            int result = gcm_decrypt_full(key2, 16, encrypted, encrypted_len,
                                         correct_aad, strlen((char*)correct_aad),
                                         &decrypted, &decrypted_len);
            
            if (!result) {
                printf("✅ Correctly rejected tampered ciphertext\n");
            } else {
                printf("❌ Tampered ciphertext should have been rejected\n");
                free(decrypted);
            }
        }
        
        free(encrypted);
    }
    
    // Test 3: Wrong tag
    printf("3. Testing wrong tag... ");
    
    if (gcm_encrypt_full(key, 16, iv, 12,
                        plaintext, strlen((char*)plaintext),
                        correct_aad, strlen((char*)correct_aad),
                        &encrypted, &encrypted_len)) {
        
        // Tamper with tag (flip last byte)
        if (encrypted_len > 16) {
            encrypted[encrypted_len - 1] ^= 0x01;
            
            unsigned char* decrypted = NULL;
            size_t decrypted_len = 0;
            
            int result = gcm_decrypt_full(key, 16, encrypted, encrypted_len,
                                         correct_aad, strlen((char*)correct_aad),
                                         &decrypted, &decrypted_len);
            
            if (!result) {
                printf("✅ Correctly rejected wrong tag\n");
            } else {
                printf("❌ Wrong tag should have been rejected\n");
                free(decrypted);
            }
        }
        
        free(encrypted);
    }
    
    // Test 4: Wrong key
    printf("4. Testing wrong key... ");
    
    if (gcm_encrypt_full(key, 16, iv, 12,
                        plaintext, strlen((char*)plaintext),
                        correct_aad, strlen((char*)correct_aad),
                        &encrypted, &encrypted_len)) {
        
        unsigned char wrong_key[16];
        memset(wrong_key, 0xFF, 16);
        
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        
        int result = gcm_decrypt_full(wrong_key, 16, encrypted, encrypted_len,
                                     correct_aad, strlen((char*)correct_aad),
                                     &decrypted, &decrypted_len);
        
        if (!result) {
            printf("✅ Correctly rejected wrong key\n");
        } else {
            printf("❌ Wrong key should have been rejected\n");
            free(decrypted);
        }
        
        free(encrypted);
    }
}

void test_gcm_nist_simple() {
    printf("\n=== NIST-like Test Cases ===\n");
    
    // Simple test similar to NIST but without exact vector matching
    printf("\nTest: Simple NIST-like case... ");
    
    unsigned char key[16];
    unsigned char iv[12];
    unsigned char plaintext[32];
    unsigned char aad[32];
    
    // Use simple patterns
    for (int i = 0; i < 16; i++) key[i] = i;
    for (int i = 0; i < 12; i++) iv[i] = i * 2;
    for (int i = 0; i < 32; i++) {
        plaintext[i] = i;
        aad[i] = 0xFF - i;
    }
    
    unsigned char* encrypted = NULL;
    size_t encrypted_len = 0;
    
    if (gcm_encrypt_full(key, 16, iv, 12,
                        plaintext, 32,
                        aad, 32,
                        &encrypted, &encrypted_len)) {
        
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        
        if (gcm_decrypt_full(key, 16, encrypted, encrypted_len,
                            aad, 32,
                            &decrypted, &decrypted_len)) {
            
            if (decrypted_len == 32 && memcmp(plaintext, decrypted, 32) == 0) {
                printf("✅ PASS\n");
            } else {
                printf("❌ FAIL - Data mismatch\n");
            }
            
            free(decrypted);
        } else {
            printf("❌ FAIL - Decryption failed\n");
        }
        
        free(encrypted);
    } else {
        printf("❌ FAIL - Encryption failed\n");
    }
}

int main() {
    printf("=== GCM Implementation Tests ===\n\n");
    
    test_gcm_basic();
    test_gcm_failures();
    test_gcm_nist_simple();
    
    printf("\n=== All GCM tests completed ===\n");
    return 0;
}