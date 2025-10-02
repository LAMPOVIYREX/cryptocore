#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../include/cli_parser.h"
#include "../include/file_io.h"
#include "../include/crypto.h"

int files_identical(const char* file1, const char* file2) {
    struct stat stat1, stat2;
    if (stat(file1, &stat1) != 0 || stat(file2, &stat2) != 0) {
        return 0;
    }
    
    if (stat1.st_size != stat2.st_size) {
        return 0;
    }
    
    FILE* f1 = fopen(file1, "rb");
    FILE* f2 = fopen(file2, "rb");
    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return 0;
    }
    
    int result = 1;
    int c1, c2;
    while ((c1 = fgetc(f1)) != EOF && (c2 = fgetc(f2)) != EOF) {
        if (c1 != c2) {
            result = 0;
            break;
        }
    }
    
    // Check if both reached EOF
    if (c1 != EOF || c2 != EOF) {
        result = 0;
    }
    
    fclose(f1);
    fclose(f2);
    return result;
}

int main() {
    const char* test_file = "test_input.txt";
    const char* encrypted_file = "test_encrypted.bin";
    const char* decrypted_file = "test_decrypted.txt";
    const char* test_key = "@00112233445566778899aabbccddeeff";
    
    printf("Testing CryptoCore round-trip encryption/decryption...\n");
    
    // Create test file with various content lengths to test padding
    FILE* f = fopen(test_file, "wb");
    const char* test_data = "This is a test message for CryptoCore!";
    fwrite(test_data, 1, strlen(test_data), f);
    fclose(f);
    
    // Read test file
    size_t input_size;
    unsigned char* input_data = read_file(test_file, &input_size);
    if (!input_data) {
        printf("FAIL: Could not read test file\n");
        return 1;
    }
    
    // Convert key
    unsigned char* key_bytes;
    size_t key_len;
    if (!hex_to_bytes(test_key, &key_bytes, &key_len)) {
        printf("FAIL: Invalid key\n");
        free(input_data);
        return 1;
    }
    
    // Encrypt
    size_t encrypted_size;
    unsigned char* encrypted_data = aes_ecb_encrypt(input_data, input_size, key_bytes, &encrypted_size);
    if (!encrypted_data) {
        printf("FAIL: Encryption failed\n");
        free(input_data);
        free(key_bytes);
        return 1;
    }
    
    if (!write_file(encrypted_file, encrypted_data, encrypted_size)) {
        printf("FAIL: Could not write encrypted file\n");
        free(input_data);
        free(encrypted_data);
        free(key_bytes);
        return 1;
    }
    
    // Decrypt
    size_t decrypted_size;
    unsigned char* decrypted_data = aes_ecb_decrypt(encrypted_data, encrypted_size, key_bytes, &decrypted_size);
    if (!decrypted_data) {
        printf("FAIL: Decryption failed\n");
        free(input_data);
        free(encrypted_data);
        free(key_bytes);
        return 1;
    }
    
    if (!write_file(decrypted_file, decrypted_data, decrypted_size)) {
        printf("FAIL: Could not write decrypted file\n");
        free(input_data);
        free(encrypted_data);
        free(decrypted_data);
        free(key_bytes);
        return 1;
    }
    
    // Verify
    if (files_identical(test_file, decrypted_file)) {
        printf("SUCCESS: Round-trip test passed!\n");
        printf("Original size: %zu, Encrypted size: %zu, Decrypted size: %zu\n", 
               input_size, encrypted_size, decrypted_size);
    } else {
        printf("FAIL: Original and decrypted files differ\n");
        printf("Original size: %zu, Decrypted size: %zu\n", input_size, decrypted_size);
    }
    
    // Cleanup
    free(input_data);
    free(encrypted_data);
    free(decrypted_data);
    free(key_bytes);
    
    remove(test_file);
    remove(encrypted_file);
    remove(decrypted_file);
    
    return 0;
}