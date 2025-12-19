#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../include/hash.h"

void test_sha256_empty() {
    printf("Testing SHA-256 empty string... ");
    char* hash = sha256_hex((unsigned char*)"", 0);
    assert(hash != NULL);
    assert(strcmp(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    free(hash);
    printf("✓\n");
}

void test_sha256_abc() {
    printf("Testing SHA-256 'abc'... ");
    char* hash = sha256_hex((unsigned char*)"abc", 3);
    assert(hash != NULL);
    assert(strcmp(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    free(hash);
    printf("✓\n");
}

void test_sha3_256_empty() {
    printf("Testing SHA3-256 empty string... ");
    char* hash = sha3_256_hex((unsigned char*)"", 0);
    assert(hash != NULL);
    assert(strcmp(hash, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a") == 0);
    free(hash);
    printf("✓\n");
}

void test_file_hashing() {
    printf("Testing file hashing... ");
    
    // Создаем тестовый файл
    FILE* f = fopen("test_hash_file.txt", "w");
    assert(f != NULL);
    fprintf(f, "Hello, CryptoCore Hash!\n");
    fclose(f);
    
    // Тестируем SHA-256
    char* sha256_hash = sha256_file("test_hash_file.txt");
    assert(sha256_hash != NULL);
    
    // Тестируем SHA3-256
    char* sha3_hash = sha3_256_file("test_hash_file.txt");
    assert(sha3_hash != NULL);
    
    // Хеши должны быть разными
    assert(strcmp(sha256_hash, sha3_hash) != 0);
    
    free(sha256_hash);
    free(sha3_hash);
    remove("test_hash_file.txt");
    
    printf("✓\n");
}

int main() {
    printf("=== Hash Function Tests ===\n\n");
    
    test_sha256_empty();
    test_sha256_abc();
    test_sha3_256_empty();
    test_file_hashing();
    
    printf("\n=== All hash tests passed! ===\n");
    return 0;
}