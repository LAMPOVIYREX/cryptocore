#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "../../include/kdf.h"

void test_kdf_basic_functionality() {
    printf("=== Basic KDF Functionality Tests ===\n\n");
    
    // Test 1: Basic derivation
    printf("1. Testing basic PBKDF2 derivation... ");
    
    const char* password = "password";
    const char* salt = "73616c74"; // "salt" in hex
    unsigned int iterations = 1000;
    size_t key_len = 32;
    
    char* derived_key = pbkdf2_derive_hex(password, salt, iterations, key_len);
    
    if (derived_key) {
        printf("✅ PASS (got key: %.8s...)\n", derived_key);
        free(derived_key);
    } else {
        printf("❌ FAIL\n");
    }
    
    // Test 2: Different passwords give different keys
    printf("\n2. Testing password uniqueness... ");
    
    char* key1 = pbkdf2_derive_hex("password1", salt, iterations, key_len);
    char* key2 = pbkdf2_derive_hex("password2", salt, iterations, key_len);
    
    if (key1 && key2 && strcmp(key1, key2) != 0) {
        printf("✅ PASS (different passwords -> different keys)\n");
    } else {
        printf("❌ FAIL\n");
    }
    
    if (key1) free(key1);
    if (key2) free(key2);
    
    // Test 3: Empty password
    printf("\n3. Testing empty password... ");
    
    char* empty_key = pbkdf2_derive_hex("", salt, iterations, key_len);
    
    if (empty_key) {
        printf("✅ PASS (empty password handled)\n");
        free(empty_key);
    } else {
        printf("❌ FAIL\n");
    }
}

void test_determinism() {
    printf("\n=== Testing Determinism ===\n\n");
    
    const char* password = "test password";
    const char* salt = "a1b2c3d4e5f67890";
    unsigned int iterations = 1000;
    size_t key_len = 32;
    
    printf("Running same derivation 3 times...\n");
    
    char* keys[3];
    int all_identical = 1;
    
    for (int i = 0; i < 3; i++) {
        keys[i] = pbkdf2_derive_hex(password, salt, iterations, key_len);
        if (!keys[i]) {
            printf("  ❌ Iteration %d failed\n", i);
            all_identical = 0;
            break;
        }
        
        printf("  Run %d: %.8s...\n", i + 1, keys[i]);
        
        // Compare with previous runs
        for (int j = 0; j < i; j++) {
            if (strcmp(keys[i], keys[j]) != 0) {
                printf("  ❌ Run %d differs from run %d\n", i + 1, j + 1);
                all_identical = 0;
            }
        }
    }
    
    if (all_identical) {
        printf("  ✅ All runs produced identical keys\n");
    }
    
    // Cleanup
    for (int i = 0; i < 3; i++) {
        if (keys[i]) free(keys[i]);
    }
}

void test_salt_uniqueness() {
    printf("\n=== Testing Salt Uniqueness ===\n\n");
    
    const char* password = "same password";
    unsigned int iterations = 1000;
    size_t key_len = 32;
    
    char* salts[] = {
        "aaaaaaaaaaaaaaaa", // Salt 1
        "bbbbbbbbbbbbbbbb", // Salt 2  
        "cccccccccccccccc", // Salt 3
    };
    
    printf("Different salts should produce different keys:\n");
    
    char* keys[3];
    int all_unique = 1;
    
    for (int i = 0; i < 3; i++) {
        keys[i] = pbkdf2_derive_hex(password, salts[i], iterations, key_len);
        if (!keys[i]) {
            printf("  ❌ Failed with salt %d\n", i);
            all_unique = 0;
            break;
        }
        
        printf("  Salt %d (%s): %.8s...\n", i + 1, salts[i], keys[i]);
    }
    
    // Check for uniqueness
    for (int i = 0; i < 3 && all_unique; i++) {
        for (int j = i + 1; j < 3; j++) {
            if (keys[i] && keys[j] && strcmp(keys[i], keys[j]) == 0) {
                printf("  ❌ Keys %d and %d are identical!\n", i + 1, j + 1);
                all_unique = 0;
            }
        }
    }
    
    if (all_unique) {
        printf("  ✅ All keys are unique\n");
    }
    
    // Cleanup
    for (int i = 0; i < 3; i++) {
        if (keys[i]) free(keys[i]);
    }
}

void test_iteration_performance() {
    printf("\n=== Testing Iteration Performance ===\n\n");
    
    const char* password = "password";
    const char* salt = "73616c74";
    size_t key_len = 32;
    
    unsigned int test_iterations[] = {100, 1000, 10000};
    
    printf("Testing different iteration counts:\n");
    
    for (int i = 0; i < 3; i++) {
        clock_t start = clock();
        char* key = pbkdf2_derive_hex(password, salt, test_iterations[i], key_len);
        clock_t end = clock();
        
        double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
        
        if (key) {
            printf("  %6u iterations: %7.3f seconds (key: %.8s...)\n", 
                   test_iterations[i], time_taken, key);
            free(key);
        } else {
            printf("  ❌ Failed with %u iterations\n", test_iterations[i]);
        }
    }
}

void test_random_salt_generation() {
    printf("\n=== Testing Random Salt Generation ===\n\n");
    
    printf("Generating 3 random salts...\n");
    
    char* salts[3];
    int all_unique = 1;
    
    for (int i = 0; i < 3; i++) {
        salts[i] = generate_random_salt_hex(16); // 16 bytes = 128 bits
        if (!salts[i]) {
            printf("  ❌ Failed to generate salt %d\n", i + 1);
            all_unique = 0;
            break;
        }
        
        printf("  Salt %d: %s\n", i + 1, salts[i]);
    }
    
    // Check uniqueness
    for (int i = 0; i < 3 && all_unique; i++) {
        for (int j = i + 1; j < 3; j++) {
            if (strcmp(salts[i], salts[j]) == 0) {
                printf("  ❌ Salts %d and %d are identical!\n", i + 1, j + 1);
                all_unique = 0;
            }
        }
    }
    
    if (all_unique) {
        printf("  ✅ All salts are unique\n");
    }
    
    // Cleanup
    for (int i = 0; i < 3; i++) {
        if (salts[i]) free(salts[i]);
    }
}

int main() {
    printf("=== KDF Implementation Tests ===\n\n");
    
    test_kdf_basic_functionality();
    test_determinism();
    test_salt_uniqueness();
    test_iteration_performance();
    test_random_salt_generation();
    
    printf("\n=== All KDF tests completed ===\n");
    return 0;
}