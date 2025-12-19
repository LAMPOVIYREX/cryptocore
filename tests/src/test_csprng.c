#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../include/csprng.h"

void test_key_uniqueness() {
    printf("Testing key uniqueness...\n");
    
    const int NUM_KEYS = 1000;
    char* keys[NUM_KEYS];
    
    // Generate 1000 keys
    for (int i = 0; i < NUM_KEYS; i++) {
        keys[i] = generate_random_key_hex(16);
        assert(keys[i] != NULL);
        
        // Check for duplicates
        for (int j = 0; j < i; j++) {
            if (strcmp(keys[i], keys[j]) == 0) {
                printf("ERROR: Duplicate key found at indices %d and %d: %s\n", i, j, keys[i]);
                exit(1);
            }
        }
    }
    
    printf("✓ Successfully generated %d unique keys\n", NUM_KEYS);
    
    // Cleanup
    for (int i = 0; i < NUM_KEYS; i++) {
        free(keys[i]);
    }
}

void test_basic_distribution() {
    printf("Testing basic distribution...\n");
    
    const int NUM_SAMPLES = 10000;
    const int KEY_LEN = 16;
    unsigned char buffer[KEY_LEN];
    
    int total_bits = NUM_SAMPLES * KEY_LEN * 8;
    int ones_count = 0;
    
    for (int i = 0; i < NUM_SAMPLES; i++) {
        assert(generate_random_bytes(buffer, KEY_LEN) == 0);
        
        for (int j = 0; j < KEY_LEN; j++) {
            unsigned char byte = buffer[j];
            ones_count += (byte & 0x01) + ((byte >> 1) & 0x01) + ((byte >> 2) & 0x01) + 
                         ((byte >> 3) & 0x01) + ((byte >> 4) & 0x01) + ((byte >> 5) & 0x01) + 
                         ((byte >> 6) & 0x01) + ((byte >> 7) & 0x01);
        }
    }
    
    double ratio = (double)ones_count / total_bits;
    printf("Bit ratio (1s/total): %.4f (should be close to 0.5)\n", ratio);
    
    // Check if ratio is reasonably close to 50%
    assert(ratio > 0.49 && ratio < 0.51);
    printf("✓ Basic distribution test passed\n");
}

void test_nist_preparation() {
    printf("Preparing data for NIST tests...\n");
    
    const size_t TOTAL_SIZE = 10000000; // 10 MB
    const size_t CHUNK_SIZE = 4096;
    unsigned char buffer[CHUNK_SIZE];
    
    FILE* f = fopen("tests/results/nist_test_data.bin", "wb");
    assert(f != NULL);
    
    size_t bytes_written = 0;
    while (bytes_written < TOTAL_SIZE) {
        size_t chunk = (TOTAL_SIZE - bytes_written < CHUNK_SIZE) ? 
                      TOTAL_SIZE - bytes_written : CHUNK_SIZE;
        
        assert(generate_random_bytes(buffer, chunk) == 0);
        size_t written = fwrite(buffer, 1, chunk, f);
        assert(written == chunk);
        
        bytes_written += written;
    }
    
    fclose(f);
    printf("✓ Generated %zu bytes for NIST testing in '../results/nist_test_data.bin'\n", bytes_written);
}

int main() {
    printf("=== CSPRNG Comprehensive Tests ===\n\n");
    
    test_key_uniqueness();
    printf("\n");
    
    test_basic_distribution();
    printf("\n");
    
    test_nist_preparation();
    printf("\n");
    
    printf("=== All CSPRNG tests passed! ===\n");
    return 0;
}