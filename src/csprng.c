#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "csprng.h"

int generate_random_bytes(unsigned char *buffer, size_t num_bytes) {
    if (buffer == NULL || num_bytes == 0) {
        fprintf(stderr, "Error: Invalid parameters for random generation\n");
        return -1;
    }
    
    if (RAND_bytes(buffer, num_bytes) != 1) {
        fprintf(stderr, "Error: Cryptographically secure random generation failed\n");
        return -1;
    }
    
    return 0;
}

char* generate_random_key_hex(size_t key_len) {
    unsigned char* key_bytes = malloc(key_len);
    if (key_bytes == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for key generation\n");
        return NULL;
    }
    
    if (generate_random_bytes(key_bytes, key_len) != 0) {
        free(key_bytes);
        return NULL;
    }
    
    // Convert to hexadecimal string (БЕЗ @ в начале!)
    char* hex_string = malloc(key_len * 2 + 1); // +1 for null terminator
    if (hex_string == NULL) {
        free(key_bytes);
        return NULL;
    }
    
    for (size_t i = 0; i < key_len; i++) {
        sprintf(hex_string + i * 2, "%02x", key_bytes[i]);
    }
    
    free(key_bytes);
    return hex_string;
}