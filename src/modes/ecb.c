#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/modes/ecb.h"

#define AES_BLOCK_SIZE 16

void pkcs7_pad(unsigned char** data, size_t* data_len) {
    size_t original_len = *data_len;
    size_t padding_len = AES_BLOCK_SIZE - (original_len % AES_BLOCK_SIZE);
    if (padding_len == 0) padding_len = AES_BLOCK_SIZE;
    
    size_t new_len = original_len + padding_len;
    unsigned char* new_data = malloc(new_len);
    if (new_data == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for padding\n");
        return;
    }
    
    // Copy original data
    if (original_len > 0 && *data != NULL) {
        memcpy(new_data, *data, original_len);
    }
    
    // Add padding
    for (size_t i = original_len; i < new_len; i++) {
        new_data[i] = (unsigned char)padding_len;
    }
    
    // Free old data and update pointers
    if (*data != NULL) {
        free(*data);
    }
    *data = new_data;
    *data_len = new_len;
}

int pkcs7_unpad(unsigned char** data, size_t* data_len) {
    if (*data_len == 0 || *data_len % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Invalid data length for unpadding\n");
        return 0;
    }
    
    unsigned char padding_byte = (*data)[*data_len - 1];
    if (padding_byte == 0 || padding_byte > AES_BLOCK_SIZE) {
        fprintf(stderr, "Error: Invalid padding byte: %d\n", padding_byte);
        return 0;
    }
    
    // Check if padding length is valid
    if (padding_byte > *data_len) {
        fprintf(stderr, "Error: Padding length exceeds data length\n");
        return 0;
    }
    
    // Verify all padding bytes
    for (size_t i = *data_len - padding_byte; i < *data_len; i++) {
        if ((*data)[i] != padding_byte) {
            fprintf(stderr, "Error: Invalid padding bytes at position %zu\n", i);
            return 0;
        }
    }
    
    *data_len -= padding_byte;
    return 1;
}