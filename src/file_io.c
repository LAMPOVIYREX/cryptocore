#include <stdio.h>
#include <stdlib.h>

#include "../include/file_io.h"



unsigned char* read_file(const char* filename, size_t* file_size) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (size <= 0) {
        fprintf(stderr, "Error: Input file is empty or invalid\n");
        fclose(file);
        return NULL;
    }
    
    unsigned char* buffer = malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }
    
    size_t bytes_read = fread(buffer, 1, size, file);
    fclose(file);
    
    if (bytes_read != (size_t)size) {
        fprintf(stderr, "Error: Failed to read entire file\n");
        free(buffer);
        return NULL;
    }
    
    *file_size = bytes_read;
    return buffer;
}

int write_file(const char* filename, const unsigned char* data, size_t data_size) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", filename);
        return 0;
    }
    
    size_t bytes_written = fwrite(data, 1, data_size, file);
    fclose(file);
    
    if (bytes_written != data_size) {
        fprintf(stderr, "Error: Failed to write entire file\n");
        return 0;
    }
    
    return 1;
}