#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <stdlib.h>
#include "types.h"
#include "hash.h"
#include "mac/hmac.h"

typedef struct {
    operation_t operation;           // Основная операция
    cipher_mode_t cipher_mode;       // Режим шифрования
    hash_algorithm_t hash_algorithm; // Алгоритм хеширования
    
    char* algorithm;                 // Строковый алгоритм
    unsigned char* key;
    size_t key_len;
    char* input_file;
    char* output_file;
    
    unsigned char* iv;               // Для шифрования
    size_t iv_len;
    int iv_provided;
    
    unsigned char* aad;              // Для GCM
    size_t aad_len;
    
    char* generated_key_hex;
    
    // Для HMAC
    int hmac_mode;
    char* verify_file;
    int verify_mode;
    
    // Для GCM
    int gcm_mode;
    
} cli_args_t;

int parse_arguments(int argc, char* argv[], cli_args_t* args);
void free_cli_args(cli_args_t* args);
void print_usage(const char* program_name);
cipher_mode_t parse_cipher_mode(const char* mode_str);
int hex_to_bytes(const char* hex_str, unsigned char** bytes, size_t* len);

#endif