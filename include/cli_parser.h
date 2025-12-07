#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <stdlib.h>
#include "types.h"
#include "hash.h"

typedef enum {
    MODE_ENCRYPT_DECRYPT,
    MODE_DIGEST,
    MODE_UNKNOWN
} operation_mode_t;

typedef struct {
    operation_mode_t operation_mode;  // Основной режим: шифрование или хеширование
    cipher_mode_t cipher_mode;        // Режим шифрования (только для MODE_ENCRYPT_DECRYPT)
    hash_algorithm_t hash_algorithm;  // Алгоритм хеширования (только для MODE_DIGEST)
    char* algorithm;                  // Строковый алгоритм
    unsigned char* key;
    size_t key_len;
    char* input_file;
    char* output_file;
    unsigned char* iv;
    size_t iv_len;
    int iv_provided;
    char* generated_key_hex;
    int verify_mode;                  // Для будущей HMAC-верификации
    char* verify_file;                // Файл для верификации
} cli_args_t;

int parse_arguments(int argc, char* argv[], cli_args_t* args);
void free_cli_args(cli_args_t* args);
void print_usage(const char* program_name);
cipher_mode_t parse_cipher_mode(const char* mode_str);
int hex_to_bytes(const char* hex_str, unsigned char** bytes, size_t* len);

#endif