#ifndef CLI_PARSER_H
#define CLI_PARSER_H

#include <stdlib.h>
#include "types.h"

typedef struct {
    operation_mode_t operation;
    cipher_mode_t mode;
    char* algorithm;
    unsigned char* key;
    size_t key_len;
    char* input_file;
    char* output_file;
    unsigned char* iv;
    size_t iv_len;
    int iv_provided;
} cli_args_t;

int parse_arguments(int argc, char* argv[], cli_args_t* args);
void free_cli_args(cli_args_t* args);
void print_usage(const char* program_name);
cipher_mode_t parse_cipher_mode(const char* mode_str);

#endif