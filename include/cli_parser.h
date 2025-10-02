#ifndef CLI_PARSER_H
#define CLI_PARSER_H

typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_UNKNOWN
} operation_mode_t;

typedef struct {
    operation_mode_t mode;
    char* algorithm;
    char* mode_str;
    unsigned char* key;
    size_t key_len;
    char* input_file;
    char* output_file;
} cli_args_t;

int parse_arguments(int argc, char* argv[], cli_args_t* args);
void free_cli_args(cli_args_t* args);
void print_usage(const char* program_name);
int hex_to_bytes(const char* hex_str, unsigned char** bytes, size_t* len);

#endif