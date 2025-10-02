#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/cli_parser.h"

// Добавьте свою реализацию strdup если ее нет
#ifndef _POSIX_C_SOURCE
char* strdup(const char* s) {
    size_t len = strlen(s) + 1;
    char* new_str = malloc(len);
    if (new_str) {
        memcpy(new_str, s, len);
    }
    return new_str;
}
#endif

void print_usage(const char* program_name) {
    fprintf(stderr, "Usage: %s -algorithm aes -mode ecb (-encrypt | -decrypt) -key @HEX_KEY -input INPUT_FILE [-output OUTPUT_FILE]\n", program_name);
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  Encryption: %s -algorithm aes -mode ecb -encrypt -key @00112233445566778899aabbccddeeff -input plain.txt -output cipher.bin\n", program_name);
    fprintf(stderr, "  Decryption: %s -algorithm aes -mode ecb -decrypt -key @00112233445566778899aabbccddeeff -input cipher.bin -output decrypted.txt\n", program_name);
}

int hex_to_bytes(const char* hex_str, unsigned char** bytes, size_t* len) {
    if (hex_str[0] != '@') {
        fprintf(stderr, "Error: Key must start with '@' followed by hexadecimal characters\n");
        return 0;
    }
    
    const char* hex_data = hex_str + 1;
    size_t hex_len = strlen(hex_data);
    
    if (hex_len == 0 || hex_len % 2 != 0) {
        fprintf(stderr, "Error: Key must have even number of hexadecimal digits\n");
        return 0;
    }
    
    *len = hex_len / 2;
    *bytes = malloc(*len);
    if (*bytes == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 0;
    }
    
    for (size_t i = 0; i < *len; i++) {
        if (sscanf(hex_data + 2*i, "%2hhx", &(*bytes)[i]) != 1) {
            fprintf(stderr, "Error: Invalid hexadecimal character in key\n");
            free(*bytes);
            *bytes = NULL;
            return 0;
        }
    }
    
    return 1;
}

int parse_arguments(int argc, char* argv[], cli_args_t* args) {
    memset(args, 0, sizeof(cli_args_t));
    args->mode = MODE_UNKNOWN;
    
    static struct option long_options[] = {
        {"algorithm", required_argument, 0, 'a'},
        {"mode", required_argument, 0, 'm'},
        {"encrypt", no_argument, 0, 'e'},
        {"decrypt", no_argument, 0, 'd'},
        {"key", required_argument, 0, 'k'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    // Используем getopt_long_only для поддержки как --input, так и -input
    while ((opt = getopt_long_only(argc, argv, "a:m:edk:i:o:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a':
                args->algorithm = strdup(optarg);
                break;
            case 'm':
                args->mode_str = strdup(optarg);
                break;
            case 'e':
                if (args->mode == MODE_DECRYPT) {
                    fprintf(stderr, "Error: Cannot specify both -encrypt and -decrypt\n");
                    return 0;
                }
                args->mode = MODE_ENCRYPT;
                break;
            case 'd':
                if (args->mode == MODE_ENCRYPT) {
                    fprintf(stderr, "Error: Cannot specify both -encrypt and -decrypt\n");
                    return 0;
                }
                args->mode = MODE_DECRYPT;
                break;
            case 'k':
                if (!hex_to_bytes(optarg, &args->key, &args->key_len)) {
                    return 0;
                }
                break;
            case 'i':
                args->input_file = strdup(optarg);
                break;
            case 'o':
                args->output_file = strdup(optarg);
                break;
            case '?':
                // Неизвестная опция
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 0;
        }
    }
    
    // Validation
    if (args->algorithm == NULL || strcmp(args->algorithm, "aes") != 0) {
        fprintf(stderr, "Error: Algorithm must be 'aes'\n");
        return 0;
    }
    
    if (args->mode_str == NULL || strcmp(args->mode_str, "ecb") != 0) {
        fprintf(stderr, "Error: Mode must be 'ecb'\n");
        return 0;
    }
    
    if (args->mode == MODE_UNKNOWN) {
        fprintf(stderr, "Error: Must specify either -encrypt or -decrypt\n");
        return 0;
    }
    
    if (args->key == NULL) {
        fprintf(stderr, "Error: Key is required\n");
        return 0;
    }
    
    if (args->key_len != 16) {
        fprintf(stderr, "Error: Key must be 16 bytes for AES-128\n");
        return 0;
    }
    
    if (args->input_file == NULL) {
        fprintf(stderr, "Error: Input file is required\n");
        return 0;
    }
    
    if (args->output_file == NULL) {
        // Generate default output filename
        const char* extension = (args->mode == MODE_ENCRYPT) ? ".enc" : ".dec";
        size_t len = strlen(args->input_file) + strlen(extension) + 1;
        args->output_file = malloc(len);
        snprintf(args->output_file, len, "%s%s", args->input_file, extension);
    }
    
    return 1;
}

void free_cli_args(cli_args_t* args) {
    if (args->algorithm) free(args->algorithm);
    if (args->mode_str) free(args->mode_str);
    if (args->key) free(args->key);
    if (args->input_file) free(args->input_file);
    if (args->output_file) free(args->output_file);
}