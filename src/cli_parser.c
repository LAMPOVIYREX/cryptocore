#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "cli_parser.h"

void print_usage(const char* program_name) {
    fprintf(stderr, "Usage: %s -algorithm aes -mode [ecb|cbc|cfb|ofb|ctr] (-encrypt | -decrypt) -key @HEX_KEY -input INPUT_FILE [-output OUTPUT_FILE] [-iv @HEX_IV]\n", program_name);
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  Encryption: %s -algorithm aes -mode cbc -encrypt -key @00112233445566778899aabbccddeeff -input plain.txt -output cipher.bin\n", program_name);
    fprintf(stderr, "  Decryption: %s -algorithm aes -mode cbc -decrypt -key @00112233445566778899aabbccddeeff -iv @aabbccddeeff00112233445566778899 -input cipher.bin -output decrypted.txt\n", program_name);
    fprintf(stderr, "Supported modes: ecb, cbc, cfb, ofb, ctr\n");
}

cipher_mode_t parse_cipher_mode(const char* mode_str) {
    if (strcmp(mode_str, "ecb") == 0) return CIPHER_MODE_ECB;
    if (strcmp(mode_str, "cbc") == 0) return CIPHER_MODE_CBC;
    if (strcmp(mode_str, "cfb") == 0) return CIPHER_MODE_CFB;
    if (strcmp(mode_str, "ofb") == 0) return CIPHER_MODE_OFB;
    if (strcmp(mode_str, "ctr") == 0) return CIPHER_MODE_CTR;
    return CIPHER_MODE_UNKNOWN;
}

int hex_to_bytes(const char* hex_str, unsigned char** bytes, size_t* len) {
    if (hex_str[0] != '@') {
        fprintf(stderr, "Error: Hexadecimal value must start with '@' followed by hexadecimal characters\n");
        return 0;
    }
    
    const char* hex_data = hex_str + 1;
    size_t hex_len = strlen(hex_data);
    
    if (hex_len == 0 || hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hexadecimal value must have even number of digits\n");
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
            fprintf(stderr, "Error: Invalid hexadecimal character\n");
            free(*bytes);
            *bytes = NULL;
            return 0;
        }
    }
    
    return 1;
}

int parse_arguments(int argc, char* argv[], cli_args_t* args) {
    memset(args, 0, sizeof(cli_args_t));
    args->operation = MODE_UNKNOWN;
    args->mode = CIPHER_MODE_UNKNOWN;
    
    int encrypt_flag = 0;
    int decrypt_flag = 0;
    char* mode_str = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-algorithm") == 0 && i + 1 < argc) {
            args->algorithm = malloc(strlen(argv[i+1]) + 1);
            if (args->algorithm) strcpy(args->algorithm, argv[i+1]);
            i++;
        }
        else if (strcmp(argv[i], "-mode") == 0 && i + 1 < argc) {
            mode_str = malloc(strlen(argv[i+1]) + 1);
            if (mode_str) strcpy(mode_str, argv[i+1]);
            i++;
        }
        else if (strcmp(argv[i], "-encrypt") == 0) {
            encrypt_flag = 1;
        }
        else if (strcmp(argv[i], "-decrypt") == 0) {
            decrypt_flag = 1;
        }
        else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
            if (!hex_to_bytes(argv[i+1], &args->key, &args->key_len)) {
                if (mode_str) free(mode_str);
                return 0;
            }
            i++;
        }
        else if (strcmp(argv[i], "-iv") == 0 && i + 1 < argc) {
            if (!hex_to_bytes(argv[i+1], &args->iv, &args->iv_len)) {
                if (mode_str) free(mode_str);
                return 0;
            }
            args->iv_provided = 1;
            i++;
        }
        else if (strcmp(argv[i], "-input") == 0 && i + 1 < argc) {
            args->input_file = malloc(strlen(argv[i+1]) + 1);
            if (args->input_file) strcpy(args->input_file, argv[i+1]);
            i++;
        }
        else if (strcmp(argv[i], "-output") == 0 && i + 1 < argc) {
            args->output_file = malloc(strlen(argv[i+1]) + 1);
            if (args->output_file) strcpy(args->output_file, argv[i+1]);
            i++;
        }
        else {
            fprintf(stderr, "Error: Unknown argument '%s'\n", argv[i]);
            print_usage(argv[0]);
            if (mode_str) free(mode_str);
            return 0;
        }
    }
    
    // Parse cipher mode
    if (mode_str) {
        args->mode = parse_cipher_mode(mode_str);
        free(mode_str);
    }
    
    // Set operation mode based on flags
    if (encrypt_flag && decrypt_flag) {
        fprintf(stderr, "Error: Cannot specify both -encrypt and -decrypt\n");
        return 0;
    }
    else if (encrypt_flag) {
        args->operation = MODE_ENCRYPT;
    }
    else if (decrypt_flag) {
        args->operation = MODE_DECRYPT;
    }
    
    // Validation
    if (args->algorithm == NULL || strcmp(args->algorithm, "aes") != 0) {
        fprintf(stderr, "Error: Algorithm must be 'aes'\n");
        return 0;
    }
    
    if (args->mode == CIPHER_MODE_UNKNOWN) {
        fprintf(stderr, "Error: Mode must be one of: ecb, cbc, cfb, ofb, ctr\n");
        return 0;
    }
    
    if (args->operation == MODE_UNKNOWN) {
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
    
    // IV validation
    if (args->operation == MODE_ENCRYPT && args->iv_provided) {
        fprintf(stderr, "Warning: IV provided during encryption will be ignored (using random IV)\n");
        free(args->iv);
        args->iv = NULL;
        args->iv_provided = 0;
    }
    
    if (args->operation == MODE_DECRYPT && args->mode != CIPHER_MODE_ECB && !args->iv_provided) {
        fprintf(stderr, "Warning: No IV provided for decryption, will read from file\n");
    }
    
    if (args->iv_provided && args->iv_len != 16) {
        fprintf(stderr, "Error: IV must be 16 bytes\n");
        return 0;
    }
    
    if (args->output_file == NULL) {
        // Generate default output filename
        const char* extension = (args->operation == MODE_ENCRYPT) ? ".enc" : ".dec";
        size_t len = strlen(args->input_file) + strlen(extension) + 1;
        args->output_file = malloc(len);
        if (args->output_file) {
            snprintf(args->output_file, len, "%s%s", args->input_file, extension);
        }
    }
    
    return 1;
}

void free_cli_args(cli_args_t* args) {
    if (args->algorithm) free(args->algorithm);
    if (args->key) free(args->key);
    if (args->input_file) free(args->input_file);
    if (args->output_file) free(args->output_file);
    if (args->iv) free(args->iv);
}