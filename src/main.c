#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cli_parser.h"
#include "file_io.h"
#include "crypto.h"
#include "common.h"
#include "types.h"

int main(int argc, char* argv[]) {
    cli_args_t args;
    
    if (!parse_arguments(argc, argv, &args)) {
        print_usage(argv[0]);
        free_cli_args(&args);
        return 1;
    }
    
    // Выводим сгенерированный ключ если он был создан
    if (args.operation == MODE_ENCRYPT && args.generated_key_hex != NULL) {
        printf("Generated random key: %s\n", args.generated_key_hex);
    }
    
    // Read input file
    size_t input_size;
    unsigned char* input_data = read_file(args.input_file, &input_size);
    if (input_data == NULL) {
        free_cli_args(&args);
        return 1;
    }
    
    // Handle IV based on operation and mode
    unsigned char iv[16];
    const unsigned char* iv_ptr = NULL;
    size_t data_start = 0;
    size_t data_size = input_size;
    
    if (args.operation == MODE_ENCRYPT) {
        // Generate random IV for modes that need it
        if (args.mode != CIPHER_MODE_ECB) {
            generate_random_iv(iv, 16);
            iv_ptr = iv;
        }
    } else { // DECRYPT
        if (args.mode != CIPHER_MODE_ECB) {
            if (args.iv_provided) {
                // Use provided IV
                iv_ptr = args.iv;
            } else {
                // Read IV from file (first 16 bytes)
                if (input_size < 16) {
                    fprintf(stderr, "Error: Input file too short to contain IV\n");
                    free(input_data);
                    free_cli_args(&args);
                    return 1;
                }
                iv_ptr = input_data;
                data_start = 16;
                data_size = input_size - 16;
            }
        }
    }
    
    // Process data
    size_t output_size;
    unsigned char* output_data = NULL;
    unsigned char* final_output = NULL;
    size_t final_size = 0;
    
    switch (args.mode) {
        case CIPHER_MODE_ECB:
            if (args.operation == MODE_ENCRYPT) {
                output_data = aes_ecb_encrypt(input_data + data_start, data_size, args.key, &output_size);
            } else {
                output_data = aes_ecb_decrypt(input_data + data_start, data_size, args.key, &output_size);
            }
            break;
        case CIPHER_MODE_CBC:
            if (args.operation == MODE_ENCRYPT) {
                output_data = aes_cbc_encrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            } else {
                output_data = aes_cbc_decrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            }
            break;
        case CIPHER_MODE_CFB:
            if (args.operation == MODE_ENCRYPT) {
                output_data = aes_cfb_encrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            } else {
                output_data = aes_cfb_decrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            }
            break;
        case CIPHER_MODE_OFB:
            if (args.operation == MODE_ENCRYPT) {
                output_data = aes_ofb_encrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            } else {
                output_data = aes_ofb_decrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            }
            break;
        case CIPHER_MODE_CTR:
            if (args.operation == MODE_ENCRYPT) {
                output_data = aes_ctr_encrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            } else {
                output_data = aes_ctr_decrypt(input_data + data_start, data_size, args.key, iv_ptr, &output_size);
            }
            break;
        default:
            fprintf(stderr, "Error: Unsupported mode\n");
            free(input_data);
            free_cli_args(&args);
            return 1;
    }
    
    free(input_data);
    
    if (output_data == NULL) {
        fprintf(stderr, "Error: Cryptographic operation failed\n");
        free_cli_args(&args);
        return 1;
    }
    
    // Prepare final output (with IV for encryption)
    if (args.operation == MODE_ENCRYPT && args.mode != CIPHER_MODE_ECB && iv_ptr != NULL) {
        final_size = 16 + output_size;
        final_output = malloc(final_size);
        if (final_output) {
            memcpy(final_output, iv_ptr, 16);
            memcpy(final_output + 16, output_data, output_size);
        }
        free(output_data);
    } else {
        final_output = output_data;
        final_size = output_size;
    }
    
    if (final_output == NULL) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free_cli_args(&args);
        return 1;
    }
    
    // Write output file
    if (!write_file(args.output_file, final_output, final_size)) {
        free(final_output);
        free_cli_args(&args);
        return 1;
    }
    
    printf("Success: %s -> %s\n", args.input_file, args.output_file);
    
    // Print IV info for encryption
    if (args.operation == MODE_ENCRYPT && args.mode != CIPHER_MODE_ECB && iv_ptr != NULL) {
        printf("Generated IV: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", iv_ptr[i]);
        }
        printf("\n");
    }
    
    free(final_output);
    free_cli_args(&args);
    return 0;
}