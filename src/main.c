#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "../include/cli_parser.h"
#include "../include/file_io.h"
#include "../include/crypto.h"
#include "../include/common.h"
#include "../include/hash.h"
#include "../include/csprng.h"

// Вспомогательная функция для обработки шифрования/дешифрования
static int handle_crypto_operation(cli_args_t* args, int is_encrypt) {
    // Выводим сгенерированный ключ если он был создан
    if (args->generated_key_hex != NULL) {
        printf("Generated random key: %s\n", args->generated_key_hex);
    }
    
    // Read input file
    size_t input_size;
    unsigned char* input_data = read_file(args->input_file, &input_size);
    if (input_data == NULL) {
        return 0;
    }
    
    // Handle IV based on operation and mode
    unsigned char iv[16];
    const unsigned char* iv_ptr = NULL;
    size_t data_start = 0;
    size_t data_size = input_size;
    
    if (is_encrypt) {
        // Generate random IV for modes that need it
        if (args->cipher_mode != CIPHER_MODE_ECB) {
            if (generate_random_bytes(iv, 16) == 0) {
                iv_ptr = iv;
            } else {
                fprintf(stderr, "Error: Failed to generate IV\n");
                free(input_data);
                return 0;
            }
        }
    } else { // DECRYPT
        if (args->cipher_mode != CIPHER_MODE_ECB) {
            if (args->iv_provided) {
                // Use provided IV
                iv_ptr = args->iv;
            } else {
                // Read IV from file (first 16 bytes)
                if (input_size < 16) {
                    fprintf(stderr, "Error: Input file too short to contain IV\n");
                    free(input_data);
                    return 0;
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
    
    switch (args->cipher_mode) {
        case CIPHER_MODE_ECB:
            if (is_encrypt) {
                output_data = aes_ecb_encrypt(input_data + data_start, data_size, args->key, &output_size);
            } else {
                output_data = aes_ecb_decrypt(input_data + data_start, data_size, args->key, &output_size);
            }
            break;
        case CIPHER_MODE_CBC:
            if (is_encrypt) {
                output_data = aes_cbc_encrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            } else {
                output_data = aes_cbc_decrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            }
            break;
        case CIPHER_MODE_CFB:
            if (is_encrypt) {
                output_data = aes_cfb_encrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            } else {
                output_data = aes_cfb_decrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            }
            break;
        case CIPHER_MODE_OFB:
            if (is_encrypt) {
                output_data = aes_ofb_encrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            } else {
                output_data = aes_ofb_decrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            }
            break;
        case CIPHER_MODE_CTR:
            if (is_encrypt) {
                output_data = aes_ctr_encrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            } else {
                output_data = aes_ctr_decrypt(input_data + data_start, data_size, args->key, iv_ptr, &output_size);
            }
            break;
        default:
            fprintf(stderr, "Error: Unsupported mode\n");
            free(input_data);
            return 0;
    }
    
    free(input_data);
    
    if (output_data == NULL) {
        fprintf(stderr, "Error: Cryptographic operation failed\n");
        return 0;
    }
    
    // Prepare final output (with IV for encryption)
    if (is_encrypt && args->cipher_mode != CIPHER_MODE_ECB && iv_ptr != NULL) {
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
        return 0;
    }
    
    // Write output file
    if (!write_file(args->output_file, final_output, final_size)) {
        free(final_output);
        return 0;
    }
    
    printf("Success: %s -> %s\n", args->input_file, args->output_file);
    
    // Print IV info for encryption
    if (is_encrypt && args->cipher_mode != CIPHER_MODE_ECB && iv_ptr != NULL) {
        printf("Generated IV: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", iv_ptr[i]);
        }
        printf("\n");
    }
    
    free(final_output);
    return 1;
}

int main(int argc, char* argv[]) {
    cli_args_t args;
    
    if (!parse_arguments(argc, argv, &args)) {
        print_usage(argv[0]);
        free_cli_args(&args);
        return 1;
    }
    
    // Обработка режима хеширования
    if (args.operation_mode == MODE_DIGEST) {
        char* hash = NULL;
        const char* input_name = args.input_file;
        
        // Проверяем, является ли ввод stdin ("-")
        if (strcmp(args.input_file, "-") == 0) {
            hash = compute_hash_from_stdin(args.hash_algorithm);
            input_name = "-"; // Специальное имя для stdin
        } else {
            hash = compute_hash(args.hash_algorithm, args.input_file);
        }
        
        if (!hash) {
            fprintf(stderr, "Error: Failed to compute hash\n");
            free_cli_args(&args);
            return 1;
        }
        
        // Вывод результата в формате "HASH_VALUE  INPUT_FILE_PATH"
        if (args.output_file) {
            FILE* out = fopen(args.output_file, "w");
            if (!out) {
                fprintf(stderr, "Error: Cannot open output file '%s'\n", args.output_file);
                free(hash);
                free_cli_args(&args);
                return 1;
            }
            fprintf(out, "%s  %s\n", hash, input_name);
            fclose(out);
            printf("Hash written to: %s\n", args.output_file);
        } else {
            printf("%s  %s\n", hash, input_name);
        }
        
        free(hash);
        free_cli_args(&args);
        return 0;
    }
    
    // Обработка режима шифрования/дешифрования
    // Определяем, это шифрование или дешифрование
    // Проверяем аргументы командной строки
    int is_encrypt = 0;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-encrypt") == 0) {
            is_encrypt = 1;
            break;
        } else if (strcmp(argv[i], "-decrypt") == 0) {
            is_encrypt = 0;
            break;
        }
    }
    
    if (!handle_crypto_operation(&args, is_encrypt)) {
        free_cli_args(&args);
        return 1;
    }
    
    free_cli_args(&args);
    return 0;
}