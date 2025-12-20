#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>

#include "../include/cli_parser.h"
#include "../include/file_io.h"
#include "../include/crypto.h"
#include "../include/common.h"
#include "../include/hash.h"
#include "../include/csprng.h"
#include "../include/mac/hmac.h"
#include "../include/modes/gcm.h"
#include "../include/kdf.h"

// Инициализация OpenSSL
static void init_openssl() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);
}

// Forward declarations
static int handle_gcm_operation(cli_args_t* args, int is_encrypt);
static unsigned char* read_file_from_stdin(size_t* file_size);
static int handle_kdf_operation(cli_args_t* args);

// Helper function to read from stdin
static unsigned char* read_file_from_stdin(size_t* file_size) {
    size_t buffer_size = 4096;
    unsigned char* buffer = malloc(buffer_size);
    if (!buffer) return NULL;
    
    size_t total_read = 0;
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer + total_read, 1, buffer_size - total_read, stdin)) > 0) {
        total_read += bytes_read;
        
        if (total_read == buffer_size) {
            buffer_size *= 2;
            unsigned char* new_buffer = realloc(buffer, buffer_size);
            if (!new_buffer) {
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
    }
    
    *file_size = total_read;
    return buffer;
}

// Function to handle GCM operations
static int handle_gcm_operation(cli_args_t* args, int is_encrypt) {
    // Read input file
    size_t input_size;
    unsigned char* input_data = read_file(args->input_file, &input_size);
    if (input_data == NULL) {
        return 0;
    }
    
    int result = 0;
    
    if (is_encrypt) {
        // Generate random nonce (12 bytes for GCM)
        unsigned char nonce[GCM_IV_SIZE];
        if (generate_random_bytes(nonce, GCM_IV_SIZE) != 0) {
            fprintf(stderr, "Error: Failed to generate nonce\n");
            free(input_data);
            return 0;
        }
        
        unsigned char* output = NULL;
        size_t output_len = 0;
        
        // Use default empty AAD if not provided
        const unsigned char* aad = (args->aad != NULL) ? args->aad : (unsigned char*)"";
        size_t aad_len = (args->aad != NULL) ? args->aad_len : 0;
        
        if (gcm_encrypt_full(args->key, args->key_len,
                            nonce, GCM_IV_SIZE,
                            input_data, input_size,
                            aad, aad_len,
                            &output, &output_len)) {
            
            // Write nonce + ciphertext + tag to output file
            if (write_file(args->output_file, output, output_len)) {
                printf("Success: %s -> %s\n", args->input_file, args->output_file);
                printf("Generated nonce: ");
                for (int i = 0; i < GCM_IV_SIZE; i++) {
                    printf("%02x", nonce[i]);
                }
                printf("\n");
                if (aad_len > 0) {
                    printf("AAD used: ");
                    for (size_t i = 0; i < aad_len; i++) {
                        printf("%02x", aad[i]);
                    }
                    printf("\n");
                }
                result = 1;
            }
            free(output);
        } else {
            fprintf(stderr, "Error: GCM encryption failed\n");
        }
    } else {
        // Decryption
        unsigned char* output = NULL;
        size_t output_len = 0;
        
        // Use default empty AAD if not provided
        const unsigned char* aad = (args->aad != NULL) ? args->aad : (unsigned char*)"";
        size_t aad_len = (args->aad != NULL) ? args->aad_len : 0;
        
        if (gcm_decrypt_full(args->key, args->key_len,
                            input_data, input_size,
                            aad, aad_len,
                            &output, &output_len)) {
            
            if (output && write_file(args->output_file, output, output_len)) {
                printf("Success: %s -> %s\n", args->input_file, args->output_file);
                result = 1;
            } else if (!output) {
                fprintf(stderr, "[ERROR] Decryption returned NULL output\n");
            }
            if (output) free(output);
        } else {
            fprintf(stderr, "[ERROR] Authentication failed: AAD mismatch or ciphertext tampered\n");
            // НЕ создавать output файл вообще!
            remove(args->output_file);
        }
    }
    
    free(input_data);
    return result;
}

// Helper function for crypto operations
static int handle_crypto_operation(cli_args_t* args, int is_encrypt) {
    // Print generated key if it was created
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
        if (args->cipher_mode != CIPHER_MODE_ECB && args->cipher_mode != CIPHER_MODE_GCM) {
            generate_random_iv(iv, 16);
            iv_ptr = iv;
        }
    } else { // DECRYPT
        if (args->cipher_mode != CIPHER_MODE_ECB && args->cipher_mode != CIPHER_MODE_GCM) {
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
        case CIPHER_MODE_GCM:
            return handle_gcm_operation(args, is_encrypt);
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
    if (is_encrypt && args->cipher_mode != CIPHER_MODE_ECB && args->cipher_mode != CIPHER_MODE_GCM && iv_ptr != NULL) {
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
    if (is_encrypt && args->cipher_mode != CIPHER_MODE_ECB && args->cipher_mode != CIPHER_MODE_GCM && iv_ptr != NULL) {
        printf("Generated IV: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", iv_ptr[i]);
        }
        printf("\n");
    }
    
    free(final_output);
    return 1;
}

// Function to handle digest operations
static int handle_digest_operation(cli_args_t* args) {
    char* hash = NULL;
    const char* input_name = args->input_file;
    
    // Check if input is stdin ("-")
    if (strcmp(args->input_file, "-") == 0) {
        // Read from stdin
        size_t data_len;
        unsigned char* data = read_file_from_stdin(&data_len);
        if (!data) {
            fprintf(stderr, "Error: Failed to read from stdin\n");
            return 0;
        }
        
        // Compute hash from data
        if (args->hash_algorithm == HASH_SHA256) {
            hash = sha256_hex(data, data_len);
        } else if (args->hash_algorithm == HASH_SHA3_256) {
            hash = sha3_256_hex(data, data_len);
        } else {
            fprintf(stderr, "Error: Unknown hash algorithm\n");
            free(data);
            return 0;
        }
        
        free(data);
        input_name = "-"; // Special name for stdin
    } else {
        // Read from file
        hash = compute_hash(args->hash_algorithm, args->input_file);
    }
    
    if (!hash) {
        fprintf(stderr, "Error: Failed to compute hash\n");
        return 0;
    }
    
    // Output result in format "HASH_VALUE  INPUT_FILE_PATH"
    if (args->output_file) {
        FILE* out = fopen(args->output_file, "w");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file '%s'\n", args->output_file);
            free(hash);
            return 0;
        }
        fprintf(out, "%s  %s\n", hash, input_name);
        fclose(out);
        printf("Hash written to: %s\n", args->output_file);
    } else {
        printf("%s  %s\n", hash, input_name);
    }
    
    free(hash);
    return 1;
}

// Function to handle HMAC operations
static int handle_hmac_operation(cli_args_t* args) {
    char* hmac_result = NULL;
    const char* input_name = args->input_file;
    
    if (strcmp(args->input_file, "-") == 0) {
        // Read from stdin
        size_t data_len;
        unsigned char* data = read_file_from_stdin(&data_len);
        if (!data) {
            fprintf(stderr, "Error: Failed to read from stdin\n");
            return 0;
        }
        
        hmac_result = hmac_compute_hex(args->key, args->key_len, 
                                      data, data_len, 
                                      args->hash_algorithm);
        free(data);
        input_name = "-";
    } else {
        // Read from file
        hmac_result = hmac_compute_file_hex(args->key, args->key_len,
                                           args->input_file, args->hash_algorithm);
    }
    
    if (!hmac_result) {
        fprintf(stderr, "Error: Failed to compute HMAC\n");
        return 0;
    }
    
    // Verification or output
    if (args->verify_mode && args->verify_file) {
        // Read expected HMAC from file
        size_t verify_size;
        unsigned char* verify_data = read_file(args->verify_file, &verify_size);
        if (!verify_data) {
            fprintf(stderr, "Error: Cannot read verify file '%s'\n", args->verify_file);
            free(hmac_result);
            return 0;
        }
        
        // Parse expected HMAC (format: HMAC_VALUE FILENAME)
        char expected_hex[65] = {0};
        sscanf((char*)verify_data, "%64s", expected_hex);
        free(verify_data);
        
        if (strcmp(hmac_result, expected_hex) == 0) {
            printf("[OK] HMAC verification successful\n");
            free(hmac_result);
            return 1;
        } else {
            fprintf(stderr, "[ERROR] HMAC verification failed\n");
            free(hmac_result);
            return 0;
        }
    } else {
        // Output HMAC
        if (args->output_file) {
            FILE* out = fopen(args->output_file, "w");
            if (!out) {
                fprintf(stderr, "Error: Cannot open output file '%s'\n", args->output_file);
                free(hmac_result);
                return 0;
            }
            fprintf(out, "%s  %s\n", hmac_result, input_name);
            fclose(out);
            printf("HMAC written to: %s\n", args->output_file);
        } else {
            printf("%s  %s\n", hmac_result, input_name);
        }
        free(hmac_result);
        return 1;
    }
}

// Function to handle KDF operations (Sprint 7)
static int handle_kdf_operation(cli_args_t* args) {
    printf("=== PBKDF2 Key Derivation ===\n\n");
    
    char* salt_hex = args->salt;
    char* generated_salt = NULL;
    
    // Generate random salt if not provided
    if (salt_hex == NULL) {
        generated_salt = generate_random_salt_hex(16); // 16 bytes = 128 bits
        if (!generated_salt) {
            fprintf(stderr, "Error: Failed to generate random salt\n");
            return 0;
        }
        salt_hex = generated_salt;
        printf("Generated random salt: %s\n", salt_hex);
    }
    
    printf("Password length: %zu characters\n", strlen(args->password));
    printf("Salt (hex): %s\n", salt_hex);
    printf("Iterations: %u\n", args->iterations);
    printf("Derived key length: %zu bytes (%zu bits)\n", 
           args->key_length, args->key_length * 8);
    
    // Show security warnings
    if (args->iterations < 10000) {
        printf("⚠️  Warning: Low iteration count. Consider at least 100,000 iterations for security.\n");
    }
    if (args->key_length < 32) {
        printf("⚠️  Warning: Key length less than 32 bytes (256 bits). Consider using at least 32 bytes.\n");
    }
    
    clock_t start = clock();
    
    // Derive key using PBKDF2
    char* derived_key_hex = pbkdf2_derive_hex(args->password, salt_hex,
                                             args->iterations, args->key_length);
    
    clock_t end = clock();
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    if (!derived_key_hex) {
        fprintf(stderr, "Error: Key derivation failed\n");
        if (generated_salt) free(generated_salt);
        return 0;
    }
    
    printf("Derivation time: %.3f seconds\n", time_taken);
    printf("\n=== Derived Key ===\n");
    printf("Key (hex): %s\n", derived_key_hex);
    
    // Show first and last 8 bytes for verification
    if (strlen(derived_key_hex) >= 32) {
        char first_part[17] = {0};
        char last_part[17] = {0};
        strncpy(first_part, derived_key_hex, 16);
        strncpy(last_part, derived_key_hex + strlen(derived_key_hex) - 16, 16);
        printf("First 8 bytes: %s...\n", first_part);
        printf("Last 8 bytes: ...%s\n", last_part);
    }
    
    // Save to file if output specified
    if (args->output_file) {
        FILE* out = fopen(args->output_file, "w");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file '%s'\n", args->output_file);
            free(derived_key_hex);
            if (generated_salt) free(generated_salt);
            return 0;
        }
        
        fprintf(out, "# PBKDF2-HMAC-SHA256 Derived Key\n");
        fprintf(out, "# Generated by CryptoCore\n");
        fprintf(out, "# Date: %s", ctime(&(time_t){time(NULL)}));
        fprintf(out, "\n");
        fprintf(out, "Password: %s\n", args->password);
        fprintf(out, "Salt: %s\n", salt_hex);
        fprintf(out, "Iterations: %u\n", args->iterations);
        fprintf(out, "Key length: %zu bytes\n", args->key_length);
        fprintf(out, "Derivation time: %.3f seconds\n", time_taken);
        fprintf(out, "\n");
        fprintf(out, "Derived key: %s\n", derived_key_hex);
        fclose(out);
        
        printf("✓ Key saved to: %s\n", args->output_file);
    }
    
    // Example of how to use the derived key
    printf("\n=== Usage Example ===\n");
    printf("To use this key for AES encryption:\n");
    printf("  ./bin/cryptocore -algorithm aes -mode gcm -encrypt \\\n");
    printf("    -key %.*s \\\n", 32, derived_key_hex); // Show first 32 chars
    printf("    -input your_file.txt -output encrypted.bin\n");
    
    // Cleanup
    free(derived_key_hex);
    if (generated_salt) free(generated_salt);
    
    return 1;
}

int main(int argc, char* argv[]) {
    // Инициализируем OpenSSL
    init_openssl();
    
    cli_args_t args;
    
    if (!parse_arguments(argc, argv, &args)) {
        print_usage(argv[0]);
        free_cli_args(&args);
        return 1;
    }
    
    // Handle different operations
    int result = 0;
    
    switch(args.operation) {
        case OPERATION_DIGEST:
            result = handle_digest_operation(&args);
            break;
            
        case OPERATION_HMAC:
            result = handle_hmac_operation(&args);
            break;
            
        case OPERATION_DERIVE:
            result = handle_kdf_operation(&args);
            break;
            
        case OPERATION_ENCRYPT:
            if (args.gcm_mode) {
                result = handle_gcm_operation(&args, 1);
            } else {
                result = handle_crypto_operation(&args, 1);
            }
            break;
            
        case OPERATION_DECRYPT:
            if (args.gcm_mode) {
                result = handle_gcm_operation(&args, 0);
            } else {
                result = handle_crypto_operation(&args, 0);
            }
            break;
            
        default:
            fprintf(stderr, "Error: Unknown operation\n");
            result = 0;
            break;
    }
    
    free_cli_args(&args);
    return result ? 0 : 1;
}