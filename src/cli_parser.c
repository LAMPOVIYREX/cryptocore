#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "../include/cli_parser.h"
#include "../include/csprng.h"
#include "../include/common.h"
#include "../include/hash.h"

// Helper function to parse crypto arguments (encryption/decryption)
static int parse_crypto_arguments(int argc, char* argv[], cli_args_t* args) {
    int encrypt_flag = 0;
    int decrypt_flag = 0;
    char* mode_str = NULL;
    
    // Start from i = 1, as argv[0] is program name
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
            args->operation = OPERATION_ENCRYPT;
        }
        else if (strcmp(argv[i], "-decrypt") == 0) {
            decrypt_flag = 1;
            args->operation = OPERATION_DECRYPT;
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
        else if (strcmp(argv[i], "-aad") == 0 && i + 1 < argc) {
            // Parse AAD for GCM mode (hex string)
            if (!hex_to_bytes(argv[i+1], &args->aad, &args->aad_len)) {
                if (mode_str) free(mode_str);
                return 0;
            }
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
        args->cipher_mode = parse_cipher_mode(mode_str);
        free(mode_str);
        
        // Check if it's GCM mode
        if (args->cipher_mode == CIPHER_MODE_GCM) {
            args->gcm_mode = 1;
        }
    }
    
    // Validate operation flags
    if (encrypt_flag && decrypt_flag) {
        fprintf(stderr, "Error: Cannot specify both -encrypt and -decrypt\n");
        return 0;
    }
    else if (!encrypt_flag && !decrypt_flag) {
        fprintf(stderr, "Error: Must specify either -encrypt or -decrypt for crypto mode\n");
        return 0;
    }
    
    // Validation
    if (args->algorithm == NULL || strcmp(args->algorithm, "aes") != 0) {
        fprintf(stderr, "Error: Algorithm must be 'aes' for crypto mode\n");
        return 0;
    }
    
    if (args->cipher_mode == CIPHER_MODE_UNKNOWN) {
        fprintf(stderr, "Error: Mode must be one of: ecb, cbc, cfb, ofb, ctr, gcm\n");
        return 0;
    }
    
    // KEY VALIDATION
    if (encrypt_flag && args->key == NULL) {
        // Generate random key
        char* generated_key_hex = generate_random_key_hex(16);
        if (generated_key_hex == NULL) {
            fprintf(stderr, "Error: Failed to generate random key\n");
            return 0;
        }
        
        // Parse generated key as regular hex
        if (!hex_to_bytes(generated_key_hex, &args->key, &args->key_len)) {
            free(generated_key_hex);
            return 0;
        }
        
        // Save hex representation for user output
        args->generated_key_hex = generated_key_hex;
    } else if (decrypt_flag && args->key == NULL) {
        // For decryption, key is mandatory
        fprintf(stderr, "Error: Key is required for decryption\n");
        return 0;
    } else if (args->key != NULL && args->key_len != 16) {
        fprintf(stderr, "Error: Key must be 16 bytes for AES-128\n");
        return 0;
    }
    
    // Check for weak keys (additional requirement)
    if (args->key != NULL && encrypt_flag && args->generated_key_hex == NULL) {
        int is_weak = 1;
        // Check if all bytes are identical
        for (size_t i = 1; i < args->key_len; i++) {
            if (args->key[i] != args->key[0]) {
                is_weak = 0;
                break;
            }
        }
        
        if (is_weak) {
            fprintf(stderr, "Warning: The provided key may be weak (all bytes identical)\n");
        }
        
        // Check for sequential bytes
        is_weak = 1;
        for (size_t i = 1; i < args->key_len; i++) {
            if (args->key[i] != args->key[i-1] + 1) {
                is_weak = 0;
                break;
            }
        }
        
        if (is_weak) {
            fprintf(stderr, "Warning: The provided key may be weak (sequential bytes)\n");
        }
    }
    
    if (args->input_file == NULL) {
        fprintf(stderr, "Error: Input file is required\n");
        return 0;
    }
    
    // IV validation
    if (encrypt_flag && args->iv_provided) {
        fprintf(stderr, "Warning: IV provided during encryption will be ignored (using random IV)\n");
        free(args->iv);
        args->iv = NULL;
        args->iv_provided = 0;
    }
    
    // For GCM mode, we use nonce instead of IV
    if (args->cipher_mode == CIPHER_MODE_GCM) {
        if (encrypt_flag) {
            // For GCM encryption, generate random nonce (handled in gcm.c)
        } else if (decrypt_flag && !args->iv_provided) {
            fprintf(stderr, "Warning: No nonce provided for GCM decryption, will read from file\n");
        }
    } else if (decrypt_flag && args->cipher_mode != CIPHER_MODE_ECB && !args->iv_provided) {
        fprintf(stderr, "Warning: No IV provided for decryption, will read from file\n");
    }
    
    if (args->iv_provided && args->iv_len != 16) {
        fprintf(stderr, "Error: IV must be 16 bytes\n");
        return 0;
    }
    
    // AAD validation for GCM
    if (args->aad != NULL && args->cipher_mode != CIPHER_MODE_GCM) {
        fprintf(stderr, "Warning: AAD provided for non-GCM mode, ignoring\n");
        free(args->aad);
        args->aad = NULL;
        args->aad_len = 0;
    }
    
    // Generate default output filename if not provided
    if (args->output_file == NULL) {
        const char* extension = (encrypt_flag) ? ".enc" : ".dec";
        size_t len = strlen(args->input_file) + strlen(extension) + 1;
        args->output_file = malloc(len);
        if (args->output_file) {
            snprintf(args->output_file, len, "%s%s", args->input_file, extension);
        }
    }
    
    return 1;
}

// Function to parse digest (hashing) arguments
static int parse_digest_arguments(int argc, char* argv[], cli_args_t* args) {
    int i = 2; // Skip "cryptocore" and "dgst"
    
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            args->hash_algorithm = parse_hash_algorithm(argv[i + 1]);
            if (args->hash_algorithm == HASH_UNKNOWN) {
                fprintf(stderr, "Error: Unknown hash algorithm '%s'. Supported: sha256, sha3-256\n", argv[i + 1]);
                return 0;
            }
            i++;
        }
        else if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            args->input_file = malloc(strlen(argv[i + 1]) + 1);
            if (args->input_file) strcpy(args->input_file, argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            args->output_file = malloc(strlen(argv[i + 1]) + 1);
            if (args->output_file) strcpy(args->output_file, argv[i + 1]);
            i++;
        }
        else {
            fprintf(stderr, "Error: Unknown argument '%s' for dgst command\n", argv[i]);
            return 0;
        }
    }
    
    // Validation
    if (args->hash_algorithm == HASH_UNKNOWN) {
        fprintf(stderr, "Error: Hash algorithm is required (--algorithm sha256|sha3-256)\n");
        return 0;
    }
    
    if (args->input_file == NULL) {
        fprintf(stderr, "Error: Input file is required (--input FILE)\n");
        return 0;
    }
    
    return 1;
}

// Function to parse HMAC arguments
static int parse_hmac_arguments(int argc, char* argv[], cli_args_t* args) {
    int i = 2; // Skip "cryptocore" and "dgst"
    args->operation = OPERATION_HMAC;
    
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            args->hash_algorithm = parse_hash_algorithm(argv[i + 1]);
            if (args->hash_algorithm == HASH_UNKNOWN) {
                fprintf(stderr, "Error: Unknown hash algorithm '%s'. Supported: sha256, sha3-256\n", argv[i + 1]);
                return 0;
            }
            i++;
        }
        else if (strcmp(argv[i], "--hmac") == 0) {
            args->hmac_mode = 1;
        }
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (!hex_to_bytes(argv[i + 1], &args->key, &args->key_len)) {
                fprintf(stderr, "Error: Invalid key format. Must be hexadecimal string.\n");
                return 0;
            }
            i++;
        }
        else if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            args->input_file = malloc(strlen(argv[i + 1]) + 1);
            if (args->input_file) strcpy(args->input_file, argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            args->output_file = malloc(strlen(argv[i + 1]) + 1);
            if (args->output_file) strcpy(args->output_file, argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--verify") == 0 && i + 1 < argc) {
            args->verify_mode = 1;
            args->verify_file = malloc(strlen(argv[i + 1]) + 1);
            if (args->verify_file) strcpy(args->verify_file, argv[i + 1]);
            i++;
        }
        else {
            fprintf(stderr, "Error: Unknown argument '%s' for HMAC command\n", argv[i]);
            return 0;
        }
    }
    
    // HMAC-specific validation
    if (!args->hmac_mode) {
        fprintf(stderr, "Error: HMAC mode requires --hmac flag\n");
        return 0;
    }
    
    if (args->key == NULL) {
        fprintf(stderr, "Error: Key is required for HMAC (--key HEX_KEY)\n");
        return 0;
    }
    
    if (args->hash_algorithm == HASH_UNKNOWN) {
        fprintf(stderr, "Error: Hash algorithm is required (--algorithm sha256|sha3-256)\n");
        return 0;
    }
    
    if (args->input_file == NULL) {
        fprintf(stderr, "Error: Input file is required (--input FILE)\n");
        return 0;
    }
    
    // Verify mode specific checks
    if (args->verify_mode && args->verify_file == NULL) {
        fprintf(stderr, "Error: Verify mode requires a verification file (--verify FILE)\n");
        return 0;
    }
    
    return 1;
}

// Function to parse KDF arguments (Sprint 7)
static int parse_kdf_arguments(int argc, char* argv[], cli_args_t* args) {
    int i = 2; // Skip "cryptocore" and "derive"
    args->operation = OPERATION_DERIVE;
    args->kdf_mode = 1;
    
    // Default values
    args->iterations = 100000;
    args->key_length = 32; // 256 bits
    
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            args->password = malloc(strlen(argv[i + 1]) + 1);
            if (args->password) strcpy(args->password, argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--salt") == 0 && i + 1 < argc) {
            args->salt = malloc(strlen(argv[i + 1]) + 1);
            if (args->salt) strcpy(args->salt, argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            args->iterations = atoi(argv[i + 1]);
            if (args->iterations < 1000) {
                fprintf(stderr, "Warning: Iteration count is very low (%u)\n", args->iterations);
            }
            if (args->iterations > 10000000) {
                fprintf(stderr, "Warning: Iteration count is very high (%u), may be slow\n", args->iterations);
            }
            i++;
        }
        else if (strcmp(argv[i], "--length") == 0 && i + 1 < argc) {
            args->key_length = atoi(argv[i + 1]);
            if (args->key_length < 16 || args->key_length > 64) {
                fprintf(stderr, "Error: Key length must be between 16 and 64 bytes\n");
                return 0;
            }
            i++;
        }
        else if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "pbkdf2") != 0) {
                fprintf(stderr, "Error: Only pbkdf2 algorithm is supported\n");
                return 0;
            }
            i++;
        }
        else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            args->output_file = malloc(strlen(argv[i + 1]) + 1);
            if (args->output_file) strcpy(args->output_file, argv[i + 1]);
            i++;
        }
        else {
            fprintf(stderr, "Error: Unknown argument '%s' for derive command\n", argv[i]);
            return 0;
        }
    }
    
    // Validation
    if (args->password == NULL) {
        fprintf(stderr, "Error: Password is required (--password PASSWORD)\n");
        return 0;
    }
    
    return 1;
}

void print_usage(const char* program_name) {
    fprintf(stderr, "CryptoCore - A Minimalist Cryptographic Provider\n");
    fprintf(stderr, "================================================\n\n");
    
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  Encryption/Decryption:\n");
    fprintf(stderr, "    %s -algorithm aes -mode [ecb|cbc|cfb|ofb|ctr|gcm] (-encrypt | -decrypt) \\\n", program_name);
    fprintf(stderr, "        [-key HEX_KEY] -input INPUT_FILE [-output OUTPUT_FILE] [-iv HEX_IV] [-aad HEX_AAD]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Hashing:\n");
    fprintf(stderr, "    %s dgst --algorithm [sha256|sha3-256] --input INPUT_FILE [--output OUTPUT_FILE]\n", program_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "  HMAC (Message Authentication):\n");
    fprintf(stderr, "    %s dgst --algorithm [sha256|sha3-256] --hmac --key HEX_KEY \\\n", program_name);
    fprintf(stderr, "        --input INPUT_FILE [--output OUTPUT_FILE] [--verify VERIFY_FILE]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Key Derivation (PBKDF2):\n");
    fprintf(stderr, "    %s derive --password PASSWORD [--salt HEX_SALT] [--iterations N] [--length L] [--output FILE]\n", program_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  Encryption with generated key: %s -algorithm aes -mode cbc -encrypt -input plain.txt -output cipher.bin\n", program_name);
    fprintf(stderr, "  GCM encryption with AAD: %s -algorithm aes -mode gcm -encrypt -key KEY -input plain.txt -output cipher.bin -aad AAD_HEX\n", program_name);
    fprintf(stderr, "  HMAC generation: %s dgst --algorithm sha256 --hmac --key KEY --input file.txt --output hmac.txt\n", program_name);
    fprintf(stderr, "  HMAC verification: %s dgst --algorithm sha256 --hmac --key KEY --input file.txt --verify expected_hmac.txt\n", program_name);
    fprintf(stderr, "  PBKDF2 with generated salt: %s derive --password \"my secret\" --iterations 100000\n", program_name);
    fprintf(stderr, "  PBKDF2 with specific salt: %s derive --password \"pass\" --salt a1b2c3d4 --length 32\n", program_name);
}

cipher_mode_t parse_cipher_mode(const char* mode_str) {
    if (strcmp(mode_str, "ecb") == 0) return CIPHER_MODE_ECB;
    if (strcmp(mode_str, "cbc") == 0) return CIPHER_MODE_CBC;
    if (strcmp(mode_str, "cfb") == 0) return CIPHER_MODE_CFB;
    if (strcmp(mode_str, "ofb") == 0) return CIPHER_MODE_OFB;
    if (strcmp(mode_str, "ctr") == 0) return CIPHER_MODE_CTR;
    if (strcmp(mode_str, "gcm") == 0) return CIPHER_MODE_GCM;
    return CIPHER_MODE_UNKNOWN;
}

int hex_to_bytes(const char* hex_str, unsigned char** bytes, size_t* len) {
    // No @ prefix check - keys and IVs accepted without prefix
    size_t hex_len = strlen(hex_str);
    
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
        if (sscanf(hex_str + 2*i, "%2hhx", &(*bytes)[i]) != 1) {
            fprintf(stderr, "Error: Invalid hexadecimal character at position %zu\n", 2*i);
            free(*bytes);
            *bytes = NULL;
            return 0;
        }
    }
    
    return 1;
}

int parse_arguments(int argc, char* argv[], cli_args_t* args) {
    memset(args, 0, sizeof(cli_args_t));
    args->operation = OPERATION_NONE;
    args->cipher_mode = CIPHER_MODE_UNKNOWN;
    args->hash_algorithm = HASH_UNKNOWN;
    
    // Check if we have at least one argument
    if (argc < 2) {
        print_usage(argv[0]);
        return 0;
    }
    
    // Check for subcommands
    if (strcmp(argv[1], "dgst") == 0) {
        // Check if HMAC mode is requested
        int hmac_requested = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--hmac") == 0) {
                hmac_requested = 1;
                break;
            }
        }
        
        if (hmac_requested) {
            return parse_hmac_arguments(argc, argv, args);
        } else {
            args->operation = OPERATION_DIGEST;
            return parse_digest_arguments(argc, argv, args);
        }
    } else if (strcmp(argv[1], "derive") == 0) {
        return parse_kdf_arguments(argc, argv, args);
    } else {
        // Encryption/decryption mode
        return parse_crypto_arguments(argc, argv, args);
    }
}

void free_cli_args(cli_args_t* args) {
    if (args->algorithm) free(args->algorithm);
    if (args->key) {
        memset(args->key, 0, args->key_len);
        free(args->key);
    }
    if (args->input_file) free(args->input_file);
    if (args->output_file) free(args->output_file);
    if (args->iv) {
        memset(args->iv, 0, args->iv_len);
        free(args->iv);
    }
    if (args->aad) {
        memset(args->aad, 0, args->aad_len);
        free(args->aad);
    }
    if (args->generated_key_hex) free(args->generated_key_hex);
    if (args->verify_file) free(args->verify_file);
    
    // KDF fields (Sprint 7)
    if (args->password) {
        memset(args->password, 0, strlen(args->password));
        free(args->password);
    }
    if (args->salt) {
        memset(args->salt, 0, strlen(args->salt));
        free(args->salt);
    }
}