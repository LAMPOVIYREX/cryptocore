#include <stdio.h>
#include <stdlib.h>
#include "../include/cli_parser.h"
#include "../include/file_io.h"
#include "../include/crypto.h"

int main(int argc, char* argv[]) {
    cli_args_t args;
    
    if (!parse_arguments(argc, argv, &args)) {
        print_usage(argv[0]);
        free_cli_args(&args);
        return 1;
    }
    
    // Read input file
    size_t input_size;
    unsigned char* input_data = read_file(args.input_file, &input_size);
    if (input_data == NULL) {
        free_cli_args(&args);
        return 1;
    }
    
    // Process data
    size_t output_size;
    unsigned char* output_data = NULL;
    
    if (args.mode == MODE_ENCRYPT) {
        output_data = aes_ecb_encrypt(input_data, input_size, args.key, &output_size);
    } else {
        output_data = aes_ecb_decrypt(input_data, input_size, args.key, &output_size);
    }
    
    free(input_data);
    
    if (output_data == NULL) {
        fprintf(stderr, "Error: Cryptographic operation failed\n");
        free_cli_args(&args);
        return 1;
    }
    
    // Write output file
    if (!write_file(args.output_file, output_data, output_size)) {
        free(output_data);
        free_cli_args(&args);
        return 1;
    }
    
    printf("Success: %s -> %s\n", args.input_file, args.output_file);
    
    free(output_data);
    free_cli_args(&args);
    return 0;
}