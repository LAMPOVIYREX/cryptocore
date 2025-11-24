#ifndef CSPRNG_H
#define CSPRNG_H

#include <stdlib.h>

/**
 * @brief Generates cryptographically secure random bytes
 * 
 * @param buffer Output buffer for random bytes
 * @param num_bytes Number of bytes to generate
 * @return int 0 on success, -1 on error
 */
int generate_random_bytes(unsigned char *buffer, size_t num_bytes);

/**
 * @brief Generates a random key and returns it as hexadecimal string
 * 
 * @param key_len Length of key in bytes
 * @return char* Hexadecimal string (must be freed by caller), NULL on error
 */
char* generate_random_key_hex(size_t key_len);

#endif