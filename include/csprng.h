#ifndef CSPRNG_H
#define CSPRNG_H

#include <stdlib.h>

int generate_random_bytes(unsigned char *buffer, size_t num_bytes);
char* generate_random_key_hex(size_t key_len);

#endif