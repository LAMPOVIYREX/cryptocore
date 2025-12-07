#ifndef SHA3_256_H
#define SHA3_256_H

#include <openssl/evp.h>
#include <stddef.h>

char* sha3_256_hex(const unsigned char *data, size_t len);
char* sha3_256_file(const char *filename);

#endif