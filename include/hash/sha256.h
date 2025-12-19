#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 32
#define SHA256_BUF_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char buffer[SHA256_BUF_SIZE];
    uint32_t buffer_len;
} CRYPTOCORE_SHA256_CTX;

void sha256_init(CRYPTOCORE_SHA256_CTX *ctx);
void sha256_update(CRYPTOCORE_SHA256_CTX *ctx, const unsigned char *data, size_t len);
void sha256_final(CRYPTOCORE_SHA256_CTX *ctx, unsigned char hash[SHA256_BLOCK_SIZE]);
void sha256(const unsigned char *data, size_t len, unsigned char hash[SHA256_BLOCK_SIZE]);
char* sha256_hex(const unsigned char *data, size_t len);
char* sha256_file(const char *filename);

#endif