#ifndef HASH_H
#define HASH_H

#include "hash/sha256.h"
#include "hash/sha3_256.h"

typedef enum {
    HASH_SHA256,
    HASH_SHA3_256,
    HASH_UNKNOWN
} hash_algorithm_t;

hash_algorithm_t parse_hash_algorithm(const char *algorithm_str);
char* compute_hash(hash_algorithm_t algorithm, const char *filename);

#endif