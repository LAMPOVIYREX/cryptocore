#ifndef KDF_H
#define KDF_H

#include <stdlib.h>
#include <time.h>

#define PBKDF2_MAX_ITERATIONS 1000000
#define PBKDF2_DEFAULT_ITERATIONS 100000
#define PBKDF2_MIN_ITERATIONS 1000

// PBKDF2-HMAC-SHA256 implementation
int pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len,
                      const unsigned char* salt, size_t salt_len,
                      unsigned int iterations,
                      unsigned char* derived_key, size_t dklen);

// High-level PBKDF2 function with hex output
char* pbkdf2_derive_hex(const char* password, const char* salt_hex,
                        unsigned int iterations, size_t key_len);

// Hierarchical key derivation (HKDF-like)
int derive_key_from_master(const unsigned char* master_key, size_t master_key_len,
                          const char* context, size_t context_len,
                          unsigned char* derived_key, size_t derived_key_len);

// Generate random salt
unsigned char* generate_random_salt(size_t salt_len);
char* generate_random_salt_hex(size_t salt_len);

#endif