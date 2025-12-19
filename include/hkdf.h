#ifndef HKDF_H
#define HKDF_H

#include <stdlib.h>
#include "mac/hmac.h"

// HKDF implementation (RFC 5869)
int hkdf_extract(const unsigned char* salt, size_t salt_len,
                const unsigned char* ikm, size_t ikm_len,
                unsigned char* prk, size_t prk_len);

int hkdf_expand(const unsigned char* prk, size_t prk_len,
               const unsigned char* info, size_t info_len,
               unsigned char* okm, size_t okm_len);

int hkdf(const unsigned char* salt, size_t salt_len,
        const unsigned char* ikm, size_t ikm_len,
        const unsigned char* info, size_t info_len,
        unsigned char* okm, size_t okm_len);

#endif