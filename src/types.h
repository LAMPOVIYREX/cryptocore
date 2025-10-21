#ifndef TYPES_H
#define TYPES_H

typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT,
    MODE_UNKNOWN
} operation_mode_t;

typedef enum {
    CIPHER_MODE_ECB,
    CIPHER_MODE_CBC,
    CIPHER_MODE_CFB,
    CIPHER_MODE_OFB,
    CIPHER_MODE_CTR,
    CIPHER_MODE_UNKNOWN
} cipher_mode_t;

#endif