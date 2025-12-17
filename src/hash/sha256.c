#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../include/hash/sha256.h"

// SHA-256 константы (первые 32 бита дробных частей квадратных корней первых 8 простых чисел)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Правое вращение
#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))

// Мажоритарная функция
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

// Σ функции
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

// Инициализация контекста SHA-256
void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
    memset(ctx->buffer, 0, SHA256_BUF_SIZE);
}



// Обработка одного блока (512 бит = 64 байта)
static void sha256_transform(SHA256_CTX *ctx, const unsigned char data[SHA256_BUF_SIZE]) {
    uint32_t a, b, c, d, e, f, g, h, i, j;
    uint32_t w[64];
    uint32_t temp1, temp2;
    
    // Подготовка массива w
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
    }
    
    for (i = 16; i < 64; ++i) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }
    
    // Инициализация рабочих переменных
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    
    // Основной цикл
    for (i = 0; i < 64; ++i) {
        temp1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        temp2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    
    // Обновление состояния
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// Добавление данных в хеш
void sha256_update(SHA256_CTX *ctx, const unsigned char *data, size_t len) {
    uint32_t i;
    
    for (i = 0; i < len; ++i) {
        ctx->buffer[ctx->buffer_len] = data[i];
        ctx->buffer_len++;
        
        if (ctx->buffer_len == SHA256_BUF_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            ctx->bit_count += 512;
            ctx->buffer_len = 0;
        }
    }
}

// Завершение хеширования
void sha256_final(SHA256_CTX *ctx, unsigned char hash[SHA256_BLOCK_SIZE]) {
    uint32_t i;
    unsigned char bit_count_bits[8];
    
    // Преобразование bit_count в биты (big-endian)
    uint64_t bit_count = ctx->bit_count + (ctx->buffer_len * 8);
    for (i = 0; i < 8; ++i) {
        bit_count_bits[i] = (unsigned char)((bit_count >> (56 - i * 8)) & 0xFF);
    }
    
    // Добавление 1 бита
    unsigned char padding = 0x80;
    sha256_update(ctx, &padding, 1);
    
    // Добавление нулей до длины 448 бит (56 байт)
    padding = 0x00;
    while (ctx->buffer_len != 56) {
        sha256_update(ctx, &padding, 1);
    }
    
    // Добавление длины сообщения (64 бита)
    sha256_update(ctx, bit_count_bits, 8);
    
    // Преобразование состояния в байты (big-endian)
    for (i = 0; i < 8; ++i) {
        hash[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

// Удобная функция для хеширования данных
void sha256(const unsigned char *data, size_t len, unsigned char hash[SHA256_BLOCK_SIZE]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

// Преобразование хеша в hex-строку
char* sha256_hex(const unsigned char *data, size_t len) {
    unsigned char hash[SHA256_BLOCK_SIZE];
    char *hex_str = malloc(SHA256_BLOCK_SIZE * 2 + 1);
    
    if (!hex_str) return NULL;
    
    sha256(data, len, hash);
    
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(hex_str + i * 2, "%02x", hash[i]);
    }
    
    hex_str[SHA256_BLOCK_SIZE * 2] = '\0';
    return hex_str;
}

// Хеширование файла
char* sha256_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) return NULL;
    
    SHA256_CTX ctx;
    sha256_init(&ctx);
    
    unsigned char buffer[4096];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        sha256_update(&ctx, buffer, bytes_read);
    }
    
    fclose(file);
    
    unsigned char hash[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, hash);
    
    char *hex_str = malloc(SHA256_BLOCK_SIZE * 2 + 1);
    if (!hex_str) return NULL;
    
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(hex_str + i * 2, "%02x", hash[i]);
    }
    
    hex_str[SHA256_BLOCK_SIZE * 2] = '\0';
    return hex_str;
}