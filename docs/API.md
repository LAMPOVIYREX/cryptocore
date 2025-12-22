# CryptoCore API Documentation

## Обзор

CryptoCore предоставляет комплексный API для криптографических операций, реализованный на языке C. Все функции используют стандартные типы данных и следуют принципам безопасности.

## Структура API

### 1. Основные типы данных

```c
// Типы операций
typedef enum {
    OPERATION_NONE,
    OPERATION_ENCRYPT,
    OPERATION_DECRYPT,
    OPERATION_DIGEST,
    OPERATION_HMAC,
    OPERATION_VERIFY,
    OPERATION_DERIVE
} operation_t;

// Режимы шифрования
typedef enum {
    CIPHER_MODE_ECB,
    CIPHER_MODE_CBC,
    CIPHER_MODE_CFB,
    CIPHER_MODE_OFB,
    CIPHER_MODE_CTR,
    CIPHER_MODE_GCM,
    CIPHER_MODE_UNKNOWN
} cipher_mode_t;

// Алгоритмы хеширования
typedef enum {
    HASH_SHA256,
    HASH_SHA3_256,
    HASH_UNKNOWN
} hash_algorithm_t;
```

### 2. CSPRNG (Криптографически стойкий генератор случайных чисел)

#### `generate_random_bytes()`
```c
/**
 * Генерирует криптографически стойкие случайные байты
 * 
 * @param buffer Буфер для записи случайных данных
 * @param num_bytes Количество байт для генерации
 * @return 0 при успехе, -1 при ошибке
 */
int generate_random_bytes(unsigned char *buffer, size_t num_bytes);
```

#### `generate_random_key_hex()`
```c
/**
 * Генерирует случайный ключ в формате hex
 * 
 * @param key_len Длина ключа в байтах (обычно 16 для AES-128)
 * @return Указатель на строку с hex-ключом (нужно освободить через free())
 */
char* generate_random_key_hex(size_t key_len);
```

### 3. Шифрование/Дешифрование

#### Базовые функции AES
```c
/**
 * Шифрует блок AES-128 (16 байт)
 * 
 * @param input Входной блок (16 байт)
 * @param output Выходной блок (16 байт)
 * @param key Ключ AES-128 (16 байт)
 */
void aes_encrypt_block(const unsigned char* input, 
                       unsigned char* output, 
                       const unsigned char* key);

/**
 * Дешифрует блок AES-128 (16 байт)
 * 
 * @param input Входной блок (16 байт)
 * @param output Выходной блок (16 байт)
 * @param key Ключ AES-128 (16 байт)
 */
void aes_decrypt_block(const unsigned char* input, 
                       unsigned char* output, 
                       const unsigned char* key);
```

#### Режимы шифрования
```c
// ECB режим
unsigned char* aes_ecb_encrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, size_t* output_len);
unsigned char* aes_ecb_decrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, size_t* output_len);

// CBC режим
unsigned char* aes_cbc_encrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);
unsigned char* aes_cbc_decrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);

// CFB режим
unsigned char* aes_cfb_encrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);
unsigned char* aes_cfb_decrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);

// OFB режим
unsigned char* aes_ofb_encrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);
unsigned char* aes_ofb_decrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);

// CTR режим
unsigned char* aes_ctr_encrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);
unsigned char* aes_ctr_decrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len);
```

### 4. Хеширование

#### SHA-256 (реализация с нуля)
```c
/**
 * Контекст SHA-256
 */
typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char buffer[64];
    uint32_t buffer_len;
} CRYPTOCORE_SHA256_CTX;

// Инициализация
void sha256_init(CRYPTOCORE_SHA256_CTX *ctx);

// Обновление данных
void sha256_update(CRYPTOCORE_SHA256_CTX *ctx, 
                   const unsigned char *data, 
                   size_t len);

// Финальный расчет
void sha256_final(CRYPTOCORE_SHA256_CTX *ctx, 
                  unsigned char hash[32]);

// Удобная функция для данных в памяти
char* sha256_hex(const unsigned char *data, size_t len);

// Функция для файлов
char* sha256_file(const char *filename);
```

#### SHA3-256 (через OpenSSL)
```c
/**
 * Вычисляет SHA3-256 хеш для данных в памяти
 * 
 * @param data Указатель на данные
 * @param len Длина данных
 * @return Hex-строка с хешем (нужно освободить через free())
 */
char* sha3_256_hex(const unsigned char *data, size_t len);

/**
 * Вычисляет SHA3-256 хеш для файла
 * 
 * @param filename Путь к файлу
 * @return Hex-строка с хешем (нужно освободить через free())
 */
char* sha3_256_file(const char *filename);
```

### 5. HMAC (Message Authentication Code)

#### Контекст HMAC
```c
typedef struct {
    unsigned char* key;
    size_t key_len;
    hash_algorithm_t hash_algo;
    unsigned char* ipad;
    unsigned char* opad;
    size_t block_size;
    
    // Контексты для streaming HMAC
    void* sha256_inner_ctx;
    void* sha256_outer_ctx;
    EVP_MD_CTX* sha3_inner_ctx;
    EVP_MD_CTX* sha3_outer_ctx;
} CRYPTOCORE_HMAC_CTX;
```

#### Основные функции HMAC
```c
/**
 * Инициализирует контекст HMAC
 * 
 * @param key Ключ HMAC
 * @param key_len Длина ключа
 * @param hash_algo Алгоритм хеширования
 * @return Указатель на контекст HMAC
 */
CRYPTOCORE_HMAC_CTX* hmac_init(const unsigned char* key, size_t key_len, 
                               hash_algorithm_t hash_algo);

/**
 * Обновляет HMAC новыми данными
 */
void hmac_update(CRYPTOCORE_HMAC_CTX* ctx, 
                 const unsigned char* data, 
                 size_t data_len);

/**
 * Завершает вычисление HMAC
 */
void hmac_final(CRYPTOCORE_HMAC_CTX* ctx, 
                unsigned char* output);

/**
 * Освобождает ресурсы HMAC
 */
void hmac_cleanup(CRYPTOCORE_HMAC_CTX* ctx);

/**
 * Вычисляет HMAC для данных в памяти
 */
char* hmac_compute_hex(const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       hash_algorithm_t hash_algo);
```

### 6. GCM (Galois/Counter Mode)

#### Контекст GCM
```c
typedef struct {
    unsigned char* key;
    size_t key_len;
    unsigned char* nonce;
    size_t nonce_len;
} GCM_CTX;
```

#### Основные функции GCM
```c
/**
 * Инициализирует контекст GCM
 */
GCM_CTX* gcm_init(const unsigned char* key, size_t key_len);

/**
 * Устанавливает nonce для GCM
 */
void gcm_set_nonce(GCM_CTX* ctx, 
                   const unsigned char* nonce, 
                   size_t nonce_len);

/**
 * Генерирует случайный nonce
 */
void gcm_generate_nonce(GCM_CTX* ctx);

/**
 * Шифрование в режиме GCM
 */
int gcm_encrypt(GCM_CTX* ctx,
                const unsigned char* plaintext, size_t plaintext_len,
                const unsigned char* aad, size_t aad_len,
                unsigned char* ciphertext,
                unsigned char* tag);

/**
 * Дешифрование в режиме GCM
 */
int gcm_decrypt(GCM_CTX* ctx,
                const unsigned char* ciphertext, size_t ciphertext_len,
                const unsigned char* aad, size_t aad_len,
                const unsigned char* tag,
                unsigned char* plaintext);
```

### 7. KDF (Key Derivation Functions)

#### PBKDF2-HMAC-SHA256
```c
/**
 * Вычисляет PBKDF2-HMAC-SHA256
 * 
 * @param password Пароль
 * @param password_len Длина пароля
 * @param salt Соль
 * @param salt_len Длина соли
 * @param iterations Количество итераций
 * @param derived_key Буфер для производного ключа
 * @param dklen Длина производного ключа
 * @return 1 при успехе, 0 при ошибке
 */
int pbkdf2_hmac_sha256(const unsigned char* password, size_t password_len,
                       const unsigned char* salt, size_t salt_len,
                       unsigned int iterations,
                       unsigned char* derived_key, size_t dklen);

/**
 * Генерирует случайную соль в hex формате
 */
char* generate_random_salt_hex(size_t salt_len);
```

### 8. Утилиты

#### Работа с файлами
```c
/**
 * Читает файл в память
 * 
 * @param filename Имя файла
 * @param file_size Указатель для сохранения размера файла
 * @return Указатель на данные файла (нужно освободить через free())
 */
unsigned char* read_file(const char* filename, size_t* file_size);

/**
 * Записывает данные в файл
 * 
 * @param filename Имя файла
 * @param data Указатель на данные
 * @param data_size Размер данных
 * @return 1 при успехе, 0 при ошибке
 */
int write_file(const char* filename, 
               const unsigned char* data, 
               size_t data_size);
```

#### Padding
```c
/**
 * Добавляет PKCS#7 padding
 */
void pkcs7_pad(unsigned char** data, size_t* data_len);

/**
 * Удаляет PKCS#7 padding
 */
int pkcs7_unpad(unsigned char** data, size_t* data_len);
```

#### Утилиты преобразования
```c
/**
 * Преобразует hex строку в байты
 * 
 * @param hex_str Hex строка (без префикса)
 * @param bytes Указатель на буфер для байтов (выделяется внутри)
 * @param len Указатель для сохранения длины
 * @return 1 при успехе, 0 при ошибке
 */
int hex_to_bytes(const char* hex_str, unsigned char** bytes, size_t* len);

/**
 * Преобразует байты в hex строку
 * 
 * @param data Указатель на данные
 * @param len Длина данных
 * @return Hex строка (нужно освободить через free())
 */
char* bytes_to_hex(const unsigned char* data, size_t len);
```

#### Вспомогательные функции
```c
/**
 * Проверяет, требуется ли padding для данного режима
 * 
 * @param mode Режим шифрования
 * @return 1 если требуется padding, 0 если нет
 */
int requires_padding(cipher_mode_t mode);

/**
 * Генерирует случайный IV
 * 
 * @param iv Буфер для IV (должен быть не менее 16 байт)
 * @param len Длина IV (обычно 16 байт)
 */
void generate_random_iv(unsigned char* iv, size_t len);

/**
 * Парсит строку режима шифрования
 * 
 * @param mode_str Строка с названием режима
 * @return cipher_mode_t или CIPHER_MODE_UNKNOWN
 */
cipher_mode_t parse_cipher_mode(const char* mode_str);

/**
 * Парсит строку алгоритма хеширования
 * 
 * @param algorithm_str Строка с названием алгоритма
 * @return hash_algorithm_t или HASH_UNKNOWN
 */
hash_algorithm_t parse_hash_algorithm(const char *algorithm_str);
```

## Модуль CLI Parser

### Структура аргументов
```c
typedef struct {
    operation_t operation;           // Основная операция
    cipher_mode_t cipher_mode;       // Режим шифрования
    hash_algorithm_t hash_algorithm; // Алгоритм хеширования
    
    char* algorithm;                 // Строковый алгоритм
    unsigned char* key;
    size_t key_len;
    char* input_file;
    char* output_file;
    
    unsigned char* iv;               // Для шифрования
    size_t iv_len;
    int iv_provided;
    
    unsigned char* aad;              // Для GCM
    size_t aad_len;
    
    char* generated_key_hex;
    
    // Для HMAC
    int hmac_mode;
    char* verify_file;
    int verify_mode;
    
    // Для GCM
    int gcm_mode;
    
    // Для KDF
    int kdf_mode;
    char* password;
    char* salt;
    unsigned int iterations;
    size_t key_length;
} cli_args_t;
```

### Функции CLI Parser
```c
/**
 * Парсит аргументы командной строки
 * 
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 * @param args Структура для сохранения распарсенных аргументов
 * @return 1 при успехе, 0 при ошибке
 */
int parse_arguments(int argc, char* argv[], cli_args_t* args);

/**
 * Освобождает ресурсы, выделенные для аргументов
 * 
 * @param args Структура с аргументами
 */
void free_cli_args(cli_args_t* args);

/**
 * Выводит справку по использованию
 * 
 * @param program_name Имя программы
 */
void print_usage(const char* program_name);
```

## Модуль AEAD (Authenticated Encryption with Associated Data)

### Контекст AEAD
```c
typedef struct {
    cipher_mode_t encryption_mode;
    hash_algorithm_t mac_algorithm;
    unsigned char* enc_key;
    unsigned char* mac_key;
    size_t key_len;
} AEAD_CTX;
```

### Функции AEAD
```c
/**
 * Инициализирует контекст AEAD
 */
AEAD_CTX* aead_init(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                   const unsigned char* key, size_t key_len);

/**
 * Выполняет шифрование с аутентификацией
 */
int aead_encrypt(AEAD_CTX* ctx,
                const unsigned char* plaintext, size_t plaintext_len,
                const unsigned char* aad, size_t aad_len,
                unsigned char* iv, size_t iv_len,
                unsigned char** ciphertext, size_t* ciphertext_len,
                unsigned char** tag, size_t* tag_len);

/**
 * Выполняет дешифрование с проверкой аутентификации
 */
int aead_decrypt(AEAD_CTX* ctx,
                const unsigned char* ciphertext, size_t ciphertext_len,
                const unsigned char* aad, size_t aad_len,
                const unsigned char* iv, size_t iv_len,
                const unsigned char* tag, size_t tag_len,
                unsigned char** plaintext, size_t* plaintext_len);

/**
 * Освобождает ресурсы AEAD
 */
void aead_cleanup(AEAD_CTX* ctx);
```

### Высокоуровневые функции AEAD
```c
/**
 * Реализует Encrypt-then-MAC подход
 */
int encrypt_then_mac(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                     const unsigned char* key, size_t key_len,
                     const unsigned char* plaintext, size_t plaintext_len,
                     const unsigned char* aad, size_t aad_len,
                     unsigned char** output, size_t* output_len);

/**
 * Реализует Decrypt-then-Verify подход
 */
int decrypt_then_verify(cipher_mode_t enc_mode, hash_algorithm_t mac_algo,
                        const unsigned char* key, size_t key_len,
                        const unsigned char* input, size_t input_len,
                        const unsigned char* aad, size_t aad_len,
                        unsigned char** output, size_t* output_len);
```

## Модуль HKDF (HMAC-based Key Derivation Function)

```c
/**
 * HKDF-extract этап
 */
int hkdf_extract(const unsigned char* salt, size_t salt_len,
                const unsigned char* ikm, size_t ikm_len,
                unsigned char* prk, size_t prk_len);

/**
 * HKDF-expand этап
 */
int hkdf_expand(const unsigned char* prk, size_t prk_len,
               const unsigned char* info, size_t info_len,
               unsigned char* okm, size_t okm_len);

/**
 * Полный HKDF
 */
int hkdf(const unsigned char* salt, size_t salt_len,
        const unsigned char* ikm, size_t ikm_len,
        const unsigned char* info, size_t info_len,
        unsigned char* okm, size_t okm_len);
```

## Константы

```c
// Размеры блоков
#define AES_BLOCK_SIZE 16
#define SHA256_BLOCK_SIZE 32
#define SHA256_BUF_SIZE 64

// GCM константы
#define GCM_IV_SIZE 12      // Рекомендованный размер nonce
#define GCM_TAG_SIZE 16     // 128-битный тег

// PBKDF2 константы
#define PBKDF2_MAX_ITERATIONS 1000000
#define PBKDF2_DEFAULT_ITERATIONS 100000
#define PBKDF2_MIN_ITERATIONS 1000

// Максимальные размеры
#define MAX_KEY_LENGTH 64      // 512 бит
#define MAX_PASSWORD_LENGTH 1024
#define MAX_FILE_PATH 4096
#define MAX_HEX_STRING_LENGTH (MAX_KEY_LENGTH * 2 + 1)
```

## Коды ошибок

| Код | Константа | Описание |
|-----|-----------|----------|
| 0 | `CRYPTO_SUCCESS` | Успешное выполнение |
| 1 | `CRYPTO_ERROR_INVALID_INPUT` | Неверные входные параметры |
| 2 | `CRYPTO_ERROR_MEMORY` | Ошибка выделения памяти |
| 3 | `CRYPTO_ERROR_CRYPTO` | Ошибка криптографической операции |
| 4 | `CRYPTO_ERROR_IO` | Ошибка ввода/вывода |
| 5 | `CRYPTO_ERROR_AUTH` | Ошибка аутентификации |
| 6 | `CRYPTO_ERROR_PARSE` | Ошибка парсинга |
| 7 | `CRYPTO_ERROR_UNSUPPORTED` | Неподдерживаемая операция |

## Security Notes

1. **Очистка памяти**: Все функции, работающие с ключами, очищают память перед освобождением с использованием `memset()`.

2. **Constant-time операции**: 
   - HMAC сравнение: `hmac_verify()` использует constant-time сравнение
   - GCM проверка тега: constant-time сравнение
   - Все критические проверки защищены от timing attacks

3. **Валидация входных данных**:
   - Проверка указателей на NULL
   - Проверка размеров данных
   - Валидация hex строк
   - Проверка границ буферов

4. **Безопасная генерация**:
   - Все случайные значения генерируются через `RAND_bytes()` OpenSSL
   - Уникальные nonce для GCM
   - Случайные соли для PBKDF2

5. **Защита от переполнений**:
   - Проверка умножений на переполнение
   - Использование `size_t` для размеров
   - Проверка границ при копировании

## Пример использования API

```c
#include "include/crypto.h"
#include "include/csprng.h"
#include "include/hash.h"
#include "include/mac/hmac.h"
#include <stdio.h>
#include <stdlib.h>

int main() {
    // 1. Генерация ключа
    char* key_hex = generate_random_key_hex(16);
    printf("Generated key: %s\n", key_hex);
    
    // 2. Преобразование hex ключа в байты
    unsigned char* key;
    size_t key_len;
    if (!hex_to_bytes(key_hex, &key, &key_len)) {
        fprintf(stderr, "Error converting hex key\n");
        free(key_hex);
        return 1;
    }
    
    // 3. Шифрование данных
    const char* plaintext = "Hello, CryptoCore!";
    size_t encrypted_len;
    unsigned char iv[16];
    generate_random_iv(iv, 16);
    
    unsigned char* encrypted = aes_cbc_encrypt(
        (unsigned char*)plaintext, strlen(plaintext),
        key, iv, &encrypted_len);
    
    if (!encrypted) {
        fprintf(stderr, "Encryption failed\n");
        free(key_hex);
        free(key);
        return 1;
    }
    
    // 4. Дешифрование
    size_t decrypted_len;
    unsigned char* decrypted = aes_cbc_decrypt(
        encrypted, encrypted_len,
        key, iv, &decrypted_len);
    
    // 5. Проверка
    if (decrypted && decrypted_len == strlen(plaintext) &&
        memcmp(plaintext, decrypted, decrypted_len) == 0) {
        printf("Encryption/decryption successful!\n");
    }
    
    // 6. Вычисление HMAC
    char* hmac = hmac_compute_hex(key, key_len,
                                 (unsigned char*)plaintext, strlen(plaintext),
                                 HASH_SHA256);
    printf("HMAC: %s\n", hmac);
    
    // 7. Очистка
    memset(key, 0, key_len);
    free(key);
    free(key_hex);
    free(encrypted);
    free(decrypted);
    free(hmac);
    
    return 0;
}
```

## Расширенный пример: Полный workflow

```c
#include "include/crypto.h"
#include "include/kdf.h"
#include "include/modes/gcm.h"
#include <stdio.h>
#include <string.h>

int secure_data_workflow() {
    // 1. Генерация ключа из пароля
    const char* password = "StrongPassword123!";
    const char* salt_hex = "a1b2c3d4e5f67890";
    char* derived_key_hex = pbkdf2_derive_hex(
        password, salt_hex, 100000, 32);
    
    if (!derived_key_hex) {
        fprintf(stderr, "Key derivation failed\n");
        return 1;
    }
    
    // 2. Преобразование ключа
    unsigned char* key;
    size_t key_len;
    if (!hex_to_bytes(derived_key_hex, &key, &key_len)) {
        fprintf(stderr, "Key conversion failed\n");
        free(derived_key_hex);
        return 1;
    }
    
    // 3. Шифрование с GCM
    const char* plaintext = "Sensitive data";
    const char* aad = "metadata:user=admin;date=2024";
    
    unsigned char* encrypted = NULL;
    size_t encrypted_len = 0;
    
    // Генерация nonce
    unsigned char nonce[GCM_IV_SIZE];
    generate_random_bytes(nonce, GCM_IV_SIZE);
    
    if (!gcm_encrypt_full(key, key_len,
                         nonce, GCM_IV_SIZE,
                         (unsigned char*)plaintext, strlen(plaintext),
                         (unsigned char*)aad, strlen(aad),
                         &encrypted, &encrypted_len)) {
        fprintf(stderr, "GCM encryption failed\n");
        goto cleanup;
    }
    
    // 4. Дешифрование и проверка
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    if (!gcm_decrypt_full(key, key_len,
                         encrypted, encrypted_len,
                         (unsigned char*)aad, strlen(aad),
                         &decrypted, &decrypted_len)) {
        fprintf(stderr, "GCM decryption/auth failed\n");
        goto cleanup;
    }
    
    // 5. Проверка целостности
    if (decrypted_len == strlen(plaintext) &&
        memcmp(plaintext, decrypted, decrypted_len) == 0) {
        printf("✅ Secure workflow completed successfully\n");
    }
    
cleanup:
    // 6. Безопасная очистка
    if (key) {
        memset(key, 0, key_len);
        free(key);
    }
    if (derived_key_hex) {
        // Очистка строки (не так эффективно, но лучше чем ничего)
        memset(derived_key_hex, 0, strlen(derived_key_hex));
        free(derived_key_hex);
    }
    free(encrypted);
    if (decrypted) {
        memset(decrypted, 0, decrypted_len);
        free(decrypted);
    }
    
    return 0;
}
```

## Зависимости

### Обязательные
- **OpenSSL 1.1.1+**: `libcrypto`, `libssl`
- **Стандартная библиотека C**: `libc`

### Опциональные (для разработки)
- **POSIX-совместимая ОС**: для `/dev/urandom` (если не используется OpenSSL RAND)
- **CMake 3.10+**: для альтернативной системы сборки
- **Doxygen**: для генерации документации

### Заголовочные файлы OpenSSL
```c
#include <openssl/evp.h>      // Основные криптографические функции
#include <openssl/rand.h>     // CSPRNG
#include <openssl/sha.h>      // SHA функции
#include <openssl/hmac.h>     // HMAC
#include <openssl/aes.h>      // AES
```

## Совместимость

### Поддерживаемые стандарты
- **C99**: Основной стандарт языка
- **FIPS 180-4**: SHA-256
- **FIPS 202**: SHA3-256
- **NIST SP 800-38A**: Режимы AES
- **NIST SP 800-38D**: GCM режим
- **RFC 2104**: HMAC
- **RFC 2898**: PBKDF2
- **RFC 5869**: HKDF

### Поддерживаемые платформы
- **Linux** (Ubuntu, Debian, CentOS, etc.)
- **macOS** (10.10+)
- **Windows** (через WSL2 или MinGW)
- **BSD** (FreeBSD, OpenBSD)

### Компиляторы
- **GCC** 4.8+
- **Clang** 3.5+
- **MSVC** 2015+ (с ограничениями)

## Ограничения

1. **Только AES-128**: Не поддерживает AES-192 или AES-256
2. **Размер ключа**: Фиксированный 16 байт для AES
3. **Нет аппаратного ускорения**: Использует программную реализацию
4. **Однопоточность**: Нет встроенной поддержки многопоточности
5. **Объем памяти**: Весь файл читается в память

## Производительность

### Ориентировочные показатели
| Операция | Скорость (на Core i7) | Память |
|----------|----------------------|--------|
| SHA-256 | ~150 MB/s | Незначительная |
| AES-CBC | ~80 MB/s | 16 байт на блок |
| HMAC-SHA256 | ~120 MB/s | ~200 байт контекст |
| PBKDF2 (10K итераций) | ~10 ms на ключ | Зависит от итераций |
| GCM | ~60 MB/s | ~500 байт контекст |

### Оптимизации
1. **Loop unrolling**: В критических участках SHA-256
2. **Предвычисленные таблицы**: Для GF(2^128) умножения в GCM
3. **Выравнивание памяти**: Для лучшей производительности SIMD
4. **Кэширование ключей**: В режимах шифрования

## Отладка и диагностика

### Макросы отладки
```c
#ifdef DEBUG
#define CRYPTO_DEBUG(msg, ...) \
    fprintf(stderr, "[DEBUG] %s:%d: " msg "\n", \
            __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define CRYPTO_DEBUG(msg, ...)
#endif

#define CRYPTO_ERROR(msg, ...) \
    fprintf(stderr, "[ERROR] %s:%d: " msg "\n", \
            __FILE__, __LINE__, ##__VA_ARGS__)

#define CRYPTO_WARNING(msg, ...) \
    fprintf(stderr, "[WARNING] %s:%d: " msg "\n", \
            __FILE__, __LINE__, ##__VA_ARGS__)
```

### Проверки assertions
```c
#include <assert.h>

#define CRYPTO_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "Assertion failed: %s (%s:%d)\n", \
                    message, __FILE__, __LINE__); \
            assert(condition); \
        } \
    } while(0)
```

## Тестирование API

### Unit тесты
Каждая публичная функция должна иметь соответствующий unit test:

```c
// tests/src/test_api.c
#include <assert.h>
#include "../include/crypto.h"

void test_aes_ecb_basic() {
    unsigned char key[16] = {0};
    unsigned char plaintext[16] = {0};
    size_t output_len;
    
    unsigned char* encrypted = aes_ecb_encrypt(
        plaintext, 16, key, &output_len);
    
    assert(encrypted != NULL);
    assert(output_len == 16);
    
    // ... больше проверок
    
    free(encrypted);
}
```

### Integration тесты
```c
void test_full_encryption_workflow() {
    // Генерация ключа -> шифрование -> дешифрование -> проверка
    // ...
}
```

## Лицензия

© 2024 CryptoCore Educational Project

Этот проект создан **исключительно для образовательных целей**. Весь исходный код открыт для изучения, анализа и использования в образовательных целях.

### Ограничения
1. Не используйте в production без независимого аудита безопасности
2. Не используйте для защиты действительно конфиденциальных данных
3. Код предназначен для демонстрации криптографических принципов

### Авторские права
Все реализации с нуля (SHA-256, HMAC, режимы AES) являются оригинальной работой автора проекта и могут свободно использоваться для обучения.

Использование OpenSSL регулируется лицензией OpenSSL.

---

## Дополнительные ресурсы

### Исходный код
- Основной репозиторий: `src/`
- Заголовочные файлы: `include/`
- Тесты: `tests/`

### Документация
- Руководство пользователя: `docs/USERGUIDE.md`
- Руководство разработчика: `docs/DEVELOPMENT.md`
- Примеры использования: `examples/`

### Ссылки
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
- [RFC Repository](https://www.rfc-editor.org/)

## Контакты

Для вопросов и предложений:
- Создайте issue в репозитории проекта
- Обратитесь к автору через образовательную платформу

**Happy secure coding!** 🔐

---

*Последнее обновление: Декабрь 2024*
*Версия API: 1.0.0*
*Соответствует: FIPS 180-4, NIST SP 800-38, RFC 2104, RFC 2898*