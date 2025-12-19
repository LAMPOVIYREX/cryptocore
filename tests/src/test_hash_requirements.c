#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <sys/stat.h>

#include "../../include/hash.h"

// TEST-2: Empty Input Test
void test_empty_input() {
    printf("Testing empty input...\n");
    
    // SHA-256 empty string
    char* sha256_empty = sha256_hex((unsigned char*)"", 0);
    assert(sha256_empty != NULL);
    printf("  SHA-256 empty: %s\n", sha256_empty);
    assert(strcmp(sha256_empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    free(sha256_empty);
    
    // SHA3-256 empty string
    char* sha3_empty = sha3_256_hex((unsigned char*)"", 0);
    assert(sha3_empty != NULL);
    printf("  SHA3-256 empty: %s\n", sha3_empty);
    assert(strcmp(sha3_empty, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a") == 0);
    free(sha3_empty);
    
    printf("  ✓ Empty input tests passed\n");
}

// TEST-3: Interoperability Test
void test_interoperability() {
    printf("Testing interoperability with system tools...\n");
    
    // Создаем тестовый файл
    FILE* f = fopen("interop_test.txt", "w");
    assert(f != NULL);
    fprintf(f, "Hello, World!\n");
    fclose(f);
    
    // Вычисляем хеш с помощью cryptocore
    char* cc_hash = sha256_file("interop_test.txt");
    assert(cc_hash != NULL);
    
    // Вычисляем хеш с помощью sha256sum
    system("sha256sum interop_test.txt | cut -d' ' -f1 > sys_hash.txt");
    
    FILE* sys = fopen("sys_hash.txt", "r");
    assert(sys != NULL);
    char sys_hash[65];
    fscanf(sys, "%64s", sys_hash);
    fclose(sys);
    
    printf("  CryptoCore hash: %s\n", cc_hash);
    printf("  System hash:     %s\n", sys_hash);
    
    // Сравниваем хеши
    assert(strcmp(cc_hash, sys_hash) == 0);
    
    // Очистка
    free(cc_hash);
    remove("interop_test.txt");
    remove("sys_hash.txt");
    
    printf("  ✓ Interoperability test passed\n");
}

// TEST-4: Large File Test (симуляция)
void test_large_file_simulation() {
    printf("Testing large file handling (simulation)...\n");
    
    // Создаем файл размером 10MB для тестирования
    const size_t LARGE_SIZE = 10 * 1024 * 1024; // 10MB
    FILE* large = fopen("large_test.bin", "wb");
    assert(large != NULL);
    
    // Заполняем случайными данными
    unsigned char buffer[4096];
    for (size_t i = 0; i < sizeof(buffer); i++) {
        buffer[i] = (unsigned char)(i % 256);
    }
    
    size_t written = 0;
    while (written < LARGE_SIZE) {
        size_t chunk = (LARGE_SIZE - written < sizeof(buffer)) ? 
                      LARGE_SIZE - written : sizeof(buffer);
        size_t result = fwrite(buffer, 1, chunk, large);
        assert(result == chunk);
        written += chunk;
    }
    fclose(large);
    
    // Вычисляем хеш
    char* hash = sha256_file("large_test.bin");
    assert(hash != NULL);
    
    // Проверяем, что хеш не нулевой
    assert(strlen(hash) == 64);
    
    printf("  Large file hash (first 16 chars): %.16s...\n", hash);
    printf("  File size: %zu bytes\n", written);
    
    free(hash);
    remove("large_test.bin");
    
    printf("  ✓ Large file test passed\n");
}

// TEST-5: Avalanche Effect Test
void test_avalanche_effect() {
    printf("Testing avalanche effect...\n");
    
    // Два сообщения, отличающиеся одним битом
    unsigned char data1[] = "Hello";
    unsigned char data2[] = "Jello"; // H(0x48) -> J(0x4A), изменен 1 бит
    
    char* hash1 = sha256_hex(data1, 5);
    char* hash2 = sha256_hex(data2, 5);
    
    assert(hash1 != NULL);
    assert(hash2 != NULL);
    
    printf("  Hash 1 (Hello): %s\n", hash1);
    printf("  Hash 2 (Jello): %s\n", hash2);
    
    // Преобразуем hex в бинарное представление
    unsigned char bin1[32], bin2[32];
    for (int i = 0; i < 32; i++) {
        sscanf(hash1 + i*2, "%2hhx", &bin1[i]);
        sscanf(hash2 + i*2, "%2hhx", &bin2[i]);
    }
    
    // Подсчитываем различающиеся биты
    int diff_bits = 0;
    for (int i = 0; i < 32; i++) {
        unsigned char xor = bin1[i] ^ bin2[i];
        while (xor) {
            diff_bits += xor & 1;
            xor >>= 1;
        }
    }
    
    printf("  Different bits: %d/256 (%.1f%%)\n", diff_bits, (diff_bits * 100.0) / 256);
    
    // Avalanche effect: должно быть примерно 128 бит (50%)
    // Принимаем от 100 до 156 бит (39% - 61%)
    assert(diff_bits >= 100 && diff_bits <= 156);
    
    free(hash1);
    free(hash2);
    
    printf("  ✓ Avalanche effect test passed\n");
}

// TEST-6: Performance Test (базовый)
void test_performance_basic() {
    printf("Testing basic performance...\n");
    
    // Создаем тестовый файл 1MB
    const size_t SIZE = 1024 * 1024;
    FILE* perf = fopen("perf_test.bin", "wb");
    assert(perf != NULL);
    
    for (size_t i = 0; i < SIZE; i++) {
        fputc((unsigned char)(i % 256), perf);
    }
    fclose(perf);
    
    // Измеряем время выполнения (очень приблизительно)
    clock_t start = clock();
    char* hash = sha256_file("perf_test.bin");
    clock_t end = clock();
    
    assert(hash != NULL);
    
    double cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;
    double speed = SIZE / cpu_time / 1024 / 1024; // MB/s
    
    printf("  File size: %zu bytes\n", SIZE);
    printf("  CPU time: %.3f seconds\n", cpu_time);
    printf("  Speed: %.2f MB/s\n", speed);
    printf("  Hash: %.16s...\n", hash);
    
    // Проверяем, что производительность разумная
    // (хотя бы 0.1 MB/s для программной реализации)
    assert(speed > 0.1);
    
    free(hash);
    remove("perf_test.bin");
    
    printf("  ✓ Performance test passed\n");
}

int main() {
    printf("=== Hash Function Requirements Tests ===\n\n");
    
    test_empty_input();
    printf("\n");
    
    test_interoperability();
    printf("\n");
    
    test_large_file_simulation();
    printf("\n");
    
    test_avalanche_effect();
    printf("\n");
    
    test_performance_basic();
    
    printf("\n=== All hash requirements tests passed! ===\n");
    return 0;
}