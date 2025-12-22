# Руководство разработчика CryptoCore

## Оглавление
1. [Архитектура проекта](#архитектура-проекта)
2. [Сборка и разработка](#сборка-и-разработка)
3. [Структура кода](#структура-кода)
4. [Добавление новых функций](#добавление-новых-функций)
5. [Тестирование](#тестирование)
6. [Ревью кода](#ревью-кода)
7. [Профилирование и оптимизация](#профилирование-и-оптимизация)
8. [Безопасность разработки](#безопасность-разработки)
9. [Внесение изменений](#внесение-изменений)
10. [Полезные инструменты](#полезные-инструменты)

---

## Архитектура проекта

### Общий обзор

```
cryptocore/
├── src/                    # Исходный код
│   ├── hash/              # Реализации хеш-функций
│   ├── mac/               # MAC функции (HMAC)
│   ├── modes/             # Режимы шифрования
│   └── *.c               # Основные модули
├── include/               # Заголовочные файлы
├── tests/                 # Тесты
│   ├── src/              # Исходники тестов
│   ├── scripts/          # Скрипты тестирования
│   └── data/             # Тестовые данные
├── docs/                  # Документация
├── bin/                   # Скомпилированные бинарники
├── obj/                   # Объектные файлы
└── test_data/            # Тестовые данные для CLI
```

### Модульная архитектура

Проект разделен на независимые модули:

1. **crypto** - базовые операции AES
2. **modes** - режимы шифрования (CBC, CTR, GCM и др.)
3. **hash** - хеш-функции (SHA-256, SHA3-256)
4. **mac** - функции аутентификации сообщений (HMAC)
5. **kdf** - функции получения ключей (PBKDF2)
6. **csprng** - криптографически стойкий ГСЧ

### Зависимости

```makefile
# Основные зависимости
- OpenSSL 1.1.1+ (libcrypto, libssl)
- Стандартная библиотека C (libc)
- Компилятор GCC/Clang с поддержкой C99
```

### Связи между модулями

```
          CLI Parser
              |
        +-----+-----+
        |           |
    Crypto       Hash
      |             |
    Modes         HMAC
      |             |
     GCM          KDF
      |             |
   AEAD         PBKDF2
```

---

## Сборка и разработка

### Требования к окружению

```bash
# Установка зависимостей для разработки
sudo apt-get install \
    build-essential \
    libssl-dev \
    openssl \
    valgrind \
    gdb \
    cppcheck \
    clang-tidy \
    gcovr \
    doxygen \
    graphviz
```

### Сборка проекта

```bash
# Полная сборка (рекомендуется для разработки)
make clean
make all

# Быстрая сборка (только измененные файлы)
make

# Сборка конкретного модуля
make obj/hash/sha256.o

# Сборка тестов
make test_hmac_build
make test_gcm_build
make test_kdf_build
```

### Флаги компиляции

```makefile
# Основные флаги (из Makefile)
CFLAGS = -Wall -Wextra -std=c99 -O2 -I./include

# Для отладки
DEBUG_CFLAGS = -g -O0 -DDEBUG -fsanitize=address

# Для production
PROD_CFLAGS = -O3 -DNDEBUG -fstack-protector-strong
```

### Настройка IDE

#### Visual Studio Code
```json
// .vscode/c_cpp_properties.json
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/include",
                "${workspaceFolder}/include/**"
            ],
            "defines": [],
            "compilerPath": "/usr/bin/gcc",
            "cStandard": "c99",
            "cppStandard": "c++17"
        }
    ]
}
```

#### CLion
- Настройте CMakeLists.txt или используйте Makefile проект
- Укажите флаги компиляции из Makefile
- Настройте пути к заголовочным файлам

---

## Структура кода

### Конвенции именования

```c
// Типы данных
typedef struct {
    // поля
} ModuleName_CTX;  // Префикс CRYPTOCORE_ для избежания конфликтов

// Функции
module_action_subject()  // Например: sha256_update()
// Глагол + объект + действие

// Константы
#define MODULE_CONSTANT_NAME VALUE  // Например: SHA256_BLOCK_SIZE
#define CONSTANT_CASE_VALUE  123    // Верхний регистр с подчеркиваниями

// Переменные
camelCaseForLocalVars
snake_case_for_parameters
p_prefix_for_pointers  // Например: p_buffer
```

### Структура файлов

#### Заголовочный файл (include/module.h)
```c
#ifndef MODULE_H
#define MODULE_H

#include <stdlib.h>
#include "../include/types.h"

// Декларации типов
typedef struct {
    // поля
} MODULE_CTX;

// Декларации функций
MODULE_CTX* module_init(parameters);
int module_operation(MODULE_CTX* ctx, ...);
void module_cleanup(MODULE_CTX* ctx);

// Inline функции
static inline int helper_function(int x) {
    return x * 2;
}

#endif // MODULE_H
```

#### Исходный файл (src/module.c)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/module.h"
#include "../include/other_module.h"

// Статические функции (private)
static int internal_helper(...) {
    // реализация
}

// Публичные функции
MODULE_CTX* module_init(parameters) {
    MODULE_CTX* ctx = malloc(sizeof(MODULE_CTX));
    if (!ctx) return NULL;
    
    // инициализация
    return ctx;
}

void module_cleanup(MODULE_CTX* ctx) {
    if (!ctx) return;
    
    // очистка чувствительных данных
    if (ctx->key) {
        memset(ctx->key, 0, ctx->key_len);
        free(ctx->key);
    }
    
    free(ctx);
}
```

### Управление памятью

#### Принципы
1. **Кто выделяет - тот освобождает**
2. **Проверка возвращаемых значений** malloc/calloc
3. **Очистка чувствительных данных** перед free
4. **Использование calloc** для структур с указателями

#### Шаблон работы с памятью
```c
int secure_operation(...) {
    unsigned char* buffer = malloc(size);
    if (!buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return 0;
    }
    
    // Использование buffer
    
    // Очистка чувствительных данных
    memset(buffer, 0, size);
    free(buffer);
    
    return 1;
}
```

### Обработка ошибок

#### Коды ошибок
```c
#define CRYPTO_SUCCESS 0
#define CRYPTO_ERROR_INVALID_INPUT 1
#define CRYPTO_ERROR_MEMORY 2
#define CRYPTO_ERROR_CRYPTO 3
#define CRYPTO_ERROR_IO 4
```

#### Макросы для обработки ошибок
```c
#define CHECK_NULL(ptr, retval) \
    if ((ptr) == NULL) { \
        fprintf(stderr, "Error: NULL pointer at %s:%d\n", __FILE__, __LINE__); \
        return (retval); \
    }

#define CHECK_ALLOC(ptr, retval) \
    if ((ptr) == NULL) { \
        fprintf(stderr, "Error: Memory allocation failed at %s:%d\n", __FILE__, __LINE__); \
        return (retval); \
    }
```

---

## Добавление новых функций

### Процесс разработки новой функции

#### Шаг 1: Проектирование API
```c
// 1. Определите интерфейс в include/header.h
int new_operation(const unsigned char* input, size_t input_len,
                  unsigned char* output, size_t* output_len);

// 2. Добавьте документацию
/**
 * Краткое описание функции
 * 
 * @param input Входные данные
 * @param input_len Длина входных данных
 * @param output Буфер для выходных данных (должен быть достаточного размера)
 * @param output_len Указатель для сохранения длины выходных данных
 * @return 0 при успехе, код ошибки при неудаче
 */
```

#### Шаг 2: Реализация
```c
// 3. Реализуйте в src/module.c
int new_operation(const unsigned char* input, size_t input_len,
                  unsigned char* output, size_t* output_len) {
    
    // Валидация параметров
    if (!input || !output || !output_len) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    // Основная логика
    // ...
    
    return CRYPTO_SUCCESS;
}
```

#### Шаг 3: Интеграция с CLI
```c
// 4. Добавьте обработку в cli_parser.c
static int parse_new_operation(int argc, char* argv[], cli_args_t* args) {
    // парсинг аргументов
}

// 5. Добавьте обработку в main.c
static int handle_new_operation(cli_args_t* args) {
    // вызов новой функции
}
```

#### Шаг 4: Тестирование
```c
// 6. Напишите unit тесты
void test_new_operation_basic() {
    // тестирование
}

// 7. Напишите integration тесты
// tests/scripts/test_new_operation.sh
```

### Пример: Добавление нового режима шифрования

#### 1. Добавьте тип в types.h
```c
typedef enum {
    // существующие типы
    CIPHER_MODE_NEW,
    CIPHER_MODE_UNKNOWN
} cipher_mode_t;
```

#### 2. Реализуйте функции в modes/new_mode.c
```c
unsigned char* aes_new_encrypt(const unsigned char* input, size_t input_len,
                               const unsigned char* key, const unsigned char* iv,
                               size_t* output_len) {
    // реализация
}
```

#### 3. Обновите crypto.h и crypto.c
```c
// Добавьте прототипы
unsigned char* aes_new_encrypt(...);
unsigned char* aes_new_decrypt(...);

// Обновите switch в handle_crypto_operation()
case CIPHER_MODE_NEW:
    if (is_encrypt) {
        output_data = aes_new_encrypt(...);
    } else {
        output_data = aes_new_decrypt(...);
    }
    break;
```

#### 4. Обновите Makefile
```makefile
MODE_SRCS = $(wildcard $(SRC_DIR)/modes/*.c) $(SRC_DIR)/modes/new_mode.c
```

### Добавление новых тестовых векторов

#### Формат тестовых данных
```json
{
    "test_cases": [
        {
            "description": "Test case description",
            "key": "hex_key",
            "input": "hex_input", 
            "expected": "hex_expected_output"
        }
    ]
}
```

#### Интеграция тестов
```c
// tests/src/test_new_vectors.c
#include "../../include/module.h"

void test_new_vectors() {
    const char* test_vectors[] = {
        "key1:input1:expected1",
        "key2:input2:expected2",
        NULL
    };
    
    for (int i = 0; test_vectors[i]; i++) {
        parse_and_test(test_vectors[i]);
    }
}
```

---

## Тестирование

### Типы тестов

#### Unit тесты
```c
// tests/src/test_module.c
#include <assert.h>
#include "../../include/module.h"

void test_function_basic() {
    // Arrange
    int input = 5;
    
    // Act
    int result = function_to_test(input);
    
    // Assert
    assert(result == 10);
    printf("✓ test_function_basic passed\n");
}
```

#### Integration тесты
```bash
#!/bin/bash
# tests/scripts/test_integration.sh
echo "=== Integration Test ==="

# Тестирование полного workflow
./bin/cryptocore -algorithm aes -mode cbc -encrypt \
    -input test.txt -output test.enc

# Проверка результатов
if [ $? -eq 0 ]; then
    echo "✅ Integration test passed"
else
    echo "❌ Integration test failed"
    exit 1
fi
```

#### Тесты производительности
```c
// tests/src/test_performance.c
#include <time.h>
#include "../../include/module.h"

void test_performance() {
    clock_t start = clock();
    
    for (int i = 0; i < 1000; i++) {
        operation_to_test();
    }
    
    clock_t end = clock();
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("Performance: %.3f seconds per 1000 operations\n", time_taken);
}
```

### Запуск тестов

```bash
# Все тесты
make test
# или
./tests/scripts/run_all_tests.sh

# Конкретный тест
make test_hmac
./bin/test_hmac_vectors

# Тесты с valgrind
valgrind --leak-check=full ./bin/test_hash

# Тесты с coverage
make clean
make CFLAGS="-fprofile-arcs -ftest-coverage"
./bin/test_hash
gcov src/hash/sha256.c
```

### Покрытие кода

```bash
# Установите gcovr
sudo apt-get install gcovr

# Генерация отчета
make clean
make CFLAGS="-fprofile-arcs -ftest-coverage -O0"
./tests/scripts/run_all_tests.sh
gcovr --exclude tests/ --html --html-details -o coverage_report.html
```

### Статический анализ

```bash
# cppcheck
cppcheck --enable=all --suppress=missingIncludeSystem src/

# clang-tidy
clang-tidy src/*.c --checks=* -- -I./include

# scan-build (clang static analyzer)
scan-build make all
```

---

## Ревью кода

### Checklist для ревью

#### Безопасность
- [ ] Проверка всех входных параметров
- [ ] Очистка чувствительных данных в памяти
- [ ] Constant-time операции где необходимо
- [ ] Нет hardcoded ключей или паролей
- [ ] Корректная обработка ошибок

#### Качество кода
- [ ] Соответствие code style
- [ ] Отсутствие memory leaks
- [ ] Отсутствие buffer overflows
- [ ] Документация функций
- [ ] Тестовое покрытие

#### Производительность
- [ ] Эффективное использование памяти
- [ ] Отсутствие лишних копий данных
- [ ] Оптимальные алгоритмы

### Процесс ревью

1. **Предварительные проверки**
   ```bash
   # Запустите статический анализ
   make analyze
   
   # Запустите тесты
   make test
   
   # Проверьте coverage
   make coverage
   ```

2. **Ревью кода**
   - Проверьте каждую функцию по checklist
   - Обратите внимание на edge cases
   - Проверьте документацию

3. **Исправления**
   - Исправьте все замечания
   - Обновите тесты при необходимости
   - Перезапустите проверки

### Автоматические проверки

```bash
#!/bin/bash
# scripts/pre-commit.sh

echo "=== Running pre-commit checks ==="

# Форматирование
clang-format -i src/*.c include/*.h

# Статический анализ
cppcheck --error-exitcode=1 src/

# Тесты
make test

# Сборка
make clean
make all

echo "=== All checks passed ==="
```

---

## Профилирование и оптимизация

### Инструменты профилирования

#### gprof
```bash
# Компиляция с profiling
make clean
make CFLAGS="-pg -O2"

# Запуск
./bin/cryptocore ...

# Анализ
gprof ./bin/cryptocore gmon.out > analysis.txt
```

#### perf
```bash
# Запись профиля
perf record ./bin/cryptocore ...

# Анализ
perf report
perf annotate
```

#### Valgrind (callgrind)
```bash
valgrind --tool=callgrind ./bin/cryptocore ...
kcachegrind callgrind.out.*
```

### Оптимизация критических участков

#### 1. Идентификация bottleneck
```c
// Добавьте timing в код
#include <time.h>

clock_t start = clock();
// критический участок
clock_t end = clock();
printf("Time: %.3f ms\n", ((double)(end - start)) * 1000 / CLOCKS_PER_SEC);
```

#### 2. Оптимизация циклов
```c
// До
for (size_t i = 0; i < len; i++) {
    output[i] = input[i] ^ key[i % 16];
}

// После (loop unrolling)
for (size_t i = 0; i < len - 3; i += 4) {
    output[i] = input[i] ^ key[i % 16];
    output[i+1] = input[i+1] ^ key[(i+1) % 16];
    output[i+2] = input[i+2] ^ key[(i+2) % 16];
    output[i+3] = input[i+3] ^ key[(i+3) % 16];
}
```

#### 3. Использование SIMD (если доступно)
```c
#ifdef __SSE2__
#include <emmintrin.h>
// Использование SSE2 инструкций
#endif
```

### Бенчмаркинг

```bash
# Создайте бенчмарки
./tests/scripts/benchmark.sh

# Сравнение версий
./scripts/compare_performance.sh v1.0 v1.1
```

---

## Безопасность разработки

### Принципы безопасного кодирования

#### 1. Валидация входных данных
```c
int secure_function(const unsigned char* data, size_t len) {
    // Проверка указателей
    if (!data && len > 0) return 0;
    
    // Проверка размеров
    if (len > MAX_ALLOWED_SIZE) return 0;
    
    // Проверка выравнивания (если необходимо)
    if ((uintptr_t)data % 16 != 0) {
        // Обработка невыровненных данных
    }
    
    return 1;
}
```

#### 2. Constant-time операции
```c
// НЕПРАВИЛЬНО
int compare(const unsigned char* a, const unsigned char* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            return 0;  // Ранний возврат - timing attack!
        }
    }
    return 1;
}

// ПРАВИЛЬНО (constant-time)
int constant_time_compare(const unsigned char* a, const unsigned char* b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}
```

#### 3. Очистка памяти
```c
void cleanup_sensitive_data(unsigned char* data, size_t len) {
    if (!data) return;
    
    // Используйте volatile чтобы компилятор не оптимизировал
    volatile unsigned char* vdata = data;
    for (size_t i = 0; i < len; i++) {
        vdata[i] = 0;
    }
    
    // Дополнительная гарантия
    memset_s(data, len, 0, len);
}
```

#### 4. Защита от side-channel атак
```c
// Используйте маскирование данных
uint32_t masked_addition(uint32_t a, uint32_t b, uint32_t mask) {
    return (a ^ mask) + (b ^ mask) ^ mask;
}
```

### Аудит кода на уязвимости

```bash
# Используйте инструменты безопасности
sudo apt-get install flawfinder rats cppcheck

# Проверка на common vulnerabilities
flawfinder src/

# Проверка на buffer overflows
rats src/

# Fuzzing тесты
sudo apt-get install afl
afl-gcc -o test_fuzz src/test_fuzz.c
afl-fuzz -i testcases/ -o findings/ ./test_fuzz
```

### Dependency checking

```bash
# Проверка версий OpenSSL
openssl version

# Проверка известных уязвимостей в зависимостях
apt-get changelog libssl-dev | head -50
```

---

## Внесение изменений

### Workflow разработки

#### 1. Создание feature branch
```bash
git checkout -b feature/new-algorithm
```

#### 2. Разработка
```bash
# Регулярные коммиты
git add src/new_algorithm.c
git commit -m "feat: add new algorithm implementation"

# Обновление документации
git add docs/API.md
git commit -m "docs: update API for new algorithm"
```

#### 3. Тестирование
```bash
# Локальные тесты
make test
./tests/scripts/run_all_tests.sh

# Проверка памяти
valgrind --leak-check=full ./bin/test_new_algorithm
```

#### 4. Ревью и мерж
```bash
# Push в remote
git push origin feature/new-algorithm

# Создание pull request
# После approval:
git checkout main
git merge --no-ff feature/new-algorithm
git branch -d feature/new-algorithm
```

### Семантическое версионирование

```
MAJOR.MINOR.PATCH
```

- **MAJOR** - обратно несовместимые изменения API
- **MINOR** - новая функциональность с обратной совместимостью  
- **PATCH** - исправления ошибок с обратной совместимостью

### Changelog

```markdown
# Changelog

## [1.1.0] - 2024-01-15
### Added
- Новая функция PBKDF2
- Поддержка SHA3-256

### Changed
- Улучшена обработка ошибок в CLI
- Оптимизирована производительность HMAC

### Fixed
- Исправлена утечка памяти в GCM
- Исправлена проверка границ в SHA-256
```

### Миграционные руководства

При breaking changes создавайте:

```markdown
# Migration Guide v1.0 to v1.1

## Изменения API

### Старый API
```c
int old_function(char* data);
```

### Новый API  
```c
int new_function(const unsigned char* data, size_t len);
```

## Шаги миграции
1. Обновите вызовы функций
2. Перекомпилируйте с новой версией
3. Обновите тесты
```

---

## Полезные инструменты

### Отладка
```bash
# GDB с pretty printing
gdb -ex "break main" -ex "run" ./bin/cryptocore

# Valgrind для памяти
valgrind --leak-check=full --show-leak-kinds=all ./bin/cryptocore

# AddressSanitizer
make CFLAGS="-fsanitize=address -g" LDFLAGS="-fsanitize=address"
```

### Документация
```bash
# Doxygen
doxygen Doxyfile

# Graphviz для диаграмм
dot -Tpng diagram.dot -o diagram.png
```

### Профилирование
```bash
# CPU profiling
sudo perf record -g ./bin/cryptocore
sudo perf report -g

# Memory profiling
valgrind --tool=massif ./bin/cryptocore
ms_print massif.out.*
```

### Continuous Integration

Пример .github/workflows/ci.yml:
```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Install dependencies
      run: sudo apt-get install libssl-dev
      
    - name: Build
      run: make all
      
    - name: Test
      run: make test
      
    - name: Static analysis
      run: cppcheck --error-exitcode=1 src/
```

### Мониторинг производительности

```bash
# Создайте dashboard для метрик
./scripts/collect_metrics.sh
```

---

## Получение помощи

### Внутренние ресурсы
- `docs/API.md` - полное описание API
- `tests/` - примеры использования
- Комментарии в коде

### Внешние ресурсы
- OpenSSL документация
- NIST стандарты (FIPS)
- RFC документы

### Команда разработки
- Используйте issues для багов
- Pull requests для новых функций
- Discussions для вопросов

---

## Лицензия

© 2024 CryptoCore Educational Project

Этот проект предназначен для образовательных целей. Весь код открыт для изучения и модификации.

**Happy coding and stay secure!** 🔐💻