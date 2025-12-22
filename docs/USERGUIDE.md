# Руководство пользователя CryptoCore

## Оглавление
1. [Быстрый старт](#быстрый-старт)
2. [Установка и настройка](#установка-и-настройка)
3. [Основные операции](#основные-операции)
4. [Шифрование и дешифрование](#шифрование-и-дешифрование)
5. [Хеширование](#хеширование)
6. [HMAC](#hmac)
7. [GCM аутентифицированное шифрование](#gcm-аутентифицированное-шифрование)
8. [PBKDF2 генерация ключей](#pbkdf2-генерация-ключей)
9. [Сценарии использования](#сценарии-использования)
10. [Устранение неполадок](#устранение-неполадок)
11. [Рекомендации по безопасности](#рекомендации-по-безопасности)

---

## Быстрый старт

### Установка за 5 минут

```bash
# 1. Клонируйте и соберите проект
git clone <repository-url>
cd cryptocore
make all

# 2. Создайте тестовые данные
make test-data

# 3. Проверьте установку
./bin/cryptocore --help
```

### Ваш первый криптографический файл

```bash
# Перейдите в директорию с тестами
cd test_data

# Шифрование файла
../bin/cryptocore -algorithm aes -mode cbc -encrypt \
    -input tests/secret.txt -output tests/secret.enc

# Вы увидите сгенерированный ключ:
# Generated random key: f80e434292fb315988b53a441d730e35
```

---

## Установка и настройка

### Требования к системе

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install git build-essential libssl-dev openssl xxd
```

**macOS:**
```bash
brew install git openssl
```

**Windows (WSL2):**
```bash
# Используйте WSL2 с Ubuntu
```

### Сборка из исходников

```bash
# Полная сборка
make clean
make all

# Сборка только основной программы
make

# Сборка тестов
make test_hmac_build test_hash_build test_gcm_build test_kdf_build
```

### Проверка установки

```bash
# Проверьте версию
./bin/cryptocore --version

# Проверьте все доступные команды
./bin/cryptocore --help

# Проверьте работу шифрования
echo "Test message" > test.txt
./bin/cryptocore -algorithm aes -mode cbc -encrypt -input test.txt -output test.enc
```

---

## Основные операции

### Структура команд

CryptoCore поддерживает несколько режимов работы:

1. **Шифрование/Дешифрование** - основной режим
2. **Хеширование** (`dgst`) - вычисление хешей
3. **HMAC** (`dgst --hmac`) - проверка целостности
4. **PBKDF2** (`derive`) - генерация ключей из паролей

### Общий синтаксис

```bash
# Шифрование/дешифрование
./bin/cryptocore -algorithm aes -mode MODE (-encrypt | -decrypt) \
    [-key HEX_KEY] -input INPUT_FILE [-output OUTPUT_FILE] \
    [-iv HEX_IV] [-aad HEX_AAD]

# Хеширование
./bin/cryptocore dgst --algorithm ALGORITHM --input INPUT_FILE \
    [--output OUTPUT_FILE]

# HMAC
./bin/cryptocore dgst --algorithm ALGORITHM --hmac --key HEX_KEY \
    --input INPUT_FILE [--output OUTPUT_FILE] [--verify FILE]

# PBKDF2
./bin/cryptocore derive --password PASSWORD \
    [--salt HEX_SALT] [--iterations N] [--length L] [--output FILE]
```

---

## Шифрование и дешифрование

### Поддерживаемые режимы

| Режим | Padding | IV/Nonce | Рекомендация |
|-------|---------|----------|--------------|
| **ECB** | PKCS#7 | Нет | Только для тестирования |
| **CBC** | PKCS#7 | 16 байт | ✅ Рекомендуется |
| **CFB** | Нет | 16 байт | Потоковый режим |
| **OFB** | Нет | 16 байт | Потоковый режим |
| **CTR** | Нет | 16 байт | Потоковый режим |
| **GCM** | Нет | 12 байт | ✅ Аутентифицированное шифрование |

### Примеры использования

#### 1. Шифрование с автоматической генерацией ключа

```bash
# Ключ сгенерируется автоматически
./bin/cryptocore -algorithm aes -mode cbc -encrypt \
    -input document.txt -output document.enc

# Сохраните сгенерированный ключ!
# Generated random key: f80e434292fb315988b53a441d730e35
```

#### 2. Шифрование с указанным ключом

```bash
# Используйте hex-ключ (32 символа = 16 байт)
./bin/cryptocore -algorithm aes -mode cbc -encrypt \
    -key 00112233445566778899aabbccddeeff \
    -input secret.txt -output secret.enc
```

#### 3. Дешифрование

```bash
# Для режимов с IV (CBC, CFB, OFB, CTR)
./bin/cryptocore -algorithm aes -mode cbc -decrypt \
    -key 00112233445566778899aabbccddeeff \
    -input secret.enc -output secret_decrypted.txt

# Если IV был сохранен в файле (автоматически)
./bin/cryptocore -algorithm aes -mode cbc -decrypt \
    -key YOUR_KEY_HERE -input file.enc -output file.dec
```

#### 4. Работа с IV

```bash
# Шифрование с указанием IV
./bin/cryptocore -algorithm aes -mode cbc -encrypt \
    -key KEY -iv AABBCCDDEEFF00112233445566778899 \
    -input data.txt -output data.enc

# Дешифрование с указанием IV
./bin/cryptocore -algorithm aes -mode cbc -decrypt \
    -key KEY -iv AABBCCDDEEFF00112233445566778899 \
    -input data.enc -output data.dec
```

### Сравнение режимов

```bash
# Тестирование всех режимов
for mode in ecb cbc cfb ofb ctr; do
    echo "Testing $mode..."
    ./bin/cryptocore -algorithm aes -mode $mode -encrypt \
        -key 00112233445566778899aabbccddeeff \
        -input test.txt -output test_$mode.enc
done
```

---

## Хеширование

### Поддерживаемые алгоритмы

- **SHA-256** - реализация с нуля по FIPS 180-4
- **SHA3-256** - через OpenSSL

### Базовое использование

```bash
# SHA-256 файла
./bin/cryptocore dgst --algorithm sha256 --input document.pdf

# SHA3-256 файла
./bin/cryptocore dgst --algorithm sha3-256 --input document.pdf

# Сохранение в файл
./bin/cryptocore dgst --algorithm sha256 \
    --input document.pdf --output document.sha256
```

### Работа с stdin

```bash
# Хеширование из stdin
echo "Hello World" | ./bin/cryptocore dgst --algorithm sha256 --input -

# Хеширование вывода другой команды
cat large_file.bin | ./bin/cryptocore dgst --algorithm sha256 --input -
```

### Проверка целостности

```bash
# 1. Создайте хеш файла
./bin/cryptocore dgst --algorithm sha256 \
    --input important.txt --output important.sha256

# 2. Позже проверьте
./bin/cryptocore dgst --algorithm sha256 \
    --input important.txt | diff - important.sha256

# Если вывод пустой - файл не изменился
```

### Сравнение с системными утилитами

```bash
# CryptoCore
./bin/cryptocore dgst --algorithm sha256 --input file.txt > crypto_hash.txt

# Системная утилита
sha256sum file.txt > system_hash.txt

# Сравнение
diff crypto_hash.txt system_hash.txt && echo "✅ Hashes match!"
```

---

## HMAC

### Назначение
HMAC используется для проверки целостности и подлинности данных.

### Генерация HMAC

```bash
# Базовый пример
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key 00112233445566778899aabbccddeeff \
    --input data.txt --output data.hmac

# Ключ любой длины
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key 4a656665 \  # "Jefe" в hex
    --input data.txt
```

### Проверка HMAC

```bash
# Генерация HMAC для проверки
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key MY_SECRET_KEY \
    --input document.txt --output expected.hmac

# Проверка (успешная)
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key MY_SECRET_KEY \
    --input document.txt --verify expected.hmac
# Вывод: [OK] HMAC verification successful

# Проверка (неудачная - файл изменен)
echo "tampered" >> document.txt
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key MY_SECRET_KEY \
    --input document.txt --verify expected.hmac
# Вывод: [ERROR] HMAC verification failed
```

### Использование с бинарными файлами

```bash
# HMAC для бинарного файла
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key $(cat secret.key) \
    --input backup.tar.gz --output backup.hmac

# Проверка перед использованием
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key $(cat secret.key) \
    --input backup.tar.gz --verify backup.hmac && \
    tar -xzf backup.tar.gz
```

---

## GCM аутентифицированное шифрование

### Особенности GCM
- **Аутентификация и шифрование** в одной операции
- **Дополнительные данные (AAD)** - аутентифицируются но не шифруются
- **Nonce 12 байт** - рекомендуется для безопасности
- **Тег 16 байт** - гарантирует целостность

### Базовое использование

```bash
# Шифрование с автоматическим nonce
./bin/cryptocore -algorithm aes -mode gcm -encrypt \
    -key 00112233445566778899aabbccddeeff \
    -input sensitive.txt -output sensitive.enc

# Дешифрование
./bin/cryptocore -algorithm aes -mode gcm -decrypt \
    -key 00112233445566778899aabbccddeeff \
    -input sensitive.enc -output sensitive_decrypted.txt
```

### Использование AAD (Additional Authenticated Data)

```bash
# Преобразуйте метаданные в hex
AAD_HEX=$(echo -n "user=admin|timestamp=$(date +%s)" | xxd -p | tr -d '\n')

# Шифрование с AAD
./bin/cryptocore -algorithm aes -mode gcm -encrypt \
    -key 00112233445566778899aabbccddeeff \
    -input data.txt -output data.enc \
    -aad "$AAD_HEX"

# Дешифрование с тем же AAD
./bin/cryptocore -algorithm aes -mode gcm -decrypt \
    -key 00112233445566778899aabbccddeeff \
    -input data.enc -output data.dec \
    -aad "$AAD_HEX"
```

### Безопасная обработка ошибок

```bash
# Неверный AAD приведет к ошибке аутентификации
WRONG_AAD="00000000000000000000000000000000"

./bin/cryptocore -algorithm aes -mode gcm -decrypt \
    -key 00112233445566778899aabbccddeeff \
    -input data.enc -output /dev/null \
    -aad "$WRONG_AAD"
# Вывод: [ERROR] Authentication failed: AAD mismatch or ciphertext tampered
# Файл НЕ создается!
```

---

## PBKDF2 генерация ключей

### Назначение
Преобразование паролей в криптографические ключи.

### Базовое использование

```bash
# Генерация ключа с автоматической солью
./bin/cryptocore derive \
    --password "my strong password" \
    --iterations 100000 \
    --length 32

# Вы увидите:
# Generated random salt: 3a1975e12eeb9e6cdb4811bc51e84be5
# Derived key: 86e79e3acd1e9404046f064765120924c45d86e6f0fff01d9097efd348f2d588
```

### Расширенные параметры

```bash
# С указанной солью
./bin/cryptocore derive \
    --password "secret" \
    --salt a1b2c3d4e5f67890 \
    --iterations 50000 \
    --length 16

# Сохранение в файл
./bin/cryptocore derive \
    --password "$(cat password.txt)" \
    --iterations 310000 \
    --length 32 \
    --output derived_key.txt
```

### Рекомендации по параметрам

| Параметр | Рекомендуемое значение | Минимальное значение |
|----------|------------------------|----------------------|
| **Длина пароля** | 12+ символов | 8 символов |
| **Итерации** | 100,000-310,000 | 10,000 |
| **Длина ключа** | 32 байта (256 бит) | 16 байт |
| **Длина соли** | 16 байт (128 бит) | 8 байт |

```bash
# Безопасный пример
./bin/cryptocore derive \
    --password "Correct Horse Battery Staple" \
    --iterations 310000 \
    --length 32
```

---

## Сценарии использования

### Сценарий 1: Шифрование конфиденциальных документов

```bash
#!/bin/bash
# encrypt_document.sh

DOCUMENT="$1"
KEY_FILE="document_key.txt"

# Генерация ключа для документа
echo "Generating encryption key..."
./bin/cryptocore -algorithm aes -mode gcm -encrypt \
    -input "$DOCUMENT" \
    -output "${DOCUMENT}.enc" 2>&1 | \
    grep "Generated random key:" | \
    awk '{print $4}' > "$KEY_FILE"

echo "Document encrypted: ${DOCUMENT}.enc"
echo "Key saved to: $KEY_FILE (keep it secret!)"
```

### Сценарий 2: Проверка целостности загрузок

```bash
#!/bin/bash
# verify_download.sh

URL="$1"
EXPECTED_HASH="$2"

# Скачивание файла
wget -O downloaded_file "$URL"

# Проверка хеша
COMPUTED_HASH=$(./bin/cryptocore dgst --algorithm sha256 \
    --input downloaded_file | awk '{print $1}')

if [ "$COMPUTED_HASH" = "$EXPECTED_HASH" ]; then
    echo "✅ Download verified successfully"
else
    echo "❌ Download verification failed!"
    echo "Expected: $EXPECTED_HASH"
    echo "Got:      $COMPUTED_HASH"
    exit 1
fi
```

### Сценарий 3: Создание безопасного бэкапа

```bash
#!/bin/bash
# secure_backup.sh

BACKUP_DIR="/data/important"
ARCHIVE="backup_$(date +%Y%m%d).tar.gz"
KEY="$(cat /etc/backup_key.txt)"

# Создание архива
tar -czf "$ARCHIVE" "$BACKUP_DIR"

# Шифрование архива
./bin/cryptocore -algorithm aes -mode gcm -encrypt \
    -key "$KEY" \
    -input "$ARCHIVE" \
    -output "${ARCHIVE}.enc"

# Создание HMAC для проверки
./bin/cryptocore dgst --algorithm sha256 --hmac \
    --key "$KEY" \
    --input "${ARCHIVE}.enc" \
    --output "${ARCHIVE}.hmac"

echo "Backup created: ${ARCHIVE}.enc"
echo "Verification: ${ARCHIVE}.hmac"
```

---

## Устранение неполадок

### Распространенные ошибки

#### Ошибка 1: "Error: Key must be 16 bytes for AES-128"
```bash
# Неправильно: ключ 15 байт
./bin/cryptocore ... -key 00112233445566778899aabbccddee

# Правильно: ключ 16 байт (32 hex символа)
./bin/cryptocore ... -key 00112233445566778899aabbccddeeff
```

#### Ошибка 2: "Error: Input file is empty or invalid"
```bash
# Проверьте файл
ls -la input.txt
file input.txt

# Создайте тестовый файл
echo "Test data" > input.txt
```

#### Ошибка 3: "Error: HMAC verification failed"
```bash
# Проверьте:
# 1. Тот же ключ
# 2. Тот же файл (не изменен)
# 3. Тот же алгоритм хеширования
```

#### Ошибка 4: "[ERROR] Authentication failed: AAD mismatch"
```bash
# Убедитесь что используете тот же AAD при шифровании и дешифровании
echo -n "AAD data" | xxd -p  # Посмотрите hex представление
```

### Отладка

```bash
# Включите подробный вывод
./bin/cryptocore -algorithm aes -mode cbc -encrypt \
    -key 00112233445566778899aabbccddeeff \
    -input test.txt -output test.enc 2>&1

# Проверьте hex дамп файлов
xxd -l 64 encrypted.bin  # Первые 64 байта
xxd -l 32 decrypted.txt  # Первые 32 байта

# Сравните размеры файлов
ls -la *.enc *.dec
```

### Логирование

```bash
# Сохраните вывод в лог
./bin/cryptocore ... 2>&1 | tee operation.log

# Просмотр лога
cat operation.log | grep -E "(Error|Success|Warning)"
```

---

## Рекомендации по безопасности

### 🚫 Что НЕ делать

1. **Не используйте ECB в production**
   ```bash
   # ПЛОХО
   ./bin/cryptocore -algorithm aes -mode ecb -encrypt ...
   
   # ХОРОШО
   ./bin/cryptocore -algorithm aes -mode gcm -encrypt ...
   ```

2. **Не используйте слабые ключи**
   ```bash
   # ПЛОХО
   -key 00000000000000000000000000000000
   -key 0123456789abcdef0123456789abcdef
   
   # ХОРОШО - используйте генерацию ключей
   ./bin/cryptocore -algorithm aes -mode cbc -encrypt ...
   ```

3. **Не переиспользуйте nonce в GCM**
   - Каждый nonce должен быть уникальным
   - CryptoCore генерирует случайный nonce автоматически

4. **Не храните ключи в коде или логах**
   ```bash
   # ПЛОХО
   echo "Key: 001122..." >> script.log
   
   # ХОРОШО
   echo "Key generated and saved to secure location"
   ```

### ✅ Лучшие практики

1. **Всегда проверяйте HMAC перед использованием данных**
   ```bash
   # Сначала проверка
   ./bin/cryptocore dgst --algorithm sha256 --hmac \
       --key "$KEY" --input data.bin --verify expected.hmac
   
   # Только потом использование
   process_data data.bin
   ```

2. **Используйте достаточное количество итераций PBKDF2**
   ```bash
   # Минимум 100,000 итераций
   ./bin/cryptocore derive --iterations 100000 ...
   ```

3. **Регулярно обновляйте ключи**
   - Установите политику ротации ключей
   - Используйте разные ключи для разных целей

4. **Аудит и мониторинг**
   ```bash
   # Ведение логов операций (без ключей!)
   echo "$(date): Encrypted file $FILE" >> /var/log/cryptocore.log
   ```

### 🔐 Security Checklist

Перед использованием в production проверьте:

- [ ] Ключи генерируются криптографически стойким ГСЧ
- [ ] Память с ключами очищается после использования
- [ ] Используются рекомендованные режимы (CBC, GCM)
- [ ] Проверяется аутентификация перед дешифрованием
- [ ] Ошибки не раскрывают чувствительную информацию
- [ ] Все входные данные валидируются
- [ ] Реализована защита от timing attacks

---

## Дополнительные ресурсы

### Полезные команды

```bash
# Преобразование текста в hex
echo -n "Hello" | xxd -p  # 48656c6c6f

# Преобразование hex в текст
echo "48656c6c6f" | xxd -r -p  # Hello

# Генерация случайных данных
openssl rand -hex 16  # Случайный ключ
openssl rand -base64 32  # Случайные данные
```

### Интеграция с другими инструментами

```bash
# Шифрование с gpg и проверка с cryptocore
gpg --output encrypted.gpg --encrypt file.txt
./bin/cryptocore dgst --algorithm sha256 --input encrypted.gpg

# Использование с tar
tar -czf - directory/ | \
./bin/cryptocore -algorithm aes -mode ctr -encrypt \
    -key $(cat key.txt) -output backup.enc
```

### Производительность

```bash
# Тестирование скорости хеширования
time ./bin/cryptocore dgst --algorithm sha256 --input large_file.bin

# Тестирование скорости шифрования
time ./bin/cryptocore -algorithm aes -mode gcm -encrypt \
    -input large_file.bin -output /dev/null
```

---

## Получение помощи

### Отладка проблем
1. Проверьте версию: `./bin/cryptocore --version`
2. Включите подробный вывод
3. Проверьте размеры и форматы файлов
4. Сравните с OpenSSL для проверки

### Отчеты об ошибках
При возникновении проблем укажите:
1. Версию CryptoCore
2. Команду, которую вы выполняли
3. Полный вывод ошибки
4. Операционную систему и версию OpenSSL

---

## Лицензия и авторские права

© 2024 CryptoCore Educational Project

Этот проект предназначен исключительно для образовательных целей. Не используйте его для защиты действительно конфиденциальных данных без независимого аудита безопасности.

**Happy secure coding!** 🔐