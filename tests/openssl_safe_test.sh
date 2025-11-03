#!/bin/bash

echo "=== OPENSSL SAFE TEST (без удаления файлов) ==="

BIN="../bin/cryptocore"
KEY_HEX="00112233445566778899aabbccddeeff"
KEY="@$KEY_HEX"

# Создаем временную директорию для OpenSSL тестов
mkdir -p openssl_temp
cd openssl_temp

# Копируем тестовый файл
cp ../test_files/test_16_bytes.txt .

echo "Тестирую ECB с OpenSSL..."
# Шифруем CryptoCore
$BIN -algorithm aes -mode ecb -encrypt -key $KEY -input test_16_bytes.txt -output cc_ecb.enc

# Пытаемся расшифровать OpenSSL
if openssl enc -aes-128-ecb -d -K $KEY_HEX -in cc_ecb.enc -out openssl_ecb.dec -nopad 2>/dev/null; then
    if diff test_16_bytes.txt openssl_ecb.dec > /dev/null; then
        echo "✅ ECB: CryptoCore -> OpenSSL РАБОТАЕТ"
    else
        echo "❌ ECB: CryptoCore -> OpenSSL НЕ РАБОТАЕТ - файлы отличаются"
        echo "Оригинал: $(xxd -l 16 test_16_bytes.txt)"
        echo "OpenSSL:  $(xxd -l 16 openssl_ecb.dec)"
    fi
else
    echo "❌ ECB: OpenSSL не смог расшифровать"
fi

echo
echo "Тестирую CBC с OpenSSL..."
# Шифруем CryptoCore
$BIN -algorithm aes -mode cbc -encrypt -key $KEY -input test_16_bytes.txt -output cc_cbc.enc

# Извлекаем IV
dd if=cc_cbc.enc of=iv.bin bs=16 count=1 status=none 2>/dev/null
dd if=cc_cbc.enc of=ciphertext.bin bs=16 skip=1 status=none 2>/dev/null

if [ -f iv.bin ] && [ -f ciphertext.bin ]; then
    IV_HEX=$(xxd -p iv.bin | tr -d '\n')
    
    if openssl enc -aes-128-cbc -d -K $KEY_HEX -iv $IV_HEX -in ciphertext.bin -out openssl_cbc.dec -nopad 2>/dev/null; then
        if diff test_16_bytes.txt openssl_cbc.dec > /dev/null; then
            echo "✅ CBC: CryptoCore -> OpenSSL РАБОТАЕТ"
        else
            echo "❌ CBC: CryptoCore -> OpenSSL НЕ РАБОТАЕТ - файлы отличаются"
        fi
    else
        echo "❌ CBC: OpenSSL не смог расшифровать"
    fi
else
    echo "❌ CBC: Не удалось извлечь IV или шифртекст"
fi

# Возвращаемся и очищаем
cd ..
rm -rf openssl_temp

echo "=== OPENSSL ТЕСТ ЗАВЕРШЕН ==="
