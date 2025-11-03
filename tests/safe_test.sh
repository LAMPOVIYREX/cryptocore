#!/bin/bash

echo "=== SAFE CRYPTOCORE TESTS (без удаления файлов) ==="

BIN="../bin/cryptocore"
KEY="@00112233445566778899aabbccddeeff"

# Проверяем что бинарник существует
if [ ! -f "$BIN" ]; then
    echo "ОШИБКА: cryptocore бинарник не найден!"
    exit 1
fi

echo "✓ Бинарник найден"
echo "✓ Тестовые файлы сохранены"
echo

# Тест 1: Базовые режимы
echo "--- ТЕСТ 1: БАЗОВЫЕ РЕЖИМЫ ---"
for mode in ecb cbc cfb ofb ctr; do
    echo -n "Тестирую $mode... "
    $BIN -algorithm aes -mode $mode -encrypt -key $KEY -input test_files/test1.txt -output test_${mode}.enc
    $BIN -algorithm aes -mode $mode -decrypt -key $KEY -input test_${mode}.enc -output test_${mode}.dec
    
    if diff test_files/test1.txt test_${mode}.dec > /dev/null 2>&1; then
        echo "✅ УСПЕХ"
    else
        echo "❌ ОШИБКА"
    fi
done

echo

# Тест 2: Разные размеры файлов
echo "--- ТЕСТ 2: РАЗНЫЕ РАЗМЕРЫ ФАЙЛОВ ---"
echo -n "16 байт (без padding)... "
$BIN -algorithm aes -mode ecb -encrypt -key $KEY -input test_files/test_16_bytes.txt -output test_16_enc.enc
$BIN -algorithm aes -mode ecb -decrypt -key $KEY -input test_16_enc.enc -output test_16_dec.txt
diff test_files/test_16_bytes.txt test_16_dec.txt > /dev/null 2>&1 && echo "✅ УСПЕХ" || echo "❌ ОШИБКА"

echo -n "15 байт (требует padding)... "
$BIN -algorithm aes -mode ecb -encrypt -key $KEY -input test_files/test_15_bytes.txt -output test_15_enc.enc
$BIN -algorithm aes -mode ecb -decrypt -key $KEY -input test_15_enc.enc -output test_15_dec.txt
diff test_files/test_15_bytes.txt test_15_dec.txt > /dev/null 2>&1 && echo "✅ УСПЕХ" || echo "❌ ОШИБКА"

echo

# Тест 3: Бинарные файлы
echo "--- ТЕСТ 3: БИНАРНЫЕ ФАЙЛЫ ---"
echo -n "Случайные данные... "
$BIN -algorithm aes -mode cbc -encrypt -key $KEY -input test_files/random_binary.bin -output test_bin_enc.enc
$BIN -algorithm aes -mode cbc -decrypt -key $KEY -input test_bin_enc.enc -output test_bin_dec.bin
diff test_files/random_binary.bin test_bin_dec.bin > /dev/null 2>&1 && echo "✅ УСПЕХ" || echo "❌ ОШИБКА"

echo

# Тест 4: IV работа
echo "--- ТЕСТ 4: ПРОВЕРКА IV ---"
echo "Шифруем CBC с автоматическим IV..."
$BIN -algorithm aes -mode cbc -encrypt -key $KEY -input test_files/test1.txt -output test_cbc_iv.enc
echo "Размер зашифрованного файла: $(stat -c%s test_cbc_iv.enc) байт"
echo "Первые 32 байта (hex):"
xxd -l 32 test_cbc_iv.enc

echo

# Очищаем только временные файлы тестов (не оригинальные тестовые файлы)
echo "Очищаю временные файлы тестов..."
rm -f test_*.enc test_*.dec test_*.bin

echo "=== ТЕСТИРОВАНИЕ ЗАВЕРШЕНО ==="
echo "✓ Оригинальные тестовые файлы сохранены в test_files/"
echo "✓ Все временные файлы удалены"
