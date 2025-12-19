#!/bin/bash

echo "=== Key Generation Integration Test ==="

# Получаем абсолютный путь
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$PROJECT_ROOT/bin/cryptocore"
TEST_DIR="$PROJECT_ROOT/tests/data"
TEST_FILE="$TEST_DIR/test_key_gen.txt"
RESULTS_DIR="$PROJECT_ROOT/tests/results"

# Создаем директории
mkdir -p "$TEST_DIR"
mkdir -p "$RESULTS_DIR"

# Создаем тестовый файл
echo "Test data for key generation" > "$TEST_FILE"
echo "Additional test line" >> "$TEST_FILE"

echo "1. Testing encryption with auto-generated key..."
output=$("$BIN" -algorithm aes -mode cbc -encrypt -input "$TEST_FILE" -output "$RESULTS_DIR/encrypted.bin" 2>&1)

# Extract key from output
if echo "$output" | grep -q "Generated random key: [0-9a-fA-F]\{32\}"; then
    generated_key=$(echo "$output" | grep "Generated random key: " | awk '{print $4}')
    echo "✓ Key generation successful: $generated_key"
    
    # Проверяем что ключ не содержит @
    if echo "$generated_key" | grep -q "@"; then
        echo "✗ Key contains @ prefix - this should not happen!"
        exit 1
    fi
else
    echo "✗ Key generation failed or wrong format"
    echo "Output was: $output"
    exit 1
fi

echo "2. Testing decryption with generated key..."
if "$BIN" -algorithm aes -mode cbc -decrypt -key "$generated_key" \
    -input "$RESULTS_DIR/encrypted.bin" -output "$RESULTS_DIR/decrypted.txt" 2>&1 | grep -q "Success"; then
    echo "✓ Decryption with generated key successful"
else
    echo "✗ Decryption with generated key failed"
    exit 1
fi

echo "3. Verifying file integrity..."
if diff "$TEST_FILE" "$RESULTS_DIR/decrypted.txt" > /dev/null; then
    echo "✓ File integrity verified"
else
    echo "✗ File integrity check failed"
    exit 1
fi

echo "4. Testing that decryption requires key..."
if "$BIN" -algorithm aes -mode cbc -decrypt \
    -input "$RESULTS_DIR/encrypted.bin" -output "$RESULTS_DIR/should_fail.txt" 2>&1 | grep -q "Error"; then
    echo "✓ Decryption correctly requires key"
else
    echo "✗ Decryption without key should have failed"
    exit 1
fi

# Test with new key format (без @)
echo "5. Testing encryption with explicit key..."
if "$BIN" -algorithm aes -mode ecb -encrypt -key "$generated_key" \
    -input "$TEST_FILE" -output "$RESULTS_DIR/explicit_encrypted.bin" 2>&1 | grep -q "Success"; then
    echo "✓ Encryption with explicit key successful"
else
    echo "✗ Encryption with explicit key failed"
    exit 1
fi

echo ""
echo "=== All Key Generation Tests Passed! ==="

# Cleanup optional
# rm -rf "$RESULTS_DIR"