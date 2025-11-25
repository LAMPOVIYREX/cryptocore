#!/bin/bash

echo "=== Key Generation Integration Test ==="

BIN="./bin/cryptocore"  # ИЗМЕНИЛИ С ../bin/cryptocore на ./bin/cryptocore
TEST_FILE="test_key_gen.txt"

# Create test file
echo "Test data for key generation" > "$TEST_FILE"

echo "1. Testing encryption with auto-generated key..."
output=$("$BIN" -algorithm aes -mode cbc -encrypt -input "$TEST_FILE" -output "encrypted.bin" 2>&1)

# Extract key from output (новый формат без @)
if echo "$output" | grep -q "Generated random key: [0-9a-fA-F]\{32\}"; then
    generated_key=$(echo "$output" | grep "Generated random key: " | cut -d' ' -f4)
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
if "$BIN" -algorithm aes -mode cbc -decrypt -key "$generated_key" -input "encrypted.bin" -output "decrypted.txt"; then
    echo "✓ Decryption with generated key successful"
else
    echo "✗ Decryption with generated key failed"
    exit 1
fi

echo "3. Verifying file integrity..."
if diff "$TEST_FILE" "decrypted.txt" > /dev/null; then
    echo "✓ File integrity verified"
else
    echo "✗ File integrity check failed"
    exit 1
fi

echo "4. Testing that decryption requires key..."
if "$BIN" -algorithm aes -mode cbc -decrypt -input "encrypted.bin" -output "should_fail.txt" 2>/dev/null; then
    echo "✗ Decryption without key should have failed"
    exit 1
else
    echo "✓ Decryption correctly requires key"
fi

# Test with new key format (без @)
echo "5. Testing encryption with explicit key (new format)..."
if "$BIN" -algorithm aes -mode ecb -encrypt -key "$generated_key" -input "$TEST_FILE" -output "explicit_encrypted.bin"; then
    echo "✓ Encryption with explicit key (new format) successful"
else
    echo "✗ Encryption with explicit key failed"
    exit 1
fi

# Cleanup
rm -f "$TEST_FILE" "encrypted.bin" "decrypted.txt" "should_fail.txt" "explicit_encrypted.bin"

echo ""
echo "=== All Key Generation Tests Passed! ==="