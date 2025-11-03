#!/bin/bash

echo "=== CryptoCore Comprehensive Tests ==="

BIN="./bin/cryptocore"
KEY_HEX="00112233445566778899aabbccddeeff"
KEY="@$KEY_HEX"

# Check if binary exists
if [ ! -f "$BIN" ]; then
    echo "ERROR: cryptocore binary not found at $BIN"
    echo "Please build the project first using 'make'"
    exit 1
fi

echo "✓ Binary found: $BIN"

# Create test files
echo "Creating test files..."
echo "0123456789ABCDEF" > test_16.txt  # 16 bytes - no padding needed
echo "Test message for padding check" > test_text.txt  # Will need padding

echo "=== Test 1: Round-trip Tests ==="
for mode in ecb cbc cfb ofb ctr; do
    echo "Testing $mode..."
    $BIN -algorithm aes -mode $mode -encrypt -key $KEY -input test_16.txt -output test_$mode.enc
    $BIN -algorithm aes -mode $mode -decrypt -key $KEY -input test_$mode.enc -output test_$mode.dec
    
    if diff test_16.txt test_$mode.dec > /dev/null; then
        echo "  ✅ $mode round-trip PASSED"
    else
        echo "  ❌ $mode round-trip FAILED"
    fi
done

echo ""
echo "=== Test 2: OpenSSL Interoperability ==="

# ECB test
echo "Testing ECB interoperability..."
$BIN -algorithm aes -mode ecb -encrypt -key $KEY -input test_16.txt -output cc_ecb.enc
openssl enc -aes-128-ecb -d -K $KEY_HEX -in cc_ecb.enc -out os_ecb.dec -nopad 2>/dev/null

if diff test_16.txt os_ecb.dec > /dev/null; then
    echo "  ✅ ECB interoperability PASSED"
else
    echo "  ❌ ECB interoperability FAILED"
fi

# CBC test  
echo "Testing CBC interoperability..."
$BIN -algorithm aes -mode cbc -encrypt -key $KEY -input test_16.txt -output cc_cbc.enc
dd if=cc_cbc.enc of=iv.bin bs=16 count=1 status=none 2>/dev/null
dd if=cc_cbc.enc of=ciphertext.bin bs=16 skip=1 status=none 2>/dev/null
IV_HEX=$(xxd -p iv.bin 2>/dev/null | tr -d '\n')
openssl enc -aes-128-cbc -d -K $KEY_HEX -iv $IV_HEX -in ciphertext.bin -out os_cbc.dec -nopad 2>/dev/null

if diff test_16.txt os_cbc.dec > /dev/null; then
    echo "  ✅ CBC interoperability PASSED"
else
    echo "  ❌ CBC interoperability FAILED"
fi

echo ""
echo "=== Test 3: Padding Tests ==="
for mode in ecb cbc; do
    echo "Testing $mode with padding..."
    $BIN -algorithm aes -mode $mode -encrypt -key $KEY -input test_text.txt -output pad_$mode.enc
    $BIN -algorithm aes -mode $mode -decrypt -key $KEY -input pad_$mode.enc -output pad_$mode.dec
    
    if diff test_text.txt pad_$mode.dec > /dev/null; then
        echo "  ✅ $mode padding PASSED"
    else
        echo "  ❌ $mode padding FAILED"
    fi
done

# Cleanup
echo "Cleaning up..."
rm -f test_*.txt test_*.enc test_*.dec cc_*.enc os_*.dec iv.bin ciphertext.bin pad_*.enc pad_*.dec

echo ""
echo "=== ALL TESTS COMPLETED ==="
