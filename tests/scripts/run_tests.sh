#!/bin/bash

echo "=== CryptoCore Comprehensive Tests ==="

BIN="../bin/cryptocore" 
KEY_HEX="00112233445566778899aabbccddeeff"
KEY="$KEY_HEX"          

# Check if binary exists
if [ ! -f "$BIN" ]; then
    echo "ERROR: cryptocore binary not found at $BIN"
    echo "Please build the project first using 'make'"
    exit 1
fi

echo "✓ Binary found: $BIN"

# Create test files in data directory
echo "Creating test files..."
cd ../data
echo "0123456789ABCDEF" > test_16.txt
echo "Test message for padding check" > test_text.txt
cd ../scripts

echo "=== Test 1: Round-trip Tests ==="
for mode in ecb cbc cfb ofb ctr; do
    echo "Testing $mode..."
    $BIN -algorithm aes -mode $mode -encrypt -key $KEY -input ../data/test_16.txt -output ../data/test_$mode.enc
    $BIN -algorithm aes -mode $mode -decrypt -key $KEY -input ../data/test_$mode.enc -output ../data/test_$mode.dec
    
    if diff ../data/test_16.txt ../data/test_$mode.dec > /dev/null; then
        echo "  ✅ $mode round-trip PASSED"
    else
        echo "  ❌ $mode round-trip FAILED"
    fi
done

echo ""
echo "=== Test 2: OpenSSL Interoperability ==="

# ECB test
echo "Testing ECB interoperability..."
$BIN -algorithm aes -mode ecb -encrypt -key $KEY -input ../data/test_16.txt -output ../data/cc_ecb.enc
openssl enc -aes-128-ecb -d -K $KEY_HEX -in ../data/cc_ecb.enc -out ../data/os_ecb.dec -nopad 2>/dev/null

if diff ../data/test_16.txt ../data/os_ecb.dec > /dev/null; then
    echo "  ✅ ECB interoperability PASSED"
else
    echo "  ❌ ECB interoperability FAILED"
fi

# CBC test  
echo "Testing CBC interoperability..."
$BIN -algorithm aes -mode cbc -encrypt -key $KEY -input ../data/test_16.txt -output ../data/cc_cbc.enc
dd if=../data/cc_cbc.enc of=../data/iv.bin bs=16 count=1 status=none 2>/dev/null
dd if=../data/cc_cbc.enc of=../data/ciphertext.bin bs=16 skip=1 status=none 2>/dev/null
IV_HEX=$(xxd -p ../data/iv.bin 2>/dev/null | tr -d '\n')
openssl enc -aes-128-cbc -d -K $KEY_HEX -iv $IV_HEX -in ../data/ciphertext.bin -out ../data/os_cbc.dec -nopad 2>/dev/null

if diff ../data/test_16.txt ../data/os_cbc.dec > /dev/null; then
    echo "  ✅ CBC interoperability PASSED"
else
    echo "  ❌ CBC interoperability FAILED"
fi

echo ""
echo "=== Test 3: Padding Tests ==="
for mode in ecb cbc; do
    echo "Testing $mode with padding..."
    $BIN -algorithm aes -mode $mode -encrypt -key $KEY -input ../data/test_text.txt -output ../data/pad_$mode.enc
    $BIN -algorithm aes -mode $mode -decrypt -key $KEY -input ../data/pad_$mode.enc -output ../data/pad_$mode.dec
    
    if diff ../data/test_text.txt ../data/pad_$mode.dec > /dev/null; then
        echo "  ✅ $mode padding PASSED"
    else
        echo "  ❌ $mode padding FAILED"
    fi
done

# Cleanup
echo "Cleaning up..."
rm -f ../data/test_*.txt ../data/*.enc ../data/*.dec ../data/iv.bin ../data/ciphertext.bin

echo ""
echo "=== ALL TESTS COMPLETED ==="