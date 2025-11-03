#!/bin/bash

# Padding Test Script

echo "=== Padding Test ==="

BIN="../bin/cryptocore"
KEY="@00112233445566778899aabbccddeeff"

# Check if binary exists
if [ ! -f "$BIN" ]; then
    echo "ERROR: cryptocore binary not found at $BIN"
    exit 1
fi

mkdir -p padding_test
cd padding_test

# Create test files of different sizes
echo -n "15_bytes_____" > "15.txt"  # 15 bytes
echo -n "16_bytes_______" > "16.txt"  # 16 bytes  
echo -n "17_bytes________" > "17.txt"  # 17 bytes
echo -n "31_bytes_______________________" > "31.txt"  # 31 bytes
echo -n "32_bytes______________________________" > "32.txt"  # 32 bytes

echo "Testing padding for different file sizes..."

for file in 15.txt 16.txt 17.txt 31.txt 32.txt; do
    size=$(stat -c%s "$file")
    echo "File: $file ($size bytes)"
    
    # Test ECB (requires padding)
    if "$BIN" -algorithm aes -mode ecb -encrypt -key "$KEY" -input "$file" -output "${file%.txt}.ecb.enc" 2>/dev/null && \
       "$BIN" -algorithm aes -mode ecb -decrypt -key "$KEY" -input "${file%.txt}.ecb.enc" -output "${file%.txt}.ecb.dec" 2>/dev/null; then
        if diff "$file" "${file%.txt}.ecb.dec" > /dev/null; then
            echo "  ✓ ECB padding OK"
        else
            echo "  ✗ ECB padding FAILED"
        fi
    else
        echo "  ✗ ECB padding FAILED - encryption/decryption error"
    fi
    
    # Test CBC (requires padding)
    if "$BIN" -algorithm aes -mode cbc -encrypt -key "$KEY" -input "$file" -output "${file%.txt}.cbc.enc" 2>/dev/null && \
       "$BIN" -algorithm aes -mode cbc -decrypt -key "$KEY" -input "${file%.txt}.cbc.enc" -output "${file%.txt}.cbc.dec" 2>/dev/null; then
        if diff "$file" "${file%.txt}.cbc.dec" > /dev/null; then
            echo "  ✓ CBC padding OK"
        else
            echo "  ✗ CBC padding FAILED"
        fi
    else
        echo "  ✗ CBC padding FAILED - encryption/decryption error"
    fi
    
    # Test CFB (no padding)
    if "$BIN" -algorithm aes -mode cfb -encrypt -key "$KEY" -input "$file" -output "${file%.txt}.cfb.enc" 2>/dev/null && \
       "$BIN" -algorithm aes -mode cfb -decrypt -key "$KEY" -input "${file%.txt}.cfb.enc" -output "${file%.txt}.cfb.dec" 2>/dev/null; then
        if diff "$file" "${file%.txt}.cfb.dec" > /dev/null; then
            echo "  ✓ CFB no-padding OK"
        else
            echo "  ✗ CFB no-padding FAILED"
        fi
    else
        echo "  ✗ CFB no-padding FAILED - encryption/decryption error"
    fi
    
    echo ""
done

cd ..
rm -rf padding_test

echo "=== Padding Test Complete ==="