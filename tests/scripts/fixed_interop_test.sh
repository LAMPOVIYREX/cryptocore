#!/bin/bash

# Fixed Interoperability Test Script

echo "=== Fixed CryptoCore OpenSSL Interoperability Test ==="

BIN="../bin/cryptocore"
KEY_HEX="00112233445566778899aabbccddeeff"
KEY="$KEY_HEX"

# Check if binary exists
if [ ! -f "$BIN" ]; then
    echo "ERROR: cryptocore binary not found at $BIN"
    echo "Please build the project first using 'make' in the root directory"
    exit 1
fi

# Create test directory
mkdir -p ../data/test_files
cd ../data/test_files

# Create test file with specific size (multiple of 16 bytes for no-padding tests)
echo -n "0123456789ABCDEF" > "test_16.txt"  # 16 bytes
echo "This is a test file for CryptoCore interoperability testing." > "test_text.txt"

echo "=== Testing Round-trip First ==="

# Test round-trip for all modes
for mode in ecb cbc cfb ofb ctr; do
    echo "Testing $mode round-trip..."
    "$BIN" -algorithm aes -mode "$mode" -encrypt -key "$KEY" -input "test_16.txt" -output "test_${mode}.enc"
    "$BIN" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "test_${mode}.enc" -output "test_${mode}.dec"
    
    if diff "test_16.txt" "test_${mode}.dec" > /dev/null; then
        echo "✓ $mode round-trip OK"
    else
        echo "✗ $mode round-trip FAILED"
    fi
done

echo ""
echo "=== Testing OpenSSL Interoperability ==="

# Test 1: CryptoCore -> OpenSSL (ECB)
echo "1. CryptoCore -> OpenSSL (ECB)"
"$BIN" -algorithm aes -mode ecb -encrypt -key "$KEY" -input "test_16.txt" -output "cc_ecb.enc"

# OpenSSL decryption
if openssl enc -aes-128-ecb -d -K "$KEY_HEX" -in "cc_ecb.enc" -out "os_ecb.dec" -nopad 2>/dev/null; then
    if diff "test_16.txt" "os_ecb.dec" > /dev/null; then
        echo "   ✓ ECB: CryptoCore -> OpenSSL OK"
    else
        echo "   ✗ ECB: CryptoCore -> OpenSSL FAILED - files differ"
        echo "   Original size: $(stat -c%s test_16.txt), Decrypted: $(stat -c%s os_ecb.dec)"
    fi
else
    echo "   ✗ ECB: CryptoCore -> OpenSSL FAILED - OpenSSL decryption error"
fi

# Test 2: OpenSSL -> CryptoCore (ECB)  
echo "2. OpenSSL -> CryptoCore (ECB)"
if openssl enc -aes-128-ecb -K "$KEY_HEX" -in "test_16.txt" -out "os_ecb.enc" -nopad 2>/dev/null; then
    "$BIN" -algorithm aes -mode ecb -decrypt -key "$KEY" -input "os_ecb.enc" -output "cc_ecb.dec"

    if diff "test_16.txt" "cc_ecb.dec" > /dev/null; then
        echo "   ✓ ECB: OpenSSL -> CryptoCore OK"
    else
        echo "   ✗ ECB: OpenSSL -> CryptoCore FAILED - files differ"
    fi
else
    echo "   ✗ ECB: OpenSSL -> CryptoCore FAILED - OpenSSL encryption error"
fi

# Test 3: CryptoCore -> OpenSSL (CBC)
echo "3. CryptoCore -> OpenSSL (CBC)"
"$BIN" -algorithm aes -mode cbc -encrypt -key "$KEY" -input "test_16.txt" -output "cc_cbc.enc"

# Extract IV and ciphertext
dd if="cc_cbc.enc" of="iv.bin" bs=16 count=1 status=none 2>/dev/null
dd if="cc_cbc.enc" of="ciphertext.bin" bs=16 skip=1 status=none 2>/dev/null

if [ -f "iv.bin" ] && [ -f "ciphertext.bin" ]; then
    IV_FROM_FILE=$(xxd -p "iv.bin" | tr -d '\n')

    if openssl enc -aes-128-cbc -d -K "$KEY_HEX" -iv "$IV_FROM_FILE" -in "ciphertext.bin" -out "os_cbc.dec" -nopad 2>/dev/null; then
        if diff "test_16.txt" "os_cbc.dec" > /dev/null; then
            echo "   ✓ CBC: CryptoCore -> OpenSSL OK"
        else
            echo "   ✗ CBC: CryptoCore -> OpenSSL FAILED - files differ"
        fi
    else
        echo "   ✗ CBC: CryptoCore -> OpenSSL FAILED - OpenSSL decryption error"
    fi
else
    echo "   ✗ CBC: CryptoCore -> OpenSSL FAILED - could not extract IV/ciphertext"
fi

# Test 4: OpenSSL -> CryptoCore (CBC)
echo "4. OpenSSL -> CryptoCore (CBC)"
if openssl enc -aes-128-cbc -K "$KEY_HEX" -iv "00000000000000000000000000000000" -in "test_16.txt" -out "os_cbc.enc" -nopad 2>/dev/null; then
    "$BIN" -algorithm aes -mode cbc -decrypt -key "$KEY" -iv "00000000000000000000000000000000" -input "os_cbc.enc" -output "cc_cbc.dec"

    if diff "test_16.txt" "cc_cbc.dec" > /dev/null; then
        echo "   ✓ CBC: OpenSSL -> CryptoCore OK"
    else
        echo "   ✗ CBC: OpenSSL -> CryptoCore FAILED - files differ"
    fi
else
    echo "   ✗ CBC: OpenSSL -> CryptoCore FAILED - OpenSSL encryption error"
fi

# Test with text files (with padding)
echo ""
echo "=== Testing with Padding ==="

# CryptoCore CBC with text (auto padding)
echo "Testing CBC with padding..."
"$BIN" -algorithm aes -mode cbc -encrypt -key "$KEY" -input "test_text.txt" -output "cc_cbc_pad.enc"

# Extract IV and ciphertext
dd if="cc_cbc_pad.enc" of="iv_pad.bin" bs=16 count=1 status=none 2>/dev/null
dd if="cc_cbc_pad.enc" of="ciphertext_pad.bin" bs=16 skip=1 status=none 2>/dev/null

if [ -f "iv_pad.bin" ] && [ -f "ciphertext_pad.bin" ]; then
    IV_PAD=$(xxd -p "iv_pad.bin" | tr -d '\n')

    # OpenSSL decryption with padding (no -nopad flag)
    if openssl enc -aes-128-cbc -d -K "$KEY_HEX" -iv "$IV_PAD" -in "ciphertext_pad.bin" -out "os_cbc_pad.dec" 2>/dev/null; then
        if diff "test_text.txt" "os_cbc_pad.dec" > /dev/null; then
            echo "   ✓ CBC with padding: CryptoCore -> OpenSSL OK"
        else
            echo "   ✗ CBC with padding: CryptoCore -> OpenSSL FAILED - files differ"
        fi
    else
        echo "   ✗ CBC with padding: CryptoCore -> OpenSSL FAILED - OpenSSL decryption error"
    fi
else
    echo "   ✗ CBC with padding: CryptoCore -> OpenSSL FAILED - could not extract IV/ciphertext"
fi

# Cleanup
cd ../../..
rm -rf ../data/test_files

echo ""
echo "=== Interoperability Test Complete ==="