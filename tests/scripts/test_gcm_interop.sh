#!/bin/bash

# GCM Interoperability Test with OpenSSL

echo "=== GCM OpenSSL Interoperability Test ==="

BIN="../bin/cryptocore"
KEY_HEX="00112233445566778899aabbccddeeff"
KEY="$KEY_HEX"
AAD_HEX="feedfacedeadbeeffeedfacedeadbeefabaddad2"
TEST_FILE="../data/gcm_test.txt"

mkdir -p ../data
echo "Test message for GCM interoperability" > "$TEST_FILE"

echo "1. CryptoCore -> OpenSSL"
# Encrypt with CryptoCore
"$BIN" -algorithm aes -mode gcm -encrypt -key "$KEY" -aad "$AAD_HEX" \
       -input "$TEST_FILE" -output "../data/cc_gcm.enc"

# Extract components
dd if="../data/cc_gcm.enc" of="../data/nonce.bin" bs=12 count=1 status=none
dd if="../data/cc_gcm.enc" of="../data/ciphertext_tag.bin" bs=12 skip=1 status=none
dd if="../data/ciphertext_tag.bin" of="../data/ciphertext.bin" bs=1 count=$(( $(stat -c%s "../data/ciphertext_tag.bin") - 16 )) status=none
dd if="../data/ciphertext_tag.bin" of="../data/tag.bin" bs=16 skip=$(($(stat -c%s "../data/ciphertext_tag.bin") / 16 - 1)) status=none

NONCE_HEX=$(xxd -p "../data/nonce.bin" | tr -d '\n')
TAG_HEX=$(xxd -p "../data/tag.bin" | tr -d '\n')

# Decrypt with OpenSSL
openssl enc -aes-128-gcm -d -K "$KEY_HEX" -iv "$NONCE_HEX" \
            -in "../data/ciphertext.bin" \
            -out "../data/openssl_decrypted.txt" \
            -aad "$AAD_HEX" -tag "$TAG_HEX" 2>/dev/null

if diff "$TEST_FILE" "../data/openssl_decrypted.txt" > /dev/null; then
    echo "   ✅ CryptoCore -> OpenSSL PASSED"
else
    echo "   ❌ CryptoCore -> OpenSSL FAILED"
fi

echo ""
echo "2. OpenSSL -> CryptoCore"
# Encrypt with OpenSSL
NONCE_HEX="cafebabefacedbaddecaf888"
openssl enc -aes-128-gcm -K "$KEY_HEX" -iv "$NONCE_HEX" \
            -in "$TEST_FILE" \
            -out "../data/openssl_gcm.enc" \
            -aad "$AAD_HEX" 2>/dev/null

# OpenSSL outputs ciphertext + tag
openssl enc -aes-128-gcm -K "$KEY_HEX" -iv "$NONCE_HEX" \
            -in "$TEST_FILE" \
            -out "../data/ciphertext_only.bin" \
            -aad "$AAD_HEX" 2>/dev/null

# Extract tag from OpenSSL output
TAG_HEX=$(openssl enc -aes-128-gcm -K "$KEY_HEX" -iv "$NONCE_HEX" \
                     -in "$TEST_FILE" \
                     -aad "$AAD_HEX" 2>&1 | grep -o 'tag [0-9a-f]*' | cut -d' ' -f2)

# Create file in CryptoCore format: nonce(12) + ciphertext + tag(16)
cat "../data/nonce.bin" "../data/ciphertext_only.bin" > "../data/combined.bin"
echo "$TAG_HEX" | xxd -r -p >> "../data/combined.bin"

# Decrypt with CryptoCore
"$BIN" -algorithm aes -mode gcm -decrypt -key "$KEY" -aad "$AAD_HEX" \
       -input "../data/combined.bin" \
       -output "../data/cc_decrypted.txt"

if diff "$TEST_FILE" "../data/cc_decrypted.txt" > /dev/null; then
    echo "   ✅ OpenSSL -> CryptoCore PASSED"
else
    echo "   ❌ OpenSSL -> CryptoCore FAILED"
fi

# Cleanup
rm -f "$TEST_FILE" "../data"/*.enc "../data"/*.bin "../data"/*.txt
rmdir "../data" 2>/dev/null || true

echo ""
echo "=== GCM Interoperability Test Complete ==="