#!/bin/bash

# Test GCM nonce uniqueness

echo "=== Testing GCM Nonce Uniqueness ==="

BIN="../bin/cryptocore"
TEST_DIR="../data/gcm_nonce_test"
KEY="00112233445566778899aabbccddeeff"

mkdir -p "$TEST_DIR"
echo "Test data for GCM" > "$TEST_DIR/test.txt"

echo "Encrypting same file 100 times with GCM..."
declare -a nonces
for i in {1..100}; do
    "$BIN" -algorithm aes -mode gcm -encrypt -key "$KEY" \
           -input "$TEST_DIR/test.txt" \
           -output "$TEST_DIR/enc_$i.bin" 2>&1 | grep "Generated nonce:" > "$TEST_DIR/nonce_$i.txt"
    
    # Extract nonce from output
    nonce=$(cat "$TEST_DIR/nonce_$i.txt" | cut -d' ' -f3)
    nonces[$i]="$nonce"
    
    # Check for duplicates
    for ((j=1; j<i; j++)); do
        if [ "${nonces[$j]}" = "${nonces[$i]}" ]; then
            echo "❌ DUPLICATE NONCE FOUND at iterations $j and $i: ${nonces[$i]}"
            exit 1
        fi
    done
done

echo "✓ All 100 nonces are unique"
echo "First nonce: ${nonces[1]}"
echo "Last nonce:  ${nonces[100]}"

# Cleanup
rm -rf "$TEST_DIR"
echo "=== GCM Nonce Test Passed ==="