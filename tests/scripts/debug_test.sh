#!/bin/bash

# Debug script to test individual modes

set -e

BIN_PATH="../bin/cryptocore"
TEST_DIR="../data/test_files"
KEY="00112233445566778899aabbccddeeff"
IV="aabbccddeeff00112233445566778899"

mkdir -p "$TEST_DIR"

# Create test file
echo "Hello, CryptoCore! This is a test." > "$TEST_DIR/debug_test.txt"

test_single_mode() {
    local mode=$1
    local input_file="$TEST_DIR/debug_test.txt"
    local encrypted_file="$TEST_DIR/debug_$mode.enc"
    local decrypted_file="$TEST_DIR/debug_$mode.dec"
    
    echo "=== Testing $mode mode ==="
    
    # Clean up
    rm -f "$encrypted_file" "$decrypted_file"
    
    # Encrypt
    echo "Encrypting..."
    if "$BIN_PATH" -algorithm aes -mode "$mode" -encrypt -key "$KEY" -input "$input_file" -output "$encrypted_file"; then
        echo "✓ Encryption successful"
        echo "Encrypted file size: $(stat -c%s "$encrypted_file") bytes"
        
        # Show first 32 bytes of encrypted file in hex
        echo "First 32 bytes (hex):"
        xxd -l 32 "$encrypted_file"
    else
        echo "✗ Encryption failed"
        return 1
    fi
    
    # Decrypt
    echo "Decrypting..."
    if [ "$mode" = "ecb" ]; then
        if "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$encrypted_file" -output "$decrypted_file"; then
            echo "✓ Decryption successful"
        else
            echo "✗ Decryption failed"
            return 1
        fi
    else
        # Try both with and without IV
        echo "Trying decryption without IV (read from file)..."
        if "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$encrypted_file" -output "$decrypted_file"; then
            echo "✓ Decryption successful (IV from file)"
        else
            echo "Trying decryption with explicit IV..."
            if "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -iv "$IV" -input "$encrypted_file" -output "$decrypted_file"; then
                echo "✓ Decryption successful (with explicit IV)"
            else
                echo "✗ All decryption attempts failed"
                return 1
            fi
        fi
    fi
    
    # Compare
    if diff "$input_file" "$decrypted_file" > /dev/null; then
        echo "✓ Round-trip successful - files are identical"
        return 0
    else
        echo "✗ Round-trip failed - files differ"
        echo "Original: $(stat -c%s "$input_file") bytes"
        echo "Decrypted: $(stat -c%s "$decrypted_file") bytes"
        return 1
    fi
}

# Test specific mode or all
if [ $# -eq 1 ]; then
    test_single_mode "$1"
else
    echo "Usage: $0 [mode]"
    echo "Modes: ecb, cbc, cfb, ofb, ctr"
    echo ""
    echo "Available tests:"
    echo "  ./test_roundtrip.sh    - Basic round-trip tests"
    echo "  ./test_interoperability.sh - OpenSSL compatibility tests"
    echo "  ./debug_test.sh [mode] - Debug individual mode"
fi