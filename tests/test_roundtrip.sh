#!/bin/bash

# CryptoCore Round-trip Test Script
# Tests encryption and decryption for all modes

set -e

echo "=== CryptoCore Round-trip Tests ==="
echo

BIN_PATH="../bin/cryptocore"
TEST_DIR="test_files"
KEY="@00112233445566778899aabbccddeeff"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if binary exists
if [ ! -f "$BIN_PATH" ]; then
    echo -e "${RED}Error: cryptocore binary not found at $BIN_PATH${NC}"
    echo "Please build the project first using 'make'"
    exit 1
fi

# Create test directory if it doesn't exist
mkdir -p "$TEST_DIR"

# Create test files
echo "Creating test files..."
echo "This is a test file for CryptoCore." > "$TEST_DIR/test1.txt"
echo "Another test file with different content." > "$TEST_DIR/test2.txt"

# Generate a binary test file
head -c 100 /dev/urandom > "$TEST_DIR/test3.bin"

# Test function
test_mode() {
    local mode=$1
    local input_file="$TEST_DIR/test1.txt"
    local encrypted_file="$TEST_DIR/test1.$mode.enc"
    local decrypted_file="$TEST_DIR/test1.$mode.dec"
    
    echo "Testing $mode mode..."
    
    # Encrypt
    if ! "$BIN_PATH" -algorithm aes -mode "$mode" -encrypt -key "$KEY" -input "$input_file" -output "$encrypted_file" 2>/dev/null; then
        echo -e "${RED}FAIL: Encryption failed for $mode${NC}"
        return 1
    fi
    
    # Check if encrypted file was created
    if [ ! -f "$encrypted_file" ]; then
        echo -e "${RED}FAIL: Encrypted file not created for $mode${NC}"
        return 1
    fi
    
    # Decrypt
    if [ "$mode" = "ecb" ]; then
        # ECB mode - no IV handling
        if ! "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$encrypted_file" -output "$decrypted_file" 2>/dev/null; then
            echo -e "${RED}FAIL: Decryption failed for $mode${NC}"
            return 1
        fi
    else
        # For other modes, IV is read from file automatically
        if ! "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$encrypted_file" -output "$decrypted_file" 2>/dev/null; then
            echo -e "${RED}FAIL: Decryption failed for $mode${NC}"
            return 1
        fi
    fi
    
    # Check if decrypted file was created
    if [ ! -f "$decrypted_file" ]; then
        echo -e "${RED}FAIL: Decrypted file not created for $mode${NC}"
        return 1
    fi
    
    # Compare
    if diff "$input_file" "$decrypted_file" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS: $mode round-trip successful${NC}"
        # Clean up test files for this mode
        rm -f "$encrypted_file" "$decrypted_file"
        return 0
    else
        echo -e "${RED}FAIL: $mode round-trip failed - files differ${NC}"
        echo "Input file size: $(stat -c%s "$input_file") bytes"
        echo "Decrypted file size: $(stat -c%s "$decrypted_file") bytes"
        return 1
    fi
}

# Test all modes
modes=("ecb" "cbc" "cfb" "ofb" "ctr")
passed=0
total=0

echo "Starting round-trip tests..."
echo

for mode in "${modes[@]}"; do
    if test_mode "$mode"; then
        ((passed++))
    else
        # Debug info for failed test
        echo "Debug info for $mode:"
        ls -la "$TEST_DIR"/test1.$mode.* 2>/dev/null || echo "No test files found"
    fi
    ((total++))
    echo
done

# Clean up original test files
rm -f "$TEST_DIR"/test1.txt "$TEST_DIR"/test2.txt "$TEST_DIR"/test3.bin

echo "=== Test Summary ==="
echo "Passed: $passed/$total"

if [ $passed -eq $total ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi