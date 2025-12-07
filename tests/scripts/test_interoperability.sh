#!/bin/bash

# CryptoCore OpenSSL Interoperability Test Script
# Tests compatibility between CryptoCore and OpenSSL

set -e

echo "=== CryptoCore OpenSSL Interoperability Tests ==="
echo

BIN_PATH="../bin/cryptocore"
TEST_DIR="../data/test_files"
KEY_HEX="00112233445566778899aabbccddeeff"
KEY="$KEY_HEX"
IV_HEX="aabbccddeeff00112233445566778899"
IV="$IV_HEX"

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

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl command not found${NC}"
    echo "Install with: sudo apt-get install openssl"
    exit 1
fi

# Check if xxd is available
if ! command -v xxd &> /dev/null; then
    echo -e "${RED}Error: xxd command not found${NC}"
    echo "Install with: sudo apt-get install xxd"
    exit 1
fi

# Create test directory if it doesn't exist
mkdir -p "$TEST_DIR"

# Create test file
echo "This is a test file for interoperability testing." > "$TEST_DIR/interop_test.txt"
TEST_FILE_SIZE=$(stat -c%s "$TEST_DIR/interop_test.txt")
echo "Test file size: $TEST_FILE_SIZE bytes"

# Test function for CryptoCore -> OpenSSL
test_cryptocore_to_openssl() {
    local mode=$1
    local openssl_mode=$2
    local input_file="$TEST_DIR/interop_test.txt"
    local cryptocore_encrypted="$TEST_DIR/interop_${mode}_cryptocore.enc"
    local iv_file="$TEST_DIR/iv.bin"
    local ciphertext_only="$TEST_DIR/ciphertext_only.bin"
    local openssl_decrypted="$TEST_DIR/decrypted_openssl.txt"
    
    echo "Testing CryptoCore -> OpenSSL for $mode mode..."
    
    # Clean up any existing files
    rm -f "$cryptocore_encrypted" "$iv_file" "$ciphertext_only" "$openssl_decrypted"
    
    # Encrypt with CryptoCore
    echo "Encrypting with CryptoCore..."
    if ! "$BIN_PATH" -algorithm aes -mode "$mode" -encrypt -key "$KEY" -input "$input_file" -output "$cryptocore_encrypted" 2>/dev/null; then
        echo -e "${RED}FAIL: CryptoCore encryption failed for $mode${NC}"
        return 1
    fi
    
    # Check if encrypted file was created
    if [ ! -f "$cryptocore_encrypted" ]; then
        echo -e "${RED}FAIL: CryptoCore encrypted file not created for $mode${NC}"
        return 1
    fi
    
    local encrypted_size=$(stat -c%s "$cryptocore_encrypted")
    echo "CryptoCore encrypted file size: $encrypted_size bytes"
    
    if [ "$mode" != "ecb" ]; then
        # Extract IV and ciphertext for modes that use IV
        echo "Extracting IV and ciphertext..."
        dd if="$cryptocore_encrypted" of="$iv_file" bs=16 count=1 status=none
        dd if="$cryptocore_encrypted" of="$ciphertext_only" bs=16 skip=1 status=none
        
        # Check if extraction worked
        if [ ! -f "$iv_file" ] || [ ! -f "$ciphertext_only" ]; then
            echo -e "${RED}FAIL: Failed to extract IV or ciphertext for $mode${NC}"
            return 1
        fi
        
        # Get IV as hex string
        IV_FROM_FILE=$(xxd -p "$iv_file" | tr -d '\n')
        echo "IV from file: $IV_FROM_FILE"
        
        # Decrypt with OpenSSL
        echo "Decrypting with OpenSSL..."
        if ! openssl enc -aes-128-$openssl_mode -d -K "$KEY_HEX" -iv "$IV_FROM_FILE" -in "$ciphertext_only" -out "$openssl_decrypted" 2>/dev/null; then
            echo -e "${RED}FAIL: OpenSSL decryption failed for $mode${NC}"
            return 1
        fi
    else {
        # ECB mode - no IV
        cp "$cryptocore_encrypted" "$ciphertext_only"
        echo "Decrypting ECB with OpenSSL..."
        if ! openssl enc -aes-128-ecb -d -K "$KEY_HEX" -in "$ciphertext_only" -out "$openssl_decrypted" 2>/dev/null; then
            echo -e "${RED}FAIL: OpenSSL decryption failed for $mode${NC}"
            return 1
        fi
    }
    
    # Check if decrypted file was created
    if [ ! -f "$openssl_decrypted" ]; then
        echo -e "${RED}FAIL: OpenSSL decrypted file not created for $mode${NC}"
        return 1
    fi
    
    # Compare
    if diff "$input_file" "$openssl_decrypted" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS: CryptoCore -> OpenSSL successful for $mode${NC}"
        return 0
    else
        echo -e "${RED}FAIL: CryptoCore -> OpenSSL failed for $mode - files differ${NC}"
        echo "Original size: $(stat -c%s "$input_file") bytes"
        echo "Decrypted size: $(stat -c%s "$openssl_decrypted") bytes"
        return 1
    fi
}

# Test function for OpenSSL -> CryptoCore
test_openssl_to_cryptocore() {
    local mode=$1
    local openssl_mode=$2
    local input_file="$TEST_DIR/interop_test.txt"
    local openssl_encrypted="$TEST_DIR/interop_${mode}_openssl.enc"
    local cryptocore_decrypted="$TEST_DIR/decrypted_cryptocore.txt"
    
    echo "Testing OpenSSL -> CryptoCore for $mode mode..."
    
    # Clean up any existing files
    rm -f "$openssl_encrypted" "$cryptocore_decrypted"
    
    # Encrypt with OpenSSL
    echo "Encrypting with OpenSSL..."
    if [ "$mode" != "ecb" ]; then
        if ! openssl enc -aes-128-$openssl_mode -K "$KEY_HEX" -iv "$IV_HEX" -in "$input_file" -out "$openssl_encrypted" 2>/dev/null; then
            echo -e "${RED}FAIL: OpenSSL encryption failed for $mode${NC}"
            return 1
        fi
        
        # Check if encrypted file was created
        if [ ! -f "$openssl_encrypted" ]; then
            echo -e "${RED}FAIL: OpenSSL encrypted file not created for $mode${NC}"
            return 1
        fi
        
        local encrypted_size=$(stat -c%s "$openssl_encrypted")
        echo "OpenSSL encrypted file size: $encrypted_size bytes"
        
        # Decrypt with CryptoCore using provided IV
        echo "Decrypting with CryptoCore..."
        if ! "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -iv "$IV" -input "$openssl_encrypted" -output "$cryptocore_decrypted" 2>/dev/null; then
            echo -e "${RED}FAIL: CryptoCore decryption failed for $mode${NC}"
            return 1
        fi
    else
        # ECB mode - no IV
        if ! openssl enc -aes-128-ecb -K "$KEY_HEX" -in "$input_file" -out "$openssl_encrypted" 2>/dev/null; then
            echo -e "${RED}FAIL: OpenSSL encryption failed for $mode${NC}"
            return 1
        fi
        
        if [ ! -f "$openssl_encrypted" ]; then
            echo -e "${RED}FAIL: OpenSSL encrypted file not created for $mode${NC}"
            return 1
        fi
        
        local encrypted_size=$(stat -c%s "$openssl_encrypted")
        echo "OpenSSL encrypted file size: $encrypted_size bytes"
        
        if ! "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$openssl_encrypted" -output "$cryptocore_decrypted" 2>/dev/null; then
            echo -e "${RED}FAIL: CryptoCore decryption failed for $mode${NC}"
            return 1
        fi
    fi
    
    # Check if decrypted file was created
    if [ ! -f "$cryptocore_decrypted" ]; then
        echo -e "${RED}FAIL: CryptoCore decrypted file not created for $mode${NC}"
        return 1
    fi
    
    # Compare
    if diff "$input_file" "$cryptocore_decrypted" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS: OpenSSL -> CryptoCore successful for $mode${NC}"
        return 0
    else
        echo -e "${RED}FAIL: OpenSSL -> CryptoCore failed for $mode - files differ${NC}"
        echo "Original size: $(stat -c%s "$input_file") bytes"
        echo "Decrypted size: $(stat -c%s "$cryptocore_decrypted") bytes"
        return 1
    fi
}

# Clean up before starting
rm -f "$TEST_DIR"/interop_* "$TEST_DIR"/decrypted_* "$TEST_DIR"/iv.bin "$TEST_DIR"/ciphertext_only.bin

# Test all modes
modes=("ecb" "cbc" "cfb" "ofb" "ctr")
openssl_modes=("ecb" "cbc" "cfb" "ofb" "ctr")

passed=0
total=0

echo "=== CryptoCore -> OpenSSL Tests ==="
for i in "${!modes[@]}"; do
    mode="${modes[$i]}"
    openssl_mode="${openssl_modes[$i]}"
    
    if test_cryptocore_to_openssl "$mode" "$openssl_mode"; then
        ((passed++))
    fi
    ((total++))
    echo
done

echo "=== OpenSSL -> CryptoCore Tests ==="
for i in "${!modes[@]}"; do
    mode="${modes[$i]}"
    openssl_mode="${openssl_modes[$i]}"
    
    if test_openssl_to_cryptocore "$mode" "$openssl_mode"; then
        ((passed++))
    fi
    ((total++))
    echo
done

# Final cleanup
rm -f "$TEST_DIR"/interop_* "$TEST_DIR"/decrypted_* "$TEST_DIR"/iv.bin "$TEST_DIR"/ciphertext_only.bin "$TEST_DIR"/interop_test.txt

echo "=== Interoperability Test Summary ==="
echo "Passed: $passed/$total"

if [ $passed -eq $total ]; then
    echo -e "${GREEN}All interoperability tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some interoperability tests failed!${NC}"
    exit 1
fi