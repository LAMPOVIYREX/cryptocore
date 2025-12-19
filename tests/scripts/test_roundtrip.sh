#!/bin/bash

# CryptoCore Round-trip Test Script
# Tests encryption and decryption for all modes

set -e

echo "=== CryptoCore Round-trip Tests ==="
echo

# Получаем абсолютный путь
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_PATH="$PROJECT_ROOT/bin/cryptocore"
TEST_DIR="$PROJECT_ROOT/tests/data/test_files"
KEY="00112233445566778899aabbccddeeff"

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

echo "✓ Binary found: $BIN_PATH"

# Create test directory if it doesn't exist
mkdir -p "$TEST_DIR"

# Create test files
echo "Creating test files..."
echo "This is a test file for CryptoCore round-trip testing." > "$TEST_DIR/roundtrip_test.txt"
echo "Another test file with different content for verification." > "$TEST_DIR/roundtrip_test2.txt"

# Generate a binary test file
head -c 100 /dev/urandom > "$TEST_DIR/roundtrip_test3.bin"

# Test function
test_mode() {
    local mode=$1
    local input_file="$TEST_DIR/roundtrip_test.txt"
    local encrypted_file="$TEST_DIR/roundtrip_${mode}.enc"
    local decrypted_file="$TEST_DIR/roundtrip_${mode}.dec"
    
    echo "Testing $mode mode..."
    
    # Clean up any existing files
    rm -f "$encrypted_file" "$decrypted_file"
    
    # Encrypt
    if ! "$BIN_PATH" -algorithm aes -mode "$mode" -encrypt -key "$KEY" -input "$input_file" -output "$encrypted_file" 2>/dev/null; then
        echo -e "  ${RED}FAIL: Encryption failed for $mode${NC}"
        return 1
    fi
    
    # Check if encrypted file was created
    if [ ! -f "$encrypted_file" ]; then
        echo -e "  ${RED}FAIL: Encrypted file not created for $mode${NC}"
        return 1
    fi
    
    # Get encrypted file size
    local encrypted_size=$(stat -c%s "$encrypted_file" 2>/dev/null || stat -f%z "$encrypted_file" 2>/dev/null)
    echo "  Encrypted file size: $encrypted_size bytes"
    
    # Decrypt
    if [ "$mode" = "ecb" ]; then
        # ECB mode - no IV handling
        if ! "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$encrypted_file" -output "$decrypted_file" 2>/dev/null; then
            echo -e "  ${RED}FAIL: Decryption failed for $mode${NC}"
            return 1
        fi
    else
        # For other modes, IV is read from file automatically
        if ! "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$encrypted_file" -output "$decrypted_file" 2>/dev/null; then
            echo -e "  ${RED}FAIL: Decryption failed for $mode${NC}"
            return 1
        fi
    fi
    
    # Check if decrypted file was created
    if [ ! -f "$decrypted_file" ]; then
        echo -e "  ${RED}FAIL: Decrypted file not created for $mode${NC}"
        return 1
    fi
    
    # Compare
    if diff "$input_file" "$decrypted_file" > /dev/null 2>&1; then
        echo -e "  ${GREEN}PASS: $mode round-trip successful${NC}"
        
        # Additional test with binary file
        if [ "$mode" != "gcm" ]; then  # Skip GCM for simplicity
            local bin_input="$TEST_DIR/roundtrip_test3.bin"
            local bin_encrypted="$TEST_DIR/roundtrip_${mode}_bin.enc"
            local bin_decrypted="$TEST_DIR/roundtrip_${mode}_bin.dec"
            
            rm -f "$bin_encrypted" "$bin_decrypted"
            
            if "$BIN_PATH" -algorithm aes -mode "$mode" -encrypt -key "$KEY" -input "$bin_input" -output "$bin_encrypted" 2>/dev/null && \
               "$BIN_PATH" -algorithm aes -mode "$mode" -decrypt -key "$KEY" -input "$bin_encrypted" -output "$bin_decrypted" 2>/dev/null; then
                if diff "$bin_input" "$bin_decrypted" > /dev/null 2>&1; then
                    echo -e "  ${GREEN}Binary test also passed${NC}"
                fi
            fi
            
            rm -f "$bin_encrypted" "$bin_decrypted"
        fi
        
        # Clean up test files for this mode
        rm -f "$encrypted_file" "$decrypted_file"
        return 0
    else
        echo -e "  ${RED}FAIL: $mode round-trip failed - files differ${NC}"
        echo "    Input file size: $(stat -c%s "$input_file" 2>/dev/null || stat -f%z "$input_file" 2>/dev/null) bytes"
        echo "    Decrypted file size: $(stat -c%s "$decrypted_file" 2>/dev/null || stat -f%z "$decrypted_file" 2>/dev/null) bytes"
        
        # Show first 50 bytes of difference
        echo "    First 50 bytes of input:"
        head -c 50 "$input_file" | hexdump -C
        echo "    First 50 bytes of decrypted:"
        head -c 50 "$decrypted_file" | hexdump -C
        
        return 1
    fi
}

# Test all modes
modes=("ecb" "cbc" "cfb" "ofb" "ctr")
passed=0
total=0

echo "Starting round-trip tests for encryption modes..."
echo

for mode in "${modes[@]}"; do
    if test_mode "$mode"; then
        ((passed++))
    fi
    ((total++))
    echo
done

# Test GCM separately (requires different handling)
echo "Testing GCM mode..."
GCM_INPUT="$TEST_DIR/roundtrip_test2.txt"
GCM_ENCRYPTED="$TEST_DIR/roundtrip_gcm.enc"
GCM_DECRYPTED="$TEST_DIR/roundtrip_gcm.dec"

rm -f "$GCM_ENCRYPTED" "$GCM_DECRYPTED"

if "$BIN_PATH" -algorithm aes -mode gcm -encrypt -key "$KEY" -input "$GCM_INPUT" -output "$GCM_ENCRYPTED" 2>/dev/null; then
    echo "  GCM encryption successful"
    
    if "$BIN_PATH" -algorithm aes -mode gcm -decrypt -key "$KEY" -input "$GCM_ENCRYPTED" -output "$GCM_DECRYPTED" 2>/dev/null; then
        if diff "$GCM_INPUT" "$GCM_DECRYPTED" > /dev/null 2>&1; then
            echo -e "  ${GREEN}PASS: GCM round-trip successful${NC}"
            ((passed++))
        else
            echo -e "  ${RED}FAIL: GCM round-trip failed${NC}"
        fi
    else
        echo -e "  ${RED}FAIL: GCM decryption failed${NC}"
    fi
else
    echo -e "  ${RED}FAIL: GCM encryption failed${NC}"
fi
((total++))

echo
echo "=== Round-trip Test Summary ==="
echo "Passed: $passed/$total"

# Clean up original test files (keep for debugging if needed)
# rm -f "$TEST_DIR"/roundtrip_test*.txt "$TEST_DIR"/roundtrip_test*.bin

if [ $passed -eq $total ]; then
    echo -e "${GREEN}All round-trip tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some round-trip tests failed!${NC}"
    echo "Test files preserved in: $TEST_DIR"
    exit 1
fi