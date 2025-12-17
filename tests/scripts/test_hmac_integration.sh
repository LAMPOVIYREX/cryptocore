#!/bin/bash

# HMAC Integration Test Script
# Tests all HMAC requirements from Sprint 5

set -e

echo "=== HMAC Integration Tests (Sprint 5) ==="
echo

BIN_PATH="../../bin/cryptocore"
TEST_DIR="../data/hmac_tests"

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

# Create test directory
mkdir -p "$TEST_DIR"

# Create test files
echo "Creating test files..."
echo "This is a test file for HMAC verification." > "$TEST_DIR/test1.txt"
echo "Another test file with different content." > "$TEST_DIR/test2.txt"

# Test 1: Basic HMAC generation
echo ""
echo "=== Test 1: Basic HMAC Generation ==="
KEY="00112233445566778899aabbccddeeff"

if "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$KEY" --input "$TEST_DIR/test1.txt" --output "$TEST_DIR/hmac1.txt" 2>/dev/null; then
    echo -e "${GREEN}✓ HMAC generation successful${NC}"
    
    # Check output format
    if grep -q "^[0-9a-f]\{64\}  $TEST_DIR/test1.txt$" "$TEST_DIR/hmac1.txt"; then
        echo -e "${GREEN}✓ Output format correct${NC}"
    else
        echo -e "${RED}✗ Output format incorrect${NC}"
        cat "$TEST_DIR/hmac1.txt"
    fi
else
    echo -e "${RED}✗ HMAC generation failed${NC}"
fi

# Test 2: HMAC verification (success case)
echo ""
echo "=== Test 2: HMAC Verification (Success) ==="

# Generate HMAC
"$BIN_PATH" dgst --algorithm sha256 --hmac --key "$KEY" --input "$TEST_DIR/test1.txt" > "$TEST_DIR/hmac_to_verify.txt"

# Verify it
if "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$KEY" --input "$TEST_DIR/test1.txt" --verify "$TEST_DIR/hmac_to_verify.txt" 2>/dev/null; then
    echo -e "${GREEN}✓ HMAC verification successful${NC}"
else
    echo -e "${RED}✗ HMAC verification failed (should have succeeded)${NC}"
fi

# Test 3: HMAC verification (failure - tampered file)
echo ""
echo "=== Test 3: Tamper Detection (File Modified) ==="

# Tamper with the file
echo "Modified content" > "$TEST_DIR/test1_tampered.txt"

if "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$KEY" --input "$TEST_DIR/test1_tampered.txt" --verify "$TEST_DIR/hmac_to_verify.txt" 2>/dev/null; then
    echo -e "${RED}✗ Tamper detection failed (should have detected modification)${NC}"
else
    echo -e "${GREEN}✓ Tamper detection successful (correctly detected modification)${NC}"
    echo "  Exit code: $?"
fi

# Test 4: HMAC verification (failure - wrong key)
echo ""
echo "=== Test 4: Tamper Detection (Wrong Key) ==="

WRONG_KEY="ffeeddccbbaa99887766554433221100"

if "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$WRONG_KEY" --input "$TEST_DIR/test1.txt" --verify "$TEST_DIR/hmac_to_verify.txt" 2>/dev/null; then
    echo -e "${RED}✗ Wrong key detection failed (should have failed)${NC}"
else
    echo -e "${GREEN}✓ Wrong key detection successful${NC}"
    echo "  Exit code: $?"
fi

# Test 5: Different key sizes
echo ""
echo "=== Test 5: Key Size Variations ==="

KEY_SIZES=("0011223344556677" \
           "00112233445566778899aabbccddeeff" \
           "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

for i in "${!KEY_SIZES[@]}"; do
    key="${KEY_SIZES[$i]}"
    size=$(( ${#key} / 2 ))
    
    echo -n "  Testing ${size}-byte key... "
    
    if "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$key" --input "$TEST_DIR/test1.txt" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
done

# Test 6: Empty file
echo ""
echo "=== Test 6: Empty File Test ==="

touch "$TEST_DIR/empty.txt"

if "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$KEY" --input "$TEST_DIR/empty.txt" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Empty file handled correctly${NC}"
    
    # Get the HMAC
    "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$KEY" --input "$TEST_DIR/empty.txt" > "$TEST_DIR/empty_hmac.txt"
    hmac_value=$(cut -d' ' -f1 "$TEST_DIR/empty_hmac.txt")
    echo "  Empty file HMAC: $hmac_value"
else
    echo -e "${RED}✗ Empty file test failed${NC}"
fi

# Test 7: Large file test (simulated with 10MB)
echo ""
echo "=== Test 7: Large File Test ==="

echo "Creating 10MB test file..."
dd if=/dev/urandom of="$TEST_DIR/large.bin" bs=1M count=10 status=none 2>/dev/null

if "$BIN_PATH" dgst --algorithm sha256 --hmac --key "$KEY" --input "$TEST_DIR/large.bin" > "$TEST_DIR/large_hmac.txt" 2>/dev/null; then
    echo -e "${GREEN}✓ Large file processed successfully${NC}"
    hmac_value=$(cut -d' ' -f1 "$TEST_DIR/large_hmac.txt")
    echo "  Large file HMAC (first 16 chars): ${hmac_value:0:16}..."
else
    echo -e "${RED}✗ Large file test failed${NC}"
fi

# Test 8: RFC 4231 Test Vectors (Test Case 1)
echo ""
echo "=== Test 8: RFC 4231 Test Vector 1 ==="

# Create test file with "Hi There"
echo -n "Hi There" > "$TEST_DIR/rfc_test.txt"

RFC_KEY="0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
EXPECTED="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

"$BIN_PATH" dgst --algorithm sha256 --hmac --key "$RFC_KEY" --input "$TEST_DIR/rfc_test.txt" > "$TEST_DIR/rfc_output.txt"
COMPUTED=$(cut -d' ' -f1 "$TEST_DIR/rfc_output.txt")

echo "  Expected: $EXPECTED"
echo "  Computed: $COMPUTED"

if [ "$COMPUTED" = "$EXPECTED" ]; then
    echo -e "${GREEN}✓ RFC 4231 Test Case 1 passed${NC}"
else
    echo -e "${RED}✗ RFC 4231 Test Case 1 failed${NC}"
fi

# Cleanup
echo ""
echo "=== Cleaning up ==="
rm -rf "$TEST_DIR"

echo ""
echo "=== HMAC Integration Tests Complete ==="
echo "All requirements from Sprint 5 have been tested:"
echo "1. ✓ Basic HMAC generation"
echo "2. ✓ HMAC verification"
echo "3. ✓ Tamper detection (file modified)"
echo "4. ✓ Tamper detection (wrong key)"
echo "5. ✓ Key size variations"
echo "6. ✓ Empty file handling"
echo "7. ✓ Large file processing"
echo "8. ✓ RFC 4231 test vectors"