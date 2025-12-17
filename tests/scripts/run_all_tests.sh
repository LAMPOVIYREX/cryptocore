#!/bin/bash

echo "=========================================="
echo "     CryptoCore Complete Test Suite      "
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Перейти в директорию скриптов
cd "$(dirname "$0")"

# Function to run test with output
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo -e "\n${YELLOW}▶ Running: $test_name${NC}"
    echo "------------------------------------------"
    
    if eval "$test_cmd"; then
        echo -e "${GREEN}✓ $test_name PASSED${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_name FAILED${NC}"
        return 1
    fi
}

# Build everything first
echo -e "\n${YELLOW}Building project...${NC}"
cd ../..
if ! make all; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# Go back to scripts directory
cd tests/scripts

# Run tests
failed=0
passed=0

# Unit tests
run_test "GCM Unit Tests" "../../bin/test_gcm_vectors" && ((passed++)) || ((failed++))
run_test "HMAC Unit Tests" "../../bin/test_hmac_vectors" && ((passed++)) || ((failed++))
run_test "Hash Unit Tests" "../../bin/test_hash" && ((passed++)) || ((failed++))

# Integration tests
run_test "Round-trip Integration" "./test_roundtrip.sh" && ((passed++)) || ((failed++))
run_test "Key Generation Tests" "./test_key_generation.sh" && ((passed++)) || ((failed++))
run_test "OpenSSL Interoperability" "./test_interoperability.sh" && ((passed++)) || ((failed++))

# Summary
echo "=========================================="
echo "           TEST SUMMARY"
echo "=========================================="
echo -e "Total tests: $((passed + failed))"
echo -e "${GREEN}Passed: $passed${NC}"
if [ $failed -gt 0 ]; then
    echo -e "${RED}Failed: $failed${NC}"
else
    echo -e "${GREEN}All tests passed!${NC}"
fi

exit $failed