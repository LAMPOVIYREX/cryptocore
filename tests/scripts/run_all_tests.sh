#!/bin/bash

echo "=========================================="
echo "     CryptoCore Complete Test Suite      "
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
make clean
if ! make all; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}Build successful!${NC}"

# Run tests
failed=0
passed=0

# Unit tests
run_test "CSPRNG Unit Tests" "../bin/test_csprng" && ((passed++)) || ((failed++))
run_test "Round-trip Unit Tests" "../bin/test_roundtrip" && ((passed++)) || ((failed++))

# Integration tests
run_test "Round-trip Integration" "./test_roundtrip.sh" && ((passed++)) || ((failed++))
run_test "Key Generation Tests" "./test_key_generation.sh" && ((passed++)) || ((failed++))
run_test "OpenSSL Interoperability" "./test_interoperability.sh" && ((passed++)) || ((failed++))

# Optional tests
echo -e "\n${YELLOW}▶ Optional tests:${NC}"
run_test "Padding Tests" "./padding_test.sh" && ((passed++)) || ((failed++))

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

# Cleanup
echo -e "\n${YELLOW}Cleaning up test files...${NC}"
make clean > /dev/null 2>&1
rm -f ../data/*.enc ../data/*.dec ../data/test_*.txt 2>/dev/null

exit $failed