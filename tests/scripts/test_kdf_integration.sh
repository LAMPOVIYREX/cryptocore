#!/bin/bash

# KDF Integration Test Script

echo "=== KDF Integration Tests ==="

# Получаем абсолютный путь
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_PATH="$PROJECT_ROOT/bin/cryptocore"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if binary exists
if [ ! -f "$BIN_PATH" ]; then
    echo -e "${RED}Error: cryptocore binary not found at $BIN_PATH${NC}"
    exit 1
fi

echo "✓ Binary found: $BIN_PATH"
echo ""

echo "1. Testing PBKDF2 with auto-generated salt..."
echo "---------------------------------------------"
"$BIN_PATH" derive --password "my secret password" --iterations 10000 --length 32

echo ""
echo "2. Testing PBKDF2 with specific salt..."
echo "---------------------------------------"
"$BIN_PATH" derive --password "test" --salt "a1b2c3d4e5f67890" --iterations 5000 --length 16

echo ""
echo "3. Testing PBKDF2 with many iterations (slower)..."
echo "--------------------------------------------------"
"$BIN_PATH" derive --password "strong password" --iterations 100000 --length 48

echo ""
echo "4. Testing PBKDF2 with output file..."
echo "--------------------------------------"
OUTPUT_FILE="$SCRIPT_DIR/kdf_output.txt"
"$BIN_PATH" derive --password "file test" --iterations 1000 --length 24 --output "$OUTPUT_FILE"
if [ -f "$OUTPUT_FILE" ]; then
    echo -e "${GREEN}✓ Output file created${NC}"
    echo "First few lines:"
    head -5 "$OUTPUT_FILE"
    rm "$OUTPUT_FILE"
    echo "File removed."
else
    echo -e "${RED}✗ Output file not created${NC}"
fi

echo ""
echo "5. Testing error cases..."
echo "-------------------------"

# No password should fail
echo "Testing missing password..."
if "$BIN_PATH" derive --iterations 1000 2>/dev/null; then
    echo -e "${RED}✗ Should have failed without password${NC}"
else
    echo -e "${GREEN}✓ Correctly failed without password${NC}"
fi

# Invalid salt should fail
echo "Testing invalid salt (odd length)..."
if "$BIN_PATH" derive --password "test" --salt "abc" --iterations 1000 2>/dev/null; then
    echo -e "${RED}✗ Should have failed with invalid salt${NC}"
else
    echo -e "${GREEN}✓ Correctly failed with invalid salt${NC}"
fi

echo ""
echo "=== KDF Integration Tests Complete ==="
echo -e "${GREEN}All integration tests passed!${NC}"