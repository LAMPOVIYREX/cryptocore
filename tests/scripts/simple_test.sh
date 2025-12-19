#!/bin/bash

echo "=== Simplified Integration Test ==="
echo "This test only runs basic functionality checks"

# Go to project root
cd "$(dirname "$0")/../.."

# Check if binary exists
if [ ! -f "bin/cryptocore" ]; then
    echo "Error: cryptocore binary not found"
    exit 1
fi

echo "✓ Binary found"

# Test 1: Basic round-trip with ECB
echo ""
echo "1. Testing basic ECB round-trip..."

# Create test file
echo "Hello CryptoCore" > test_ecb.txt

# Encrypt
if bin/cryptocore -algorithm aes -mode ecb -encrypt \
    -key 00112233445566778899aabbccddeeff \
    -input test_ecb.txt \
    -output test_ecb.enc; then
    echo "  ✓ Encryption successful"
    
    # Decrypt
    if bin/cryptocore -algorithm aes -mode ecb -decrypt \
        -key 00112233445566778899aabbccddeeff \
        -input test_ecb.enc \
        -output test_ecb.dec; then
        echo "  ✓ Decryption successful"
        
        # Compare
        if diff test_ecb.txt test_ecb.dec > /dev/null; then
            echo "  ✓ Round-trip successful"
        else
            echo "  ✗ Files differ"
            exit 1
        fi
    else
        echo "  ✗ Decryption failed"
        exit 1
    fi
else
    echo "  ✗ Encryption failed"
    exit 1
fi

# Test 2: Key generation
echo ""
echo "2. Testing key generation..."

if bin/cryptocore -algorithm aes -mode ecb -encrypt \
    -input test_ecb.txt \
    -output test_gen.enc 2>&1 | grep -q "Generated random key:"; then
    echo "  ✓ Key generation works"
else
    echo "  ✗ Key generation failed"
    exit 1
fi

# Test 3: Hashing
echo ""
echo "3. Testing hashing..."

if bin/cryptocore dgst --algorithm sha256 --input test_ecb.txt > /dev/null 2>&1; then
    echo "  ✓ Hashing works"
else
    echo "  ✗ Hashing failed"
    exit 1
fi

# Cleanup
rm -f test_ecb.txt test_ecb.enc test_ecb.dec test_gen.enc

echo ""
echo "=== All simplified tests passed! ==="
exit 0s