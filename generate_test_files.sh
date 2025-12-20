#!/bin/bash
# generate_test_files.sh

echo "Generating test files for CryptoCore..."

# Создаем директорию
TEST_DIR="test_data"
mkdir -p "$TEST_DIR"

# Функция для создания файла с проверкой
create_file() {
    local filename="$1"
    local content="$2"
    
    if [ -f "$TEST_DIR/$filename" ]; then
        echo "  ✓ $filename already exists"
    else
        echo "$content" > "$TEST_DIR/$filename"
        echo "  ✓ Created $filename"
    fi
}

echo "1. Creating basic test files..."

create_file "secret.txt" "This is a secret message for testing CryptoCore."
create_file "document.pdf.txt" "IMPORTANT DOCUMENT - Test PDF content\nDate: $(date)\nAuthor: Test User"
create_file "password.txt" "MyStrongPassword123!"
create_file "report.txt" "Confidential Report\n=================\nThis is a test report for encryption."

echo "2. Creating binary test file..."
if [ ! -f "$TEST_DIR/random.bin" ]; then
    dd if=/dev/urandom of="$TEST_DIR/random.bin" bs=1024 count=10 status=none
    echo "  ✓ Created random.bin (10KB)"
else
    echo "  ✓ random.bin already exists"
fi

echo "3. Creating files for specific examples..."

# Пример 1: Шифрование
create_file "example1_plain.txt" "Hello CryptoCore! This message will be encrypted."

# Пример 2: HMAC
cat > "$TEST_DIR/hmac_test.txt" <<EOF
File for HMAC Testing
====================
This file will be protected with HMAC
to ensure its integrity.

Contents:
- Line 1: Test data
- Line 2: More test data
- Line 3: Final test line

Timestamp: $(date)
EOF
echo "  ✓ Created hmac_test.txt"

# Пример 3: PBKDF2
create_file "user_password.txt" "User123!SecurePass@2024"

# Пример 4: GCM с метаданными
cat > "$TEST_DIR/gcm_metadata.txt" <<EOF
GCM Test with Metadata
=====================
This file will be encrypted with GCM
using Additional Authenticated Data (AAD).

Metadata included in AAD:
- File: gcm_metadata.txt
- Owner: test_user
- Created: $(date)
- Security: confidential
EOF
echo "  ✓ Created gcm_metadata.txt"

echo "4. Creating metadata for AAD..."
echo "user=test|role=admin|department=security|level=confidential|timestamp=$(date +%s)" > "$TEST_DIR/aad_metadata.txt"

echo ""
echo "Test files generated in ./$TEST_DIR/:"
ls -la "$TEST_DIR/"
echo ""
echo "Total files: $(ls -1 "$TEST_DIR/" | wc -l)"
echo ""
echo "Usage examples:"
echo "  # Encryption"
echo "  ./bin/cryptocore -algorithm aes -mode cbc -encrypt \\"
echo "      -input test_data/secret.txt -output encrypted.bin"
echo ""
echo "  # HMAC"
echo "  ./bin/cryptocore dgst --algorithm sha256 --hmac \\"
echo "      --key 00112233445566778899aabbccddeeff \\"
echo "      --input test_data/hmac_test.txt"
echo ""
echo "  # PBKDF2"
echo "  ./bin/cryptocore derive --password \"\$(cat test_data/user_password.txt)\" \\"
echo "      --iterations 100000 --length 32"