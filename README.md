# CryptoCore

A command-line tool for AES encryption and decryption supporting multiple modes of operation (ECB, CBC, CFB, OFB, CTR).

## Features

- **Algorithms**: AES-128
- **Modes**: ECB, CBC, CFB, OFB, CTR  
- **Padding**: PKCS#7 (for ECB and CBC modes)
- **Key Management**: Automatic secure key generation or hexadecimal input
- **IV Handling**: Automatic generation for encryption, file-based or argument for decryption
- **Security**: Cryptographically secure random number generation using OpenSSL RAND_bytes

## Build Instructions

### Prerequisites

- GCC compiler
- OpenSSL development libraries

### On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev

Build:
bash
make
Usage
Encryption with auto-generated key:
bash
./bin/cryptocore -algorithm aes -mode cbc -encrypt -input plain.txt -output cipher.bin
The tool will generate a secure random key and display it:

text
Generated random key: 1a2b3c4d5e6f7890fedcba9876543210
Success: plain.txt -> cipher.bin
Generated IV: aabbccddeeff00112233445566778899
Encryption with specific key:
bash
./bin/cryptocore -algorithm aes -mode cbc -encrypt -key 00112233445566778899aabbccddeeff -input plain.txt -output cipher.bin
Decryption:
bash
./bin/cryptocore -algorithm aes -mode cbc -decrypt -key 00112233445566778899aabbccddeeff -input cipher.bin -output decrypted.txt
Supported Modes:
ecb - Electronic Codebook (no IV)

cbc - Cipher Block Chaining

cfb - Cipher Feedback

ofb - Output Feedback

ctr - Counter

Key and IV Format
Keys: 16-byte hexadecimal strings (32 hex characters)

IVs: 16-byte hexadecimal strings (32 hex characters)

No @ prefix required - use plain hex strings

CSPRNG Security
The tool uses OpenSSL's RAND_bytes() for cryptographically secure random number generation, which:

Uses /dev/urandom on Unix systems

Provides cryptographically strong randomness

Is suitable for cryptographic key generation

NIST Statistical Test Suite
Installing NIST STS
Download from NIST website

Extract and compile:

bash
tar -xzf sts-2.1.2.tar.gz
cd sts-2.1.2
make
Running NIST Tests
Generate test data using CryptoCore's CSPRNG:

bash
make csprng_test
./bin/test_csprng
Run NIST STS on generated data:

bash
cd sts-2.1.2
./assess 1000000
# Follow prompts to specify the test file: ../nist_test_data.bin
View results in ./experiments/AlgorithmTesting/finalAnalysisReport.txt

Expected Results
A properly functioning CSPRNG should pass the majority of NIST tests. Typical results:

Frequency Test: PASS

Block Frequency Test: PASS

Runs Test: PASS

Longest Runs Test: PASS

DFT Test: PASS

Non-overlapping Templates: PASS (most templates)

Overlapping Templates: PASS

Universal Statistical Test: PASS

Linear Complexity Test: PASS

Serial Test: PASS

Approximate Entropy Test: PASS

Cumulative Sums Test: PASS

Random Excursions Test: PASS (most states)

Random Excursions Variant Test: PASS (most states)

A small number of failures is statistically expected, but widespread failures indicate RNG flaws.

Testing
Run all tests:
bash
make test
Run specific test suites:
bash
# Round-trip tests
./tests/test_roundtrip.sh

# OpenSSL interoperability
./tests/test_interoperability.sh

# Key generation tests
./tests/test_key_generation.sh

# CSPRNG statistical tests
./bin/test_csprng
Security Notes
Generated keys are displayed only once - save them securely

The tool warns about potentially weak user-provided keys

IVs are automatically generated using CSPRNG for encryption

For decryption, IVs can be read from file or provided via command line

text

## 4. Создаем скрипт для автоматического NIST тестирования `tests/run_nist_tests.sh`

```bash
#!/bin/bash

echo "=== NIST Statistical Test Suite Runner ==="

# Check if NIST STS is available
NIST_DIR="../sts-2.1.2"
NIST_BIN="$NIST_DIR/assess"

if [ ! -f "$NIST_BIN" ]; then
    echo "Error: NIST STS not found at $NIST_DIR"
    echo "Please download and compile NIST STS first:"
    echo "1. Download from https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software"
    echo "2. Extract to sts-2.1.2 directory in project root"
    echo "3. Run 'make' in the sts-2.1.2 directory"
    exit 1
fi

echo "✓ NIST STS found"

# Generate test data if not exists
TEST_DATA="nist_test_data.bin"
if [ ! -f "$TEST_DATA" ]; then
    echo "Generating test data..."
    ./bin/test_csprng
fi

if [ ! -f "$TEST_DATA" ]; then
    echo "Error: Failed to generate test data"
    exit 1
fi

echo "✓ Test data ready: $TEST_DATA ($(stat -c%s "$TEST_DATA") bytes)"

# Run NIST tests
echo "Running NIST Statistical Test Suite..."
cd "$NIST_DIR"

# Create assessment configuration
cat > assess_config.txt << EOF
$TEST_DATA
0
1
1000000
EOF

./assess 1000000 < assess_config.txt

echo ""
echo "=== NIST Tests Complete ==="
echo "Results available in: $NIST_DIR/experiments/AlgorithmTesting/finalAnalysisReport.txt"
echo "Summary of results:"

# Extract and display summary
if [ -f "experiments/AlgorithmTesting/finalAnalysisReport.txt" ]; then
    grep -E "(TEST|passed|failed)" "experiments/AlgorithmTesting/finalAnalysisReport.txt" | head -20
fi