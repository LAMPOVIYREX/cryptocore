# CryptoCore

A command-line tool for AES encryption and decryption supporting multiple modes of operation (ECB, CBC, CFB, OFB, CTR) and cryptographic hash functions (SHA-256, SHA3-256).

## Features

- **Encryption/Decryption**:
  - **Algorithms**: AES-128
  - **Modes**: ECB, CBC, CFB, OFB, CTR  
  - **Padding**: PKCS#7 (for ECB and CBC modes)
  - **Key Management**: Automatic secure key generation or hexadecimal input
  - **IV Handling**: Automatic generation for encryption, file-based or argument for decryption
  - **Security**: Cryptographically secure random number generation using OpenSSL RAND_bytes

- **Hashing (Sprint 4)**:
  - **SHA-256**: Implemented from scratch following NIST FIPS 180-4
  - **SHA3-256**: Using OpenSSL's implementation
  - **File Support**: Handles files of any size with streaming processing
  - **Output Format**: Standard hash format compatible with system tools

## Build Instructions

### Prerequisites

- GCC compiler
- OpenSSL development libraries

### On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev openssl xxd

Build:
bash
make
Usage
Encryption/Decryption
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
Hashing (Sprint 4)
Basic hash computation:
bash
./bin/cryptocore dgst --algorithm sha256 --input document.pdf
Hash with output to file:
bash
./bin/cryptocore dgst --algorithm sha3-256 --input backup.tar --output backup.sha3
Verify against system tools:
bash
./bin/cryptocore dgst --algorithm sha256 --input test.txt > my_hash.txt
sha256sum test.txt > system_hash.txt
diff my_hash.txt system_hash.txt
Supported Modes
Encryption Modes:
ecb - Electronic Codebook (no IV)

cbc - Cipher Block Chaining

cfb - Cipher Feedback

ofb - Output Feedback

ctr - Counter

Hash Algorithms:
sha256 - SHA-256 (implemented from scratch)

sha3-256 - SHA3-256 (using OpenSSL)

Key and IV Format
Keys: 16-byte hexadecimal strings (32 hex characters)

IVs: 16-byte hexadecimal strings (32 hex characters)

No @ prefix required - use plain hex strings

CSPRNG Security
The tool uses OpenSSL's RAND_bytes() for cryptographically secure random number generation, which:

Uses /dev/urandom on Unix systems

Provides cryptographically strong randomness

Is suitable for cryptographic key generation

Hashing Implementation
SHA-256:
Implemented from scratch following NIST FIPS 180-4

Uses Merkle-Damgård construction with 512-bit blocks

Processes files in chunks for memory efficiency

Passes NIST test vectors

SHA3-256:
Uses OpenSSL's EVP interface

Based on Keccak sponge construction

Interoperable with system sha3sum tool

Testing
Run all tests:
bash
make test
Run specific test suites:
bash
# Unit tests
make csprng_test
make roundtrip_test
make hash_test

# Integration tests
./tests/scripts/test_roundtrip.sh
./tests/scripts/test_interoperability.sh
./tests/scripts/test_key_generation.sh
Hash function tests:
bash
make hash_test
./tests/bin/test_hash
NIST Statistical Test Suite:
bash
make nist_test
# Follow instructions to run NIST STS
Examples
File Encryption and Decryption:
bash
# Encrypt with random key
./bin/cryptocore -algorithm aes -mode ctr -encrypt -input secret.txt -output secret.enc

# Decrypt with the generated key
./bin/cryptocore -algorithm aes -mode ctr -decrypt -key <generated_key> -input secret.enc -output secret_decrypted.txt
File Integrity Verification:
bash
# Compute hash
./bin/cryptocore dgst --algorithm sha256 --input important_document.pdf > document.sha256

# Later verify
./bin/cryptocore dgst --algorithm sha256 --input important_document.pdf > check.sha256
diff document.sha256 check.sha256
Interoperability with OpenSSL:
bash
# Encrypt with CryptoCore, decrypt with OpenSSL
./bin/cryptocore -algorithm aes -mode cbc -encrypt -key 00112233445566778899aabbccddeeff -input plain.txt -output cc_cipher.bin
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -in cc_cipher.bin -out openssl_decrypted.txt
Project Structure
text
cryptocore/
├── bin/                    # Compiled binaries
├── include/               # Header files
│   ├── hash/             # Hash function headers
│   ├── modes/            # Encryption mode headers
│   └── *.h               # Other headers
├── src/                  # Source code
│   ├── hash/             # Hash implementations
│   ├── modes/            # Encryption mode implementations
│   └── *.c               # Other source files
├── tests/                # Test files
│   ├── bin/              # Test binaries
│   ├── data/             # Test data
│   ├── results/          # Test results
│   ├── scripts/          # Test scripts
│   └── src/              # Test source code
├── Makefile              # Build system
└── README.md             # This file
Security Notes
Generated keys are displayed only once - save them securely

The tool warns about potentially weak user-provided keys

IVs are automatically generated using CSPRNG for encryption

For decryption, IVs can be read from file or provided via command line

Hash functions process files in chunks to handle large files efficiently

Hashing Support (Sprint 4)
CryptoCore now supports cryptographic hash functions for data integrity verification.

Available Hash Algorithms
SHA-256 - Implemented from scratch following NIST FIPS 180-4

SHA3-256 - Using OpenSSL's implementation

Output Format
The tool outputs hashes in the standard format:

text
HASH_VALUE  INPUT_FILE_PATH
Examples
bash
# Verify against system tools
./bin/cryptocore dgst --algorithm sha256 --input test.txt > my_hash.txt
sha256sum test.txt > system_hash.txt
diff my_hash.txt system_hash.txt

# Empty file test (SHA-256 of empty string):
echo -n "" | ./bin/cryptocore dgst --algorithm sha256 --input -
# Output: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  -
Testing Hash Functions
Run the hash function tests:

bash
make test_hash_build
./tests/bin/test_hash
Implementation Notes
SHA-256 is implemented from scratch (no external dependencies)

SHA3-256 uses OpenSSL's EVP interface

Both implementations support files of any size (streaming processing)

All hash functions pass NIST test vectors

License
This project is for educational purposes as part of a cryptography course.

Acknowledgments
NIST for cryptographic standards

OpenSSL project for cryptographic libraries

Course instructors for guidance and requirements