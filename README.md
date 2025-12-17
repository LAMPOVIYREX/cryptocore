# CryptoCore

A comprehensive command-line cryptographic toolkit supporting encryption, hashing, and message authentication. Built as part of a cryptography course with implementations from scratch where specified.

## Features

### Encryption/Decryption
- **Algorithms**: AES-128
- **Modes**: ECB, CBC, CFB, OFB, CTR, GCM (AEAD)
- **Padding**: PKCS#7 (for ECB and CBC modes)
- **Key Management**: Automatic secure key generation or hexadecimal input
- **IV Handling**: Automatic generation for encryption, file-based or argument for decryption
- **Security**: Cryptographically secure random number generation using OpenSSL RAND_bytes

### Hashing (Sprint 4)
- **SHA-256**: Implemented from scratch following NIST FIPS 180-4
- **SHA3-256**: Using OpenSSL's implementation
- **File Support**: Handles files of any size with streaming processing
- **Output Format**: Standard hash format compatible with system tools

### HMAC (Sprint 5)
- **RFC 2104 Compliant**: HMAC implementation from scratch
- **SHA-256 Based**: Uses the SHA-256 implementation from Sprint 4
- **Variable Key Sizes**: Supports keys of any length
- **Streaming Processing**: Handles large files efficiently
- **Verification Mode**: Can verify existing HMAC values
- **Tamper Detection**: Detects file modifications and incorrect keys

### GCM Authenticated Encryption (Sprint 6)
- **NIST SP 800-38D Compliant**: GCM implementation from scratch
- **Authenticated Encryption with Associated Data (AEAD)**: Supports AAD
- **Constant-time Tag Verification**: Prevents timing attacks
- **Secure Nonce Generation**: 12-byte random nonce for each encryption
- **Authentication Failure Protection**: No output file created on failure

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
Or install dependencies and build:

bash
make install-dependencies
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
GCM Mode (Authenticated Encryption)
Encryption with Additional Authenticated Data (AAD):
bash
./bin/cryptocore -algorithm aes -mode gcm -encrypt \
    -key 00112233445566778899aabbccddeeff \
    -input secret.txt \
    -output secret.enc \
    -aad feedfacedeadbeeffeedfacedeadbeefabaddad2
Decryption with AAD verification:
bash
./bin/cryptocore -algorithm aes -mode gcm -decrypt \
    -key 00112233445566778899aabbccddeeff \
    -input secret.enc \
    -output secret_decrypted.txt \
    -aad feedfacedeadbeeffeedfacedeadbeefabaddad2
Error Cases:
Wrong AAD during decryption → authentication failure, no output file created

Tampered ciphertext → authentication failure, no output file created

Wrong tag → authentication failure, no output file created

Security Notes:
Nonce (12 bytes) is randomly generated for each encryption

Tag (16 bytes) provides 128-bit authentication

AAD is authenticated but not encrypted

Constant-time tag comparison prevents timing attacks

Hashing
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
HMAC (Message Authentication)
Generate HMAC:

bash
./bin/cryptocore dgst --algorithm sha256 --hmac --key KEY_HEX --input file.txt
Generate HMAC and save to file:

bash
./bin/cryptocore dgst --algorithm sha256 --hmac --key KEY_HEX --input secret.txt --output secret.hmac
Verify HMAC:

bash
./bin/cryptocore dgst --algorithm sha256 --hmac --key KEY_HEX --input secret.txt --verify expected.hmac
Supported Modes
Encryption Modes:
ecb - Electronic Codebook (no IV)

cbc - Cipher Block Chaining

cfb - Cipher Feedback

ofb - Output Feedback

ctr - Counter

gcm - Galois/Counter Mode (Authenticated Encryption)

Hash Algorithms:
sha256 - SHA-256 (implemented from scratch)

sha3-256 - SHA3-256 (using OpenSSL)

HMAC Algorithms:
sha256 - HMAC-SHA256 (implemented from scratch)

sha3-256 - HMAC-SHA3-256 (using OpenSSL)

Key and IV Format
Keys: Hexadecimal strings (16 bytes = 32 hex characters for AES-128)

IVs: Hexadecimal strings (16 bytes = 32 hex characters)

No @ prefix required - use plain hex strings

HMAC Keys: Any length hexadecimal strings

Examples:

Valid key: 00112233445566778899aabbccddeeff

Valid IV: aabbccddeeff00112233445566778899

Valid HMAC key (short): 4a656665 ("Jefe" in hex)

Valid HMAC key (long): 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b

Testing
Run all tests:
bash
make test_all
Run specific test suites:
bash
# Unit tests
make test
make test_hmac
make test_hash
make test_roundtrip
make test_csprng
make test_gcm  # New GCM tests

# Integration tests
cd tests/scripts
./run_all_tests.sh
./test_hmac_integration.sh
./test_gcm_unique_nonce.sh  # New GCM nonce test
GCM-specific tests:
bash
# Build and run GCM unit tests
make test_gcm_build
./bin/test_gcm_vectors

# Run GCM integration tests
cd tests/scripts
./test_gcm_unique_nonce.sh
Examples
File Encryption and Decryption:
bash
# Encrypt with random key
./bin/cryptocore -algorithm aes -mode ctr -encrypt -input secret.txt -output secret.enc

# Decrypt with the generated key
./bin/cryptocore -algorithm aes -mode ctr -decrypt -key <generated_key> -input secret.enc -output secret_decrypted.txt
GCM Authenticated Encryption:
bash
# Encrypt with AAD
./bin/cryptocore -algorithm aes -mode gcm -encrypt -key KEY -input data.txt -output data.enc -aad AAD_HEX

# Decrypt and verify
./bin/cryptocore -algorithm aes -mode gcm -decrypt -key KEY -input data.enc -output data_decrypted.txt -aad AAD_HEX
Message Authentication with HMAC:
bash
# Generate HMAC for a file
./bin/cryptocore dgst --algorithm sha256 --hmac --key mysecretkey --input data.bin > data.hmac

# Verify HMAC later
./bin/cryptocore dgst --algorithm sha256 --hmac --key mysecretkey --input data.bin --verify data.hmac
Implementation Notes
SHA-256:
Implemented from scratch (no external dependencies)

Passes all NIST test vectors

Uses standard Merkle-Damgård construction

HMAC:
Implemented from scratch following RFC 2104

Passes all RFC 4231 test vectors

Correctly handles edge cases (empty files, various key sizes)

Uses constant-time comparison for verification

GCM:
Implemented from scratch following NIST SP 800-38D

GF(2¹²⁸) multiplication with polynomial x¹²⁸ + x⁷ + x² + x + 1

12-byte nonce (recommended size)

16-byte authentication tag

Constant-time tag verification

Encryption Modes:
ECB and CBC use PKCS#7 padding

CFB, OFB, CTR are stream ciphers (no padding)

GCM provides authenticated encryption

All modes are interoperable with OpenSSL

Security Notes
Generated keys are displayed only once - save them securely

The tool warns about potentially weak user-provided keys

IVs are automatically generated using CSPRNG for encryption

For decryption, IVs can be read from file or provided via command line

HMAC keys should be kept secret and have sufficient entropy

GCM provides both confidentiality and authentication

Critical: On GCM authentication failure, no output file is created

All hash/MAC functions process files in chunks to handle large files efficiently

Project Structure
text
cryptocore/
├── bin/                    # Compiled binaries
├── include/               # Header files
│   ├── hash/             # Hash function headers
│   │   ├── sha256.h
│   │   └── sha3_256.h
│   ├── mac/              # MAC headers
│   │   └── hmac.h
│   ├── modes/            # Encryption mode headers
│   │   └── gcm.h
│   ├── aead.h
│   ├── cli_parser.h
│   ├── common.h
│   ├── crypto.h
│   ├── csprng.h
│   ├── file_io.h
│   ├── hash.h
│   └── types.h
├── src/                  # Source code
│   ├── hash/             # Hash implementations
│   │   ├── sha256.c
│   │   └── sha3_256.c
│   ├── mac/              # MAC implementations
│   │   └── hmac.c
│   ├── modes/            # Encryption mode implementations
│   │   └── gcm.c
│   ├── aead.c
│   ├── cli_parser.c
│   ├── crypto.c
│   ├── csprng.c
│   ├── file_io.c
│   ├── hash.c
│   ├── main.c
│   └── modes.c
├── tests/                # Test files
│   ├── bin/              # Test binaries
│   ├── data/             # Test data
│   ├── results/          # Test results
│   ├── scripts/          # Test scripts
│   │   ├── debug_test.sh
│   │   ├── fixed_interop_test.sh
│   │   ├── openssl_safe_test.sh
│   │   ├── padding_test.sh
│   │   ├── run_all_tests.sh
│   │   ├── run_nist_tests.sh
│   │   ├── run_tests.sh
│   │   ├── safe_test.sh
│   │   ├── test_hmac_integration.sh
│   │   ├── test_interoperability.sh
│   │   ├── test_key_generation.sh
│   │   ├── test_roundtrip.sh
│   │   ├── test_gcm_unique_nonce.sh     # New GCM test
│   │   └── test_gcm_interop.sh          # New GCM interoperability test
│   └── src/              # Test source code
│       ├── test_csprng.c
│       ├── test_hash.c
│       ├── test_hash_requirements.c
│       ├── test_hmac_vectors.c
│       ├── test_roundtrip.c
│       └── test_gcm_vectors.c           # New GCM vector tests
├── Makefile              # Build system
└── README.md             # This file
License
This project is for educational purposes as part of a cryptography course.

Acknowledgments
NIST for cryptographic standards (FIPS 180-4, FIPS 202, SP 800-38D, RFC 2104)

OpenSSL project for cryptographic libraries

Course instructors for guidance and requirements

RFC authors for clear specifications

Sprint Completion Status
✅ Sprint 1: Core ECB mode implementation
✅ Sprint 2: Confidential modes (CBC, CFB, OFB, CTR)
✅ Sprint 3: CSPRNG and key generation
✅ Sprint 4: Hash functions (SHA-256, SHA3-256)
✅ Sprint 5: HMAC for data authenticity and integrity
✅ Sprint 6: GCM authenticated encryption with associated data