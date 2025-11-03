# CryptoCore

A command-line tool for AES encryption and decryption supporting multiple modes of operation (ECB, CBC, CFB, OFB, CTR).

## Features

- **Algorithms**: AES-128
- **Modes**: ECB, CBC, CFB, OFB, CTR
- **Padding**: PKCS#7 (for ECB and CBC modes)
- **Key Format**: Hexadecimal string (16 bytes for AES-128)
- **IV Handling**: Automatic generation for encryption, file-based or argument for decryption

## Build Instructions

### Prerequisites

- GCC compiler
- OpenSSL development libraries

### On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev