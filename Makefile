CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -I./include -I./include/hash -I./include/mac -I./include/modes
LDFLAGS = -lcrypto -lssl

# Disable all built-in rules
MAKEFLAGS += -r

# Main directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files (explicitly list all source files)
MAIN_SRCS = $(SRC_DIR)/aead.c $(SRC_DIR)/cli_parser.c $(SRC_DIR)/crypto.c \
            $(SRC_DIR)/csprng.c $(SRC_DIR)/file_io.c $(SRC_DIR)/hash.c \
            $(SRC_DIR)/main.c $(SRC_DIR)/modes.c $(SRC_DIR)/kdf.c

MODE_SRCS = $(wildcard $(SRC_DIR)/modes/*.c)
HASH_SRCS = $(wildcard $(SRC_DIR)/hash/*.c)
MAC_SRCS = $(wildcard $(SRC_DIR)/mac/*.c)

# Object files
MAIN_OBJS = $(MAIN_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
MODE_OBJS = $(MODE_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
HASH_OBJS = $(HASH_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
MAC_OBJS = $(MAC_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# All object files
OBJS = $(MAIN_OBJS) $(MODE_OBJS) $(HASH_OBJS) $(MAC_OBJS)

# Target binary
TARGET = $(BIN_DIR)/cryptocore

# Test binaries
TEST_HMAC_BIN = $(BIN_DIR)/test_hmac_vectors
TEST_HASH_BIN = $(BIN_DIR)/test_hash
TEST_ROUNDTRIP_BIN = $(BIN_DIR)/test_roundtrip
TEST_CSPRNG_BIN = $(BIN_DIR)/test_csprng
TEST_HASH_REQ_BIN = $(BIN_DIR)/test_hash_requirements
TEST_GCM_BIN = $(BIN_DIR)/test_gcm_vectors
TEST_KDF_BIN = $(BIN_DIR)/test_kdf_vectors

# Test source files
TEST_HMAC_SRC = tests/src/test_hmac_vectors.c
TEST_HASH_SRC = tests/src/test_hash.c
TEST_ROUNDTRIP_SRC = tests/src/test_roundtrip.c
TEST_CSPRNG_SRC = tests/src/test_csprng.c
TEST_HASH_REQ_SRC = tests/src/test_hash_requirements.c
TEST_GCM_SRC = tests/src/test_gcm_vectors.c
TEST_KDF_SRC = tests/src/test_kdf_vectors.c

# Test object files
TEST_HMAC_OBJ = $(TEST_HMAC_SRC:tests/src/%.c=$(OBJ_DIR)/tests/%.o)
TEST_HASH_OBJ = $(TEST_HASH_SRC:tests/src/%.c=$(OBJ_DIR)/tests/%.o)
TEST_ROUNDTRIP_OBJ = $(TEST_ROUNDTRIP_SRC:tests/src/%.c=$(OBJ_DIR)/tests/%.o)
TEST_CSPRNG_OBJ = $(TEST_CSPRNG_SRC:tests/src/%.c=$(OBJ_DIR)/tests/%.o)
TEST_HASH_REQ_OBJ = $(TEST_HASH_REQ_SRC:tests/src/%.c=$(OBJ_DIR)/tests/%.o)
TEST_GCM_OBJ = $(TEST_GCM_SRC:tests/src/%.c=$(OBJ_DIR)/tests/%.o)
TEST_KDF_OBJ = $(TEST_KDF_SRC:tests/src/%.c=$(OBJ_DIR)/tests/%.o)

# Phony targets
.PHONY: all clean install-dependencies test test_hmac test_hash test_roundtrip test_csprng test_hash_req test_gcm test_kdf test_all help test_hmac_build test_hash_build test_roundtrip_build test_csprng_build test_hash_req_build test_gcm_build test_kdf_build test-data clean-test-data

# Default target
all: $(TARGET)

help:
	@echo "Available targets:"
	@echo "  all                     - Build main binary (default)"
	@echo "  clean                   - Remove all build artifacts"
	@echo "  clean_tests             - Remove test binaries only"
	@echo "  clean_all               - Remove all build artifacts and tests"
	@echo "  install-dependencies    - Install required dependencies"
	@echo "  test                    - Run all unit tests"
	@echo "  test_hmac               - Run HMAC unit tests"
	@echo "  test_hash               - Run hash function unit tests"
	@echo "  test_hash_req           - Run hash requirements tests"
	@echo "  test_roundtrip          - Run round-trip encryption tests"
	@echo "  test_csprng             - Run CSPRNG tests"
	@echo "  test_gcm                - Run GCM tests"
	@echo "  test_kdf                - Run KDF tests"
	@echo "  test_hmac_build         - Build HMAC test binary"
	@echo "  test_hash_build         - Build hash test binary"
	@echo "  test_roundtrip_build    - Build round-trip test binary"
	@echo "  test_csprng_build       - Build CSPRNG test binary"
	@echo "  test_hash_req_build     - Build hash requirements test binary"
	@echo "  test_gcm_build          - Build GCM test binary"
	@echo "  test_kdf_build          - Build KDF test binary"
	@echo "  test_all                - Run all tests (unit + integration)"
	@echo "  test-data               - Generate test data files"
	@echo "  clean-test-data         - Clean test data files"
	@echo "  help                    - Show this help message"

# Main binary
$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "✓ Built main binary: $@"

# Generic rule for all .c files in src root
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled: $<"

# Special rule for modes/ directory
$(OBJ_DIR)/modes/%.o: $(SRC_DIR)/modes/%.c | $(OBJ_DIR)/modes
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled: $<"

# Special rule for hash/ directory  
$(OBJ_DIR)/hash/%.o: $(SRC_DIR)/hash/%.c | $(OBJ_DIR)/hash
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled: $<"

# Special rule for mac/ directory
$(OBJ_DIR)/mac/%.o: $(SRC_DIR)/mac/%.c | $(OBJ_DIR)/mac
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled: $<"

# Create directories
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/hash
	@mkdir -p $(OBJ_DIR)/modes
	@mkdir -p $(OBJ_DIR)/mac
	@mkdir -p $(OBJ_DIR)/tests
	@echo "Created directory: $@"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)
	@echo "Created directory: $@"

# Install dependencies
install-dependencies:
	@echo "=== Installing Dependencies ==="
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev xxd openssl
	@echo "✓ Dependencies installed"

# Clean
clean:
	@echo "=== Cleaning Build Artifacts ==="
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "✓ Cleaned all build artifacts"

# Clean test files
clean_tests:
	@echo "=== Cleaning Test Binaries ==="
	rm -f $(TEST_HMAC_BIN) $(TEST_HASH_BIN) $(TEST_ROUNDTRIP_BIN) $(TEST_CSPRNG_BIN) $(TEST_HASH_REQ_BIN) $(TEST_GCM_BIN) $(TEST_KDF_BIN)
	rm -rf $(OBJ_DIR)/tests
	@echo "✓ Cleaned test binaries"

clean_all: clean clean_tests clean-test-data
	@echo "✓ Cleaned all build artifacts and tests"

# Test data management
test-data:
	@echo "=== Generating Test Data ==="
	@if [ -f "generate_test_files.sh" ]; then \
		chmod +x generate_test_files.sh; \
		./generate_test_files.sh; \
	else \
		echo "Error: generate_test_files.sh not found in current directory"; \
		echo "Please create generate_test_files.sh script first"; \
		exit 1; \
	fi

clean-test-data:
	@echo "=== Cleaning Test Data ==="
	rm -rf test_data
	rm -f encrypted.bin decrypted.txt *.hmac key.txt *.enc *.dec test_*.txt test_*.bin
	@echo "✓ Test data cleaned"

# Test targets
test_hmac_build: $(TEST_HMAC_BIN)
test_hash_build: $(TEST_HASH_BIN)
test_roundtrip_build: $(TEST_ROUNDTRIP_BIN)
test_csprng_build: $(TEST_CSPRNG_BIN)
test_hash_req_build: $(TEST_HASH_REQ_BIN)
test_gcm_build: $(TEST_GCM_BIN)
test_kdf_build: $(TEST_KDF_BIN)

$(TEST_HMAC_BIN): $(TEST_HMAC_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✓ Built HMAC test binary: $@"

$(TEST_HASH_BIN): $(TEST_HASH_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✓ Built hash test binary: $@"

$(TEST_ROUNDTRIP_BIN): $(TEST_ROUNDTRIP_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✓ Built round-trip test binary: $@"

$(TEST_CSPRNG_BIN): $(TEST_CSPRNG_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✓ Built CSPRNG test binary: $@"

$(TEST_HASH_REQ_BIN): $(TEST_HASH_REQ_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✓ Built hash requirements test binary: $@"

$(TEST_GCM_BIN): $(TEST_GCM_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✓ Built GCM test binary: $@"

$(TEST_KDF_BIN): $(TEST_KDF_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJS))
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "✓ Built KDF test binary: $@"

# Rule for test object files
$(OBJ_DIR)/tests/%.o: tests/src/%.c | $(OBJ_DIR)/tests
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled test: $<"

$(OBJ_DIR)/tests:
	@mkdir -p $@

# Run tests
test_hmac: test_hmac_build
	@echo "=== Running HMAC Tests ==="
	$(TEST_HMAC_BIN)

test_hash: test_hash_build
	@echo "=== Running Hash Tests ==="
	$(TEST_HASH_BIN)

test_hash_req: test_hash_req_build
	@echo "=== Running Hash Requirements Tests ==="
	$(TEST_HASH_REQ_BIN)

test_roundtrip: test_roundtrip_build
	@echo "=== Running Round-trip Tests ==="
	$(TEST_ROUNDTRIP_BIN)

test_csprng: test_csprng_build
	@echo "=== Running CSPRNG Tests ==="
	$(TEST_CSPRNG_BIN)

test_gcm: test_gcm_build
	@echo "=== Running GCM Tests ==="
	$(TEST_GCM_BIN)

test_kdf: test_kdf_build
	@echo "=== Running KDF Tests ==="
	$(TEST_KDF_BIN)

test: test_hash test_hash_req test_roundtrip test_csprng test_hmac test_gcm test_kdf
	@echo ""
	@echo "=== All Unit Tests Passed! ==="

test_all: test test-data
	@echo ""
	@echo "=== Running Integration Tests ==="
	@if [ -f "tests/scripts/test_kdf_integration.sh" ]; then \
		cd tests/scripts && ./test_kdf_integration.sh; \
	else \
		echo "Note: Integration tests not found, running unit tests only"; \
	fi
	@echo ""
	@echo "=== Integration test completed ==="