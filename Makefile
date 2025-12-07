CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -I./include -I./include/hash
LDFLAGS = -lcrypto -lssl

# Основные директории
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
INC_DIR = include
HASH_INC_DIR = include/hash

# Директории для тестов
TEST_SRC_DIR = tests/src
TEST_BIN_DIR = tests/bin
TEST_OBJ_DIR = obj/tests
TEST_DATA_DIR = tests/data
TEST_SCRIPTS_DIR = tests/scripts
TEST_RESULTS_DIR = tests/results

# Основные исходные файлы (существующие)
MAIN_SRCS = $(wildcard $(SRC_DIR)/*.c)
MODE_SRCS = $(wildcard $(SRC_DIR)/modes/*.c)
HASH_SRCS = $(wildcard $(SRC_DIR)/hash/*.c)

# Все исходные файлы
ALL_SRCS = $(MAIN_SRCS) $(MODE_SRCS) $(HASH_SRCS)

# Объектные файлы
MAIN_OBJS = $(MAIN_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
MODE_OBJS = $(MODE_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
HASH_OBJS = $(HASH_SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Все объектные файлы
OBJS = $(MAIN_OBJS) $(MODE_OBJS) $(HASH_OBJS)

# Целевой бинарник
TARGET = $(BIN_DIR)/cryptocore

# Тестовые файлы
TEST_SRCS = $(wildcard $(TEST_SRC_DIR)/*.c)
TEST_OBJS = $(TEST_SRCS:$(TEST_SRC_DIR)/%.c=$(TEST_OBJ_DIR)/%.o)
TEST_TARGETS = $(TEST_BIN_DIR)/test_csprng $(TEST_BIN_DIR)/test_roundtrip $(TEST_BIN_DIR)/test_hash $(TEST_BIN_DIR)/test_hash_requirements

# Имена отдельных тестовых целей
TEST_CSPRNG_SRC = $(TEST_SRC_DIR)/test_csprng.c
TEST_CSPRNG_OBJ = $(TEST_OBJ_DIR)/test_csprng.o
TEST_CSPRNG_TARGET = $(TEST_BIN_DIR)/test_csprng

TEST_ROUNDTRIP_SRC = $(TEST_SRC_DIR)/test_roundtrip.c
TEST_ROUNDTRIP_OBJ = $(TEST_OBJ_DIR)/test_roundtrip.o
TEST_ROUNDTRIP_TARGET = $(TEST_BIN_DIR)/test_roundtrip

TEST_HASH_SRC = $(TEST_SRC_DIR)/test_hash.c
TEST_HASH_OBJ = $(TEST_OBJ_DIR)/test_hash.o
TEST_HASH_TARGET = $(TEST_BIN_DIR)/test_hash

TEST_HASH_REQ_SRC = tests/src/test_hash_requirements.c
TEST_HASH_REQ_OBJ = obj/tests/test_hash_requirements.o
TEST_HASH_REQ_TARGET = tests/bin/test_hash_requirements

# Основные объектные файлы без main.o (для линковки тестов)
MAIN_OBJ = $(OBJ_DIR)/main.o
LIB_OBJS = $(filter-out $(MAIN_OBJ), $(OBJS))

# Phony targets
.PHONY: all clean install-dependencies test test_build run_tests \
        nist_test csprng_test roundtrip_test hash_test hash_req_test help

# Default target
all: $(TARGET) test_build

help:
	@echo "Available targets:"
	@echo "  all              - Build main binary and tests (default)"
	@echo "  $(TARGET)        - Build only main binary"
	@echo "  test_build       - Build only test binaries"
	@echo "  test             - Run all unit tests"
	@echo "  hash_test        - Run only basic hash function tests"
	@echo "  hash_req_test    - Run hash requirements tests (avalanche, interoperability)"
	@echo "  run_tests        - Run all tests (unit + integration)"
	@echo "  csprng_test      - Run only CSPRNG tests"
	@echo "  roundtrip_test   - Run only round-trip tests"
	@echo "  nist_test        - Generate data for NIST tests"
	@echo "  clean            - Remove all build artifacts"
	@echo "  install-dependencies - Install required dependencies"
	@echo "  help             - Show this help message"

# Основной бинарник
$(TARGET): $(OBJS) | $(BIN_DIR)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "✓ Built main binary: $@"

# Правило для основных объектных файлов
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled: $<"

# Правило для hash объектных файлов
$(OBJ_DIR)/hash/%.o: $(SRC_DIR)/hash/%.c | $(OBJ_DIR)/hash
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled: $<"

# Правило для modes объектных файлов
$(OBJ_DIR)/modes/%.o: $(SRC_DIR)/modes/%.c | $(OBJ_DIR)/modes
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled: $<"

# Сборка тестовых бинарников
test_build: $(TEST_TARGETS)

$(TEST_CSPRNG_TARGET): $(TEST_CSPRNG_OBJ) $(LIB_OBJS) | $(TEST_BIN_DIR)
	$(CC) $(TEST_CSPRNG_OBJ) $(LIB_OBJS) -o $@ $(LDFLAGS)
	@echo "✓ Built test: $@"

$(TEST_ROUNDTRIP_TARGET): $(TEST_ROUNDTRIP_OBJ) $(LIB_OBJS) | $(TEST_BIN_DIR)
	$(CC) $(TEST_ROUNDTRIP_OBJ) $(LIB_OBJS) -o $@ $(LDFLAGS)
	@echo "✓ Built test: $@"

$(TEST_HASH_TARGET): $(TEST_HASH_OBJ) $(LIB_OBJS) | $(TEST_BIN_DIR)
	$(CC) $(TEST_HASH_OBJ) $(LIB_OBJS) -o $@ $(LDFLAGS)
	@echo "✓ Built test: $@"

$(TEST_HASH_REQ_TARGET): $(TEST_HASH_REQ_OBJ) $(LIB_OBJS) | $(TEST_BIN_DIR)
	$(CC) $(TEST_HASH_REQ_OBJ) $(LIB_OBJS) -o $@ $(LDFLAGS)
	@echo "✓ Built test: $@"

# Правило для тестовых объектных файлов
$(TEST_OBJ_DIR)/%.o: $(TEST_SRC_DIR)/%.c | $(TEST_OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  Compiled test: $<"

# Запуск юнит-тестов
test: test_build
	@echo ""
	@echo "=== Running All Unit Tests ==="
	@echo ""
	@echo "1. CSPRNG Tests:"
	@$(TEST_CSPRNG_TARGET) && echo "   ✓ CSPRNG tests passed" || (echo "   ✗ CSPRNG tests failed" && exit 1)
	@echo ""
	@echo "2. Round-trip Tests:"
	@$(TEST_ROUNDTRIP_TARGET) && echo "   ✓ Round-trip tests passed" || (echo "   ✗ Round-trip tests failed" && exit 1)
	@echo ""
	@echo "3. Basic Hash Function Tests:"
	@$(TEST_HASH_TARGET) && echo "   ✓ Basic hash function tests passed" || (echo "   ✗ Basic hash function tests failed" && exit 1)
	@echo ""
	@echo "4. Hash Requirements Tests:"
	@$(TEST_HASH_REQ_TARGET) && echo "   ✓ Hash requirements tests passed" || (echo "   ✗ Hash requirements tests failed" && exit 1)
	@echo ""
	@echo "=== All unit tests passed! ==="

# Отдельные тесты
csprng_test: $(TEST_CSPRNG_TARGET)
	@echo "=== Running CSPRNG Tests ==="
	@$(TEST_CSPRNG_TARGET)

roundtrip_test: $(TEST_ROUNDTRIP_TARGET)
	@echo "=== Running Round-trip Tests ==="
	@$(TEST_ROUNDTRIP_TARGET)

hash_test: $(TEST_HASH_TARGET)
	@echo "=== Running Basic Hash Function Tests ==="
	@$(TEST_HASH_TARGET)

hash_req_test: $(TEST_HASH_REQ_TARGET)
	@echo "=== Running Hash Requirements Tests ==="
	@$(TEST_HASH_REQ_TARGET)

# Запуск всех тестов (юнит + интеграционные)
run_tests: test_build
	@echo ""
	@echo "=== Running Complete Test Suite ==="
	@echo ""
	
	# Юнит-тесты
	@echo "1. Unit Tests:"
	@$(TEST_CSPRNG_TARGET) > $(TEST_RESULTS_DIR)/csprng_test.log 2>&1 && \
	    echo "   ✓ CSPRNG tests passed" || (echo "   ✗ CSPRNG tests failed" && cat $(TEST_RESULTS_DIR)/csprng_test.log && false)
	@$(TEST_ROUNDTRIP_TARGET) > $(TEST_RESULTS_DIR)/roundtrip_test.log 2>&1 && \
	    echo "   ✓ Round-trip tests passed" || (echo "   ✗ Round-trip tests failed" && cat $(TEST_RESULTS_DIR)/roundtrip_test.log && false)
	@$(TEST_HASH_TARGET) > $(TEST_RESULTS_DIR)/hash_test.log 2>&1 && \
	    echo "   ✓ Basic hash function tests passed" || (echo "   ✗ Basic hash function tests failed" && cat $(TEST_RESULTS_DIR)/hash_test.log && false)
	@$(TEST_HASH_REQ_TARGET) > $(TEST_RESULTS_DIR)/hash_req_test.log 2>&1 && \
	    echo "   ✓ Hash requirements tests passed" || (echo "   ✗ Hash requirements tests failed" && cat $(TEST_RESULTS_DIR)/hash_req_test.log && false)
	
	@echo ""
	@echo "2. Integration Tests:"
	
	# Создаем тестовые файлы
	@mkdir -p $(TEST_DATA_DIR)/test_files
	@echo "Test data for integration" > $(TEST_DATA_DIR)/test_files/test1.txt
	@echo -n "0123456789ABCDEF" > $(TEST_DATA_DIR)/test_16_bytes.txt
	@echo -n "0123456789ABCDE" > $(TEST_DATA_DIR)/test_15_bytes.txt
	
	# Round-trip integration test
	@chmod +x $(TEST_SCRIPTS_DIR)/test_roundtrip.sh 2>/dev/null || true
	@if [ -f "$(TEST_SCRIPTS_DIR)/test_roundtrip.sh" ]; then \
	    echo "   Running round-trip integration test..."; \
	    $(TEST_SCRIPTS_DIR)/test_roundtrip.sh > $(TEST_RESULTS_DIR)/integration_roundtrip.log 2>&1 && \
	    echo "   ✓ Round-trip integration test passed" || (echo "   ✗ Round-trip integration test failed" && false); \
	else \
	    echo "   ⚠ Round-trip integration script not found"; \
	fi
	
	# Hash integration test
	@if [ -f "$(TARGET)" ]; then \
	    echo "   Running hash integration test..."; \
	    echo "Test hash data" > $(TEST_DATA_DIR)/hash_test.txt; \
	    $(TARGET) dgst --algorithm sha256 --input $(TEST_DATA_DIR)/hash_test.txt > $(TEST_RESULTS_DIR)/hash_integration.log 2>&1 && \
	    echo "   ✓ Hash integration test passed" || (echo "   ✗ Hash integration test failed" && false); \
	    \
	    # Test stdin input \
	    echo "   Testing stdin input..."; \
	    echo -n "abc" | $(TARGET) dgst --algorithm sha256 --input - > $(TEST_RESULTS_DIR)/hash_stdin.log 2>&1 && \
	    echo "   ✓ Stdin hash test passed" || (echo "   ✗ Stdin hash test failed" && false); \
	else \
	    echo "   ⚠ Main binary not found for hash integration test"; \
	fi
	
	# Key generation test
	@chmod +x $(TEST_SCRIPTS_DIR)/test_key_generation.sh 2>/dev/null || true
	@if [ -f "$(TEST_SCRIPTS_DIR)/test_key_generation.sh" ]; then \
	    echo "   Running key generation test..."; \
	    $(TEST_SCRIPTS_DIR)/test_key_generation.sh > $(TEST_RESULTS_DIR)/integration_keygen.log 2>&1 && \
	    echo "   ✓ Key generation test passed" || (echo "   ✗ Key generation test failed" && false); \
	else \
	    echo "   ⚠ Key generation script not found"; \
	fi
	
	@echo ""
	@echo "=== All tests completed ==="
	@echo "Logs available in $(TEST_RESULTS_DIR)/"

# Генерация данных для NIST тестов
nist_test: $(TEST_CSPRNG_TARGET) | $(TEST_RESULTS_DIR)
	@echo "=== Generating NIST Test Data ==="
	@$(TEST_CSPRNG_TARGET) 2>/dev/null || true
	@if [ -f "$(TEST_RESULTS_DIR)/nist_test_data.bin" ]; then \
	    size=$$(stat -c%s "$(TEST_RESULTS_DIR)/nist_test_data.bin"); \
	    echo "✓ Generated $(TEST_RESULTS_DIR)/nist_test_data.bin ($$size bytes)"; \
	    echo ""; \
	    echo "To run NIST STS:"; \
	    echo "1. Download NIST STS from https://csrc.nist.gov/projects/random-bit-generation/documentation-and-software"; \
	    echo "2. Compile: tar -xzf sts-2.1.2.tar.gz && cd sts-2.1.2 && make"; \
	    echo "3. Run: ./assess 1000000"; \
	    echo "4. Use $(TEST_RESULTS_DIR)/nist_test_data.bin as input"; \
	else \
	    echo "⚠ NIST test data not generated"; \
	    echo "Running test manually:"; \
	    $(TEST_CSPRNG_TARGET); \
	fi

# Установка зависимостей
install-dependencies:
	@echo "=== Installing Dependencies ==="
	sudo apt-get update
	sudo apt-get install -y build-essential libssl-dev xxd openssl
	@echo "✓ Dependencies installed"

# Создание директорий
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(OBJ_DIR)/hash
	@mkdir -p $(OBJ_DIR)/modes
	@echo "Created directory: $@"

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)
	@echo "Created directory: $@"

$(TEST_BIN_DIR):
	@mkdir -p $(TEST_BIN_DIR)
	@echo "Created directory: $@"

$(TEST_OBJ_DIR):
	@mkdir -p $(TEST_OBJ_DIR)
	@echo "Created directory: $@"

$(TEST_RESULTS_DIR):
	@mkdir -p $(TEST_RESULTS_DIR)
	@echo "Created directory: $@"

# Очистка
clean:
	@echo "=== Cleaning Build Artifacts ==="
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	rm -rf $(TEST_OBJ_DIR) $(TEST_BIN_DIR)
	rm -f $(TEST_RESULTS_DIR)/*.log $(TEST_RESULTS_DIR)/nist_test_data.bin 2>/dev/null || true
	rm -f $(TEST_DATA_DIR)/*.enc $(TEST_DATA_DIR)/*.dec $(TEST_DATA_DIR)/test_*.txt 2>/dev/null || true
	rm -f $(TEST_DATA_DIR)/test_files/*.enc $(TEST_DATA_DIR)/test_files/*.dec 2>/dev/null || true
	rm -f $(TEST_DATA_DIR)/hash_test.txt 2>/dev/null || true
	@echo "✓ Cleaned all build artifacts"

# Автоматическое создание директорий перед сборкой
$(OBJS): | $(OBJ_DIR)
$(TEST_OBJS): | $(TEST_OBJ_DIR)
$(TARGET): | $(BIN_DIR)
$(TEST_TARGETS): | $(TEST_BIN_DIR)