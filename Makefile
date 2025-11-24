CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = -lcrypto

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/cryptocore

TEST_SRC = tests/test_roundtrip.c
TEST_OBJ = $(OBJ_DIR)/test_roundtrip.o
TEST_TARGET = $(BIN_DIR)/test_roundtrip

CSRPNG_TEST_SRC = tests/test_csprng.c
CSRPNG_TEST_OBJ = $(OBJ_DIR)/test_csprng.o
CSRPNG_TEST_TARGET = $(BIN_DIR)/test_csprng

.PHONY: all clean test csprng_test

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Правило для компиляции тестовых файлов
$(OBJ_DIR)/%.o: tests/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

test: $(TEST_TARGET) $(CSRPNG_TEST_TARGET)
	@echo "=== Running Round-trip Tests ==="
	./$(TEST_TARGET)
	@echo ""
	@echo "=== Running CSPRNG Tests ==="
	./$(CSRPNG_TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) | $(BIN_DIR)
	$(CC) $(TEST_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) -o $@ $(LDFLAGS)

csprng_test: $(CSRPNG_TEST_TARGET)
	./$(CSRPNG_TEST_TARGET)

$(CSRPNG_TEST_TARGET): $(CSRPNG_TEST_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) | $(BIN_DIR)
	$(CC) $(CSRPNG_TEST_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) nist_test_data.bin

install-dependencies:
	sudo apt-get update
	sudo apt-get install libssl-dev