CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -Iinclude -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lcrypto

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SOURCES = $(SRC_DIR)/main.c $(SRC_DIR)/cli_parser.c $(SRC_DIR)/file_io.c $(SRC_DIR)/crypto.c $(SRC_DIR)/modes/ecb.c
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
TARGET = $(BIN_DIR)/cryptocore

TEST_SRC = tests/test_roundtrip.c
TEST_OBJ = $(OBJ_DIR)/test_roundtrip.o
TEST_TARGET = $(BIN_DIR)/test_roundtrip

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

test: $(TEST_TARGET)
	$(TEST_TARGET)

$(TEST_TARGET): $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) $(TEST_OBJ) | $(BIN_DIR)
	$(CC) $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) $(TEST_OBJ) -o $@ $(LDFLAGS)

$(OBJ_DIR)/test_roundtrip.o: $(TEST_SRC) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

install-dependencies:
	sudo apt-get update
	sudo apt-get install libssl-dev