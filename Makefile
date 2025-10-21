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

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) | $(BIN_DIR)
	$(CC) $(TEST_OBJ) $(filter-out $(OBJ_DIR)/main.o, $(OBJECTS)) -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

install-dependencies:
	sudo apt-get update
	sudo apt-get install libssl-dev