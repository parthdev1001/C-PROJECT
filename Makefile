CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -std=c99 -Iinclude -O2 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS ?= -lpcap

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests

SRCS = $(SRC_DIR)/capture.c \
       $(SRC_DIR)/parser.c \
       $(SRC_DIR)/display.c

OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
MAIN_OBJ = $(OBJ_DIR)/main.o

TARGET = $(BIN_DIR)/netsnoop
TEST_TARGET = $(BIN_DIR)/test_parser

.PHONY: all clean test run

all: $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(OBJ_DIR)/test_parser.o: $(TEST_DIR)/test_parser.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_TARGET): $(OBJS) $(OBJ_DIR)/test_parser.o | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

test: $(TEST_TARGET)
	@echo "Running NetSnoop Unit Tests..."
	@./$(TEST_TARGET)

run: $(TARGET)
	@echo "Running NetSnoop against sample PCAP..."
	./$(TARGET) -r samples/sample_traffic.pcap

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) netsnoop.log
