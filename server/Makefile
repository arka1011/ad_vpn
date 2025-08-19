CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2 -fPIC
INCLUDES = -I. -I../logger -I../tun -I../secure_channel -I../crypto
LDFLAGS = -lpthread -ldl

# Source files
SERVER_SRC = server.c
SERVER_OBJ = server.o

# Build directories
BUILD_DIR = ../build
BUILD_LIB = $(BUILD_DIR)/lib
BUILD_BIN = $(BUILD_DIR)/bin
BUILD_INCLUDE = $(BUILD_DIR)/include

# Library names
SERVER_LIB_STATIC = $(BUILD_LIB)/libserver.a
SERVER_LIB_SHARED = $(BUILD_LIB)/libserver.so

# Dependencies (other module libraries)
LOGGER_LIB = $(BUILD_LIB)/liblogger.so
TUN_LIB = $(BUILD_LIB)/libtun_utils.so
SECURE_CHANNEL_LIB = $(BUILD_LIB)/libsecure_channel.so
CRYPTO_LIB = $(BUILD_LIB)/libcrypto.so

# Test executable
TEST_EXEC = $(BUILD_BIN)/test_server

# Default target
all: $(SERVER_LIB_STATIC) $(SERVER_LIB_SHARED) $(TEST_EXEC)

# Create build directories
$(BUILD_LIB):
	mkdir -p $(BUILD_LIB)

$(BUILD_BIN):
	mkdir -p $(BUILD_BIN)

$(BUILD_INCLUDE):
	mkdir -p $(BUILD_INCLUDE)

# Compile server object
$(SERVER_OBJ): $(SERVER_SRC) server.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $(SERVER_SRC) -o $(SERVER_OBJ)

# Static library
$(SERVER_LIB_STATIC): $(SERVER_OBJ) | $(BUILD_LIB)
	ar rcs $@ $^

# Shared library
$(SERVER_LIB_SHARED): $(SERVER_OBJ) | $(BUILD_LIB)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Test executable
$(TEST_EXEC): test_server.c $(SERVER_LIB_SHARED) | $(BUILD_BIN)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_server.c -L$(BUILD_LIB) -lserver -Wl,-rpath,$(BUILD_LIB)

# Install shared library and headers
install: $(SERVER_LIB_SHARED)
	install -d /usr/local/lib /usr/local/include
	install -m 755 $(SERVER_LIB_SHARED) /usr/local/lib/
	install -m 644 server.h /usr/local/include/
	@echo "Running ldconfig to update shared library cache (requires root)..."
	@sudo ldconfig

# Uninstall
uninstall:
	rm -f /usr/local/lib/$(SERVER_LIB_SHARED) /usr/local/include/server.h

# Clean
clean:
	rm -f $(SERVER_OBJ) $(SERVER_LIB_STATIC) $(SERVER_LIB_SHARED) $(TEST_EXEC)
	rm -rf $(BUILD_DIR)

# Dependencies
$(SERVER_LIB_SHARED): $(LOGGER_LIB) $(TUN_LIB) $(SECURE_CHANNEL_LIB) $(CRYPTO_LIB)

.PHONY: all clean install uninstall
