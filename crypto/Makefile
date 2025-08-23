CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2 -fPIC
INCLUDES = -I.
LDFLAGS = -lcrypto

# Source files
CRYPTO_SRC = src/crypto.c
CRYPTO_OBJ = build/crypto.o

# Build directories
BUILD_DIR = ../build
BUILD_LIB = $(BUILD_DIR)/lib
BUILD_BIN = $(BUILD_DIR)/bin
BUILD_INCLUDE = $(BUILD_DIR)/include

# Local build directories
LOCAL_BUILD_LIB = build/lib
LOCAL_BUILD_BIN = build/bin
LOCAL_BUILD_INCLUDE = build/include

# Library names
CRYPTO_LIB_STATIC = $(BUILD_LIB)/libcrypto.a
CRYPTO_LIB_SHARED = $(BUILD_LIB)/libcrypto.so
LOCAL_CRYPTO_LIB_STATIC = $(LOCAL_BUILD_LIB)/libcrypto.a
LOCAL_CRYPTO_LIB_SHARED = $(LOCAL_BUILD_LIB)/libcrypto.so

# Test executable
TEST_EXEC = $(BUILD_BIN)/test_crypto
LOCAL_TEST_EXEC = $(LOCAL_BUILD_BIN)/test_crypto

# Default target
all: $(CRYPTO_LIB_STATIC) $(CRYPTO_LIB_SHARED) $(LOCAL_CRYPTO_LIB_STATIC) $(LOCAL_CRYPTO_LIB_SHARED) $(TEST_EXEC) $(LOCAL_TEST_EXEC)
	$(MAKE) -C tests

# Create build directories
$(BUILD_LIB):
	mkdir -p $(BUILD_LIB)

$(BUILD_BIN):
	mkdir -p $(BUILD_BIN)

$(BUILD_INCLUDE):
	mkdir -p $(BUILD_INCLUDE)

$(LOCAL_BUILD_LIB):
	mkdir -p $(LOCAL_BUILD_LIB)

$(LOCAL_BUILD_BIN):
	mkdir -p $(LOCAL_BUILD_BIN)

$(LOCAL_BUILD_INCLUDE):
	mkdir -p $(LOCAL_BUILD_INCLUDE)

# Compile crypto object
$(CRYPTO_OBJ): $(CRYPTO_SRC) src/crypto.h | $(LOCAL_BUILD_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(CRYPTO_SRC) -o $(CRYPTO_OBJ)

# Static library (main build)
$(CRYPTO_LIB_STATIC): $(CRYPTO_OBJ) | $(BUILD_LIB)
	ar rcs $@ $^

# Shared library (main build)
$(CRYPTO_LIB_SHARED): $(CRYPTO_OBJ) | $(BUILD_LIB)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Static library (local build)
$(LOCAL_CRYPTO_LIB_STATIC): $(CRYPTO_OBJ) | $(LOCAL_BUILD_LIB)
	ar rcs $@ $^

# Shared library (local build)
$(LOCAL_CRYPTO_LIB_SHARED): $(CRYPTO_OBJ) | $(LOCAL_BUILD_LIB)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Test executable (main build)
$(TEST_EXEC): tests/test_crypto.c $(CRYPTO_LIB_SHARED) | $(BUILD_BIN)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_crypto.c -L$(BUILD_LIB) -lcrypto -Wl,-rpath,$(BUILD_LIB)

# Test executable (local build)
$(LOCAL_TEST_EXEC): tests/test_crypto.c $(LOCAL_CRYPTO_LIB_SHARED) | $(LOCAL_BUILD_BIN)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_crypto.c -L$(LOCAL_BUILD_LIB) -lcrypto -Wl,-rpath,$(LOCAL_BUILD_LIB)

# Install shared library and headers
install: $(CRYPTO_LIB_SHARED)
	install -d /usr/local/lib /usr/local/include
	install -m 755 $(CRYPTO_LIB_SHARED) /usr/local/lib/
	install -m 644 src/crypto.h /usr/local/include/
	@echo "Running ldconfig to update shared library cache (requires root)..."
	@sudo ldconfig

# Uninstall
uninstall:
	rm -f /usr/local/lib/$(CRYPTO_LIB_SHARED) /usr/local/include/crypto.h

# Clean - only remove crypto-specific files
clean:
	rm -f $(CRYPTO_OBJ) $(CRYPTO_LIB_STATIC) $(CRYPTO_LIB_SHARED) $(TEST_EXEC)
	rm -f $(LOCAL_CRYPTO_LIB_STATIC) $(LOCAL_CRYPTO_LIB_SHARED) $(LOCAL_TEST_EXEC)
	rm -rf build/
	$(MAKE) -C tests clean

.PHONY: all clean install uninstall
