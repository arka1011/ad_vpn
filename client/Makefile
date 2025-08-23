CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2 -fPIC
INCLUDES = -I. -I../logger -I../tun -I../crypto -I../secure_channel
LDFLAGS = -lpthread -ldl

# Source files
CLIENT_SRC = src/client.c
CLIENT_OBJ = build/client.o

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
CLIENT_LIB_STATIC = $(BUILD_LIB)/libclient.a
CLIENT_LIB_SHARED = $(BUILD_LIB)/libclient.so
LOCAL_CLIENT_LIB_STATIC = $(LOCAL_BUILD_LIB)/libclient.a
LOCAL_CLIENT_LIB_SHARED = $(LOCAL_BUILD_LIB)/libclient.so

# Dependencies (other module libraries)
LOGGER_LIB = $(BUILD_LIB)/liblogger.so
TUN_LIB = $(BUILD_LIB)/libtun_utils.so
SECURE_CHANNEL_LIB = $(BUILD_LIB)/libsecure_channel.so
CRYPTO_LIB = $(BUILD_LIB)/libcrypto.so

# Test executable
TEST_EXEC = $(BUILD_BIN)/test_client

# Default target
all: $(CLIENT_LIB_STATIC) $(CLIENT_LIB_SHARED) $(LOCAL_CLIENT_LIB_STATIC) $(LOCAL_CLIENT_LIB_SHARED)
#	$(MAKE) -C tests

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

# Compile client object
$(CLIENT_OBJ): $(CLIENT_SRC) src/client.h | $(LOCAL_BUILD_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(CLIENT_SRC) -o $(CLIENT_OBJ)

# Static library (main build)
$(CLIENT_LIB_STATIC): $(CLIENT_OBJ) | $(BUILD_LIB)
	ar rcs $@ $^

# Shared library (main build)
$(CLIENT_LIB_SHARED): $(CLIENT_OBJ) | $(BUILD_LIB)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Static library (local build)
$(LOCAL_CLIENT_LIB_STATIC): $(CLIENT_OBJ) | $(LOCAL_BUILD_LIB)
	ar rcs $@ $^

# Shared library (local build)
$(LOCAL_CLIENT_LIB_SHARED): $(CLIENT_OBJ) | $(LOCAL_BUILD_LIB)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Test executable (main build)
$(TEST_EXEC): tests/test_client.c $(CLIENT_LIB_SHARED) | $(BUILD_BIN)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tests/test_client.c -L$(BUILD_LIB) -lclient -Wl,-rpath,$(BUILD_LIB)

# Install shared library and headers
install: $(CLIENT_LIB_SHARED)
	install -d /usr/local/lib /usr/local/include
	install -m 755 $(CLIENT_LIB_SHARED) /usr/local/lib/
	install -m 644 src/client.h /usr/local/include/
	@echo "Running ldconfig to update shared library cache (requires root)..."
	@sudo ldconfig

# Uninstall
uninstall:
	rm -f /usr/local/lib/$(CLIENT_LIB_SHARED) /usr/local/include/client.h

# Clean - only remove client-specific files
clean:
	rm -f $(CLIENT_OBJ) $(CLIENT_LIB_STATIC) $(CLIENT_LIB_SHARED) $(TEST_EXEC)
	rm -f $(LOCAL_CLIENT_LIB_STATIC) $(LOCAL_CLIENT_LIB_SHARED)
	rm -rf build/
	$(MAKE) -C tests clean

# Dependencies
$(CLIENT_LIB_SHARED): $(LOGGER_LIB) $(TUN_LIB) $(SECURE_CHANNEL_LIB) $(CRYPTO_LIB)

.PHONY: all clean install uninstall
