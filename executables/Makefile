CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I../logger -I../tun -I../secure_channel -I../crypto -I../client -I../server
LDFLAGS = -lpthread -ldl

# Build directories
BUILD_DIR = ../build
BUILD_LIB = $(BUILD_DIR)/lib
BUILD_BIN = $(BUILD_DIR)/bin
BUILD_INCLUDE = $(BUILD_DIR)/include

# Source files
CLIENT_SRC = src/vpn_client.c
SERVER_SRC = src/vpn_server.c

# Executables
CLIENT_EXEC = $(BUILD_BIN)/vpn_client
SERVER_EXEC = $(BUILD_BIN)/vpn_server

# Library dependencies
LOGGER_LIB = $(BUILD_LIB)/liblogger.so
TUN_LIB = $(BUILD_LIB)/libtun_utils.so
SECURE_CHANNEL_LIB = $(BUILD_LIB)/libsecure_channel.so
CRYPTO_LIB = $(BUILD_LIB)/libcrypto.so
CLIENT_LIB = $(BUILD_LIB)/libclient.so
SERVER_LIB = $(BUILD_LIB)/libserver.so

# Default target
all: $(CLIENT_EXEC) $(SERVER_EXEC)

# Create build directories
$(BUILD_LIB):
	mkdir -p $(BUILD_LIB)

$(BUILD_BIN):
	mkdir -p $(BUILD_BIN)

$(BUILD_INCLUDE):
	mkdir -p $(BUILD_INCLUDE)

# VPN Client executable
$(CLIENT_EXEC): $(CLIENT_SRC) $(CLIENT_LIB) $(LOGGER_LIB) | $(BUILD_BIN)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(CLIENT_SRC) \
		-L$(BUILD_LIB) -lclient -llogger -ltun_utils -lsecure_channel -lcrypto \
		-Wl,-rpath,$(BUILD_LIB) $(LDFLAGS)

# VPN Server executable
$(SERVER_EXEC): $(SERVER_SRC) $(SERVER_LIB) $(LOGGER_LIB) | $(BUILD_BIN)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SERVER_SRC) \
		-L$(BUILD_LIB) -lserver -llogger -ltun_utils -lsecure_channel -lcrypto \
		-Wl,-rpath,$(BUILD_LIB) $(LDFLAGS)

# Install executables
install: $(CLIENT_EXEC) $(SERVER_EXEC)
	install -d /usr/local/bin
	install -m 755 $(CLIENT_EXEC) /usr/local/bin/
	install -m 755 $(SERVER_EXEC) /usr/local/bin/
	@echo "VPN executables installed to /usr/local/bin/"

# Uninstall
uninstall:
	rm -f /usr/local/bin/vpn_client /usr/local/bin/vpn_server

# Clean
clean:
	rm -f $(CLIENT_EXEC) $(SERVER_EXEC)

# Dependencies
$(CLIENT_EXEC): $(CLIENT_LIB) $(LOGGER_LIB) $(TUN_LIB) $(SECURE_CHANNEL_LIB) $(CRYPTO_LIB)
$(SERVER_EXEC): $(SERVER_LIB) $(LOGGER_LIB) $(TUN_LIB) $(SECURE_CHANNEL_LIB) $(CRYPTO_LIB)

.PHONY: all clean install uninstall
