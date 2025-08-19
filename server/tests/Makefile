CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../../logger -I../../tun -I../../secure_channel -I../../crypto -I../../server
LDFLAGS = -lpthread -ldl

# Test executable
TEST_EXEC = test_server

# Library dependencies
SERVER_LIB = ../../build/lib/libserver.so
LOGGER_LIB = ../../build/lib/liblogger.so
TUN_LIB = ../../build/lib/libtun_utils.so
SECURE_CHANNEL_LIB = ../../build/lib/libsecure_channel.so
CRYPTO_LIB = ../../build/lib/libcrypto.so

# Default target
all: $(TEST_EXEC)

# Server tests
$(TEST_EXEC): test_server.c $(SERVER_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_server.c -L../../build/lib -lserver -llogger -ltun_utils -lsecure_channel -lcrypto -Wl,-rpath,../../build/lib

# Run tests
test: $(TEST_EXEC)
	@echo "Running Server Tests..."
	@./$(TEST_EXEC)

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
