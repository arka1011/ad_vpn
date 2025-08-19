CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../../logger -I../../tun -I../../secure_channel -I../../crypto -I../../client
LDFLAGS = -lpthread -ldl

# Test executable
TEST_EXEC = test_client

# Library dependencies
CLIENT_LIB = ../../build/lib/libclient.so
LOGGER_LIB = ../../build/lib/liblogger.so
TUN_LIB = ../../build/lib/libtun_utils.so
SECURE_CHANNEL_LIB = ../../build/lib/libsecure_channel.so
CRYPTO_LIB = ../../build/lib/libcrypto.so

# Default target
all: $(TEST_EXEC)

# Client tests
$(TEST_EXEC): test_client.c $(CLIENT_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_client.c -L../../build/lib -lclient -llogger -ltun_utils -lsecure_channel -lcrypto -Wl,-rpath,../../build/lib

# Run tests
test: $(TEST_EXEC)
	@echo "Running Client Tests..."
	@./$(TEST_EXEC)

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
