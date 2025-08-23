CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../src
LDFLAGS = -lpthread -ldl

# Test executable
TEST_EXEC = test_executables

# Library dependencies
LOGGER_LIB = ../../build/lib/liblogger.so
TUN_LIB = ../../build/lib/libtun_utils.so
SECURE_CHANNEL_LIB = ../../build/lib/libsecure_channel.so
CRYPTO_LIB = ../../build/lib/libcrypto.so
CLIENT_LIB = ../../build/lib/libclient.so
SERVER_LIB = ../../build/lib/libserver.so

# Default target
all: 
	@echo "No test files found for executables module"
	@echo "Create test_executables.c to enable tests"

# Executables tests (only if test file exists)
ifneq (,$(wildcard test_executables.c))
all: $(TEST_EXEC)

$(TEST_EXEC): test_executables.c $(LOGGER_LIB) $(TUN_LIB) $(SECURE_CHANNEL_LIB) $(CRYPTO_LIB) $(CLIENT_LIB) $(SERVER_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_executables.c \
		-L../../build/lib -llogger -ltun_utils -lsecure_channel -lcrypto -lclient -lserver \
		-Wl,-rpath,../../build/lib $(LDFLAGS)
endif

# Run tests
test: 
	@echo "No test files found for executables module"

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
