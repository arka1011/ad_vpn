CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../src
LDFLAGS = -lcrypto -lpthread

# Test executable
TEST_EXEC = test_secure_channel

# Library dependencies
SECURE_CHANNEL_LIB = ../../build/lib/libsecure_channel.so

# Default target
all: 
	@echo "No test files found for secure_channel module"
	@echo "Create test_secure_channel.c to enable tests"

# Secure channel tests (only if test file exists)
ifneq (,$(wildcard test_secure_channel.c))
all: $(TEST_EXEC)

$(TEST_EXEC): test_secure_channel.c $(SECURE_CHANNEL_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_secure_channel.c -L../../build/lib -lsecure_channel -Wl,-rpath,../../build/lib $(LDFLAGS)
endif

# Run tests
test: 
	@echo "No test files found for secure_channel module"

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
