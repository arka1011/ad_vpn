CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../src
LDFLAGS = -lcrypto

# Test executable
TEST_EXEC = test_crypto

# Library dependencies
CRYPTO_LIB = ../../build/lib/libcrypto.so

# Default target
all: $(TEST_EXEC)

# Crypto tests
$(TEST_EXEC): test_crypto.c $(CRYPTO_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_crypto.c -L../../build/lib -lcrypto -Wl,-rpath,../../build/lib

# Run tests
test: $(TEST_EXEC)
	@echo "Running Crypto Tests..."
	@./$(TEST_EXEC)

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
