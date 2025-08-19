CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../../logger -I../../tun
LDFLAGS = -lpthread

# Test executable
TEST_EXEC = test_tun

# Library dependencies
TUN_LIB = ../../build/lib/libtun_utils.so
LOGGER_LIB = ../../build/lib/liblogger.so

# Default target
all: $(TEST_EXEC)

# TUN tests
$(TEST_EXEC): test_tun.c $(TUN_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_tun.c -L../../build/lib -ltun_utils -llogger -Wl,-rpath,../../build/lib

# Run tests
test: $(TEST_EXEC)
	@echo "Running TUN Tests..."
	@./$(TEST_EXEC)

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
