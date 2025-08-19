CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../src
LDFLAGS = -lpthread

# Test executable
TEST_EXEC = test_logger

# Library dependencies
LOGGER_LIB = ../../build/lib/liblogger.so

# Default target
all: $(TEST_EXEC)

# Logger tests
$(TEST_EXEC): test_logger.c $(LOGGER_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_logger.c -L../../build/lib -llogger -Wl,-rpath,../../build/lib

# Run tests
test: $(TEST_EXEC)
	@echo "Running Logger Tests..."
	@./$(TEST_EXEC)

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
