CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I.. -I../src
LDFLAGS = -lpthread

# Test executable
TEST_EXEC = test_logger

# Library dependencies
LOGGER_LIB = ../../build/lib/liblogger.so

# Default target
all: 
	@echo "Logger tests - library must be built first"
	@echo "Run 'make -C ..' to build the logger library"

# Logger tests (only if library exists)
ifneq (,$(wildcard $(LOGGER_LIB)))
all: $(TEST_EXEC)

$(TEST_EXEC): test_logger.c $(LOGGER_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_logger.c -L../../build/lib -llogger -Wl,-rpath,../../build/lib
endif

# Run tests
test: 
	@if [ -f $(LOGGER_LIB) ]; then \
		$(MAKE) $(TEST_EXEC); \
		echo "Running Logger Tests..."; \
		./$(TEST_EXEC); \
	else \
		echo "Logger library not found. Build the logger module first."; \
	fi

# Clean
clean:
	rm -f $(TEST_EXEC)

.PHONY: all test clean
