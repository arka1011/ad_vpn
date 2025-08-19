# Detect platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
else ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
else
    PLATFORM := unknown
endif

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
INCLUDES = -I. -I../build/include
LDFLAGS = -lpthread -ldl

# Test executables (only logger available on macOS)
TEST_LOGGER = test_logger

# Library dependencies (from main build directory)
LOGGER_LIB = ../build/lib/liblogger.so

# Default target - platform specific
all: logger-tests
ifeq ($(PLATFORM),linux)
all: all crypto-tests tun-tests client-tests server-tests secure-channel-tests
endif

# Test targets
logger-tests:
	@echo "Building logger tests..."
	$(MAKE) -C ../logger/tests

crypto-tests:
	@echo "Building crypto tests..."
	$(MAKE) -C ../crypto/tests

tun-tests:
	@echo "Building TUN tests..."
	$(MAKE) -C ../tun/tests

client-tests:
	@echo "Building client tests..."
	$(MAKE) -C ../client/tests

server-tests:
	@echo "Building server tests..."
	$(MAKE) -C ../server/tests

secure-channel-tests:
	@echo "Building secure channel tests..."
	$(MAKE) -C ../secure_channel/tests

# Run all tests
test: all
	@echo "Running all tests..."
	@echo "===================="
	@echo "Testing Logger Module..."
	$(MAKE) -C ../logger/tests test
	@echo ""
ifeq ($(PLATFORM),linux)
	@echo "Testing Crypto Module..."
	$(MAKE) -C ../crypto/tests test
	@echo ""
	@echo "Testing TUN Module..."
	$(MAKE) -C ../tun/tests test
	@echo ""
	@echo "Testing Client Module..."
	$(MAKE) -C ../client/tests test
	@echo ""
	@echo "Testing Server Module..."
	$(MAKE) -C ../server/tests test
	@echo ""
	@echo "Testing Secure Channel Module..."
	$(MAKE) -C ../secure_channel/tests test
	@echo ""
else
	@echo "Skipping Linux-specific tests on $(PLATFORM)"
endif
	@echo "All tests completed!"

# Clean
clean:
	$(MAKE) -C ../logger/tests clean
ifeq ($(PLATFORM),linux)
	$(MAKE) -C ../crypto/tests clean
	$(MAKE) -C ../tun/tests clean
	$(MAKE) -C ../client/tests clean
	$(MAKE) -C ../server/tests clean
	$(MAKE) -C ../secure_channel/tests clean
endif

.PHONY: all test clean logger-tests crypto-tests tun-tests client-tests server-tests secure-channel-tests
