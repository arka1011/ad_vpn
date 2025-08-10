CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
LDFLAGS = -lpthread

# Directories
LOGGER_DIR = ../logger
SRC_DIR = .
BUILD_DIR = build

# Source files
CLIENT_SRC = $(SRC_DIR)/linux_client.c
LOGGER_SRC = $(LOGGER_DIR)/logger.c

# Object files
CLIENT_OBJ = $(BUILD_DIR)/linux_client.o
LOGGER_OBJ = $(BUILD_DIR)/logger.o

# Target executable
CLIENT_EXEC = linux_client

# Create build directory
$(shell mkdir -p $(BUILD_DIR))

# Default target
all: $(CLIENT_EXEC)

# Build client executable
$(CLIENT_EXEC): $(CLIENT_OBJ) $(LOGGER_OBJ)
	$(CC) $(CLIENT_OBJ) $(LOGGER_OBJ) -o $(CLIENT_EXEC) $(LDFLAGS)

# Compile client source
$(CLIENT_OBJ): $(CLIENT_SRC) $(LOGGER_DIR)/logger.h
	$(CC) $(CFLAGS) -c $(CLIENT_SRC) -o $(CLIENT_OBJ)

# Compile logger
$(LOGGER_OBJ): $(LOGGER_SRC) $(LOGGER_DIR)/logger.h
	$(CC) $(CFLAGS) -c $(LOGGER_SRC) -o $(LOGGER_OBJ)

# Clean build files
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(CLIENT_EXEC)
	rm -f *.log

# Install (optional)
install: $(CLIENT_EXEC)
	sudo cp $(CLIENT_EXEC) /usr/local/bin/

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(CLIENT_EXEC)

# Run client
run: $(CLIENT_EXEC)
	./$(CLIENT_EXEC)

# Debug build
debug: CFLAGS += -DDEBUG -O0
debug: $(CLIENT_EXEC)

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: $(CLIENT_EXEC)

# Test connection to server
test: $(CLIENT_EXEC)
	./$(CLIENT_EXEC) 127.0.0.1 8080

.PHONY: all clean install uninstall run debug release test
