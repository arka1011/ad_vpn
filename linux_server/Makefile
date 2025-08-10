CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
LDFLAGS = -lpthread

# Directories
LOGGER_DIR = ../logger
SRC_DIR = .
BUILD_DIR = build

# Source files
SERVER_SRC = $(SRC_DIR)/linux_server.c
LOGGER_SRC = $(LOGGER_DIR)/logger.c

# Object files
SERVER_OBJ = $(BUILD_DIR)/linux_server.o
LOGGER_OBJ = $(BUILD_DIR)/logger.o

# Target executable
SERVER_EXEC = linux_server

# Create build directory
$(shell mkdir -p $(BUILD_DIR))

# Default target
all: $(SERVER_EXEC)

# Build server executable
$(SERVER_EXEC): $(SERVER_OBJ) $(LOGGER_OBJ)
	$(CC) $(SERVER_OBJ) $(LOGGER_OBJ) -o $(SERVER_EXEC) $(LDFLAGS)

# Compile server source
$(SERVER_OBJ): $(SERVER_SRC) $(LOGGER_DIR)/logger.h
	$(CC) $(CFLAGS) -c $(SERVER_SRC) -o $(SERVER_OBJ)

# Compile logger
$(LOGGER_OBJ): $(LOGGER_SRC) $(LOGGER_DIR)/logger.h
	$(CC) $(CFLAGS) -c $(LOGGER_SRC) -o $(LOGGER_OBJ)

# Clean build files
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SERVER_EXEC)
	rm -f *.log

# Install (optional)
install: $(SERVER_EXEC)
	sudo cp $(SERVER_EXEC) /usr/local/bin/

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(SERVER_EXEC)

# Run server
run: $(SERVER_EXEC)
	./$(SERVER_EXEC)

# Debug build
debug: CFLAGS += -DDEBUG -O0
debug: $(SERVER_EXEC)

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: $(SERVER_EXEC)

.PHONY: all clean install uninstall run debug release
