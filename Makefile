CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
LDFLAGS = -lpthread

# Source files
LOGGER_SRC = logger/logger.c
LOGGER_OBJ = logger/logger.o
EXAMPLE_SRC = logger/logger_example.c
EXAMPLE_OBJ = logger/logger_example.o
SERVER_DIR = linux_server
CLIENT_DIR = linux_client

# Targets
all: logger_example linux_server linux_client

# Build logger library
logger_lib: $(LOGGER_OBJ)
	ar rcs logger/liblogger.a $(LOGGER_OBJ)

# Build server
linux_server:
	$(MAKE) -C $(SERVER_DIR)

# Build client
linux_client:
	$(MAKE) -C $(CLIENT_DIR)

# Compile logger library
$(LOGGER_OBJ): $(LOGGER_SRC) logger/logger.h
	$(CC) $(CFLAGS) -c $(LOGGER_SRC) -o $(LOGGER_OBJ)

# Compile example program
$(EXAMPLE_OBJ): $(EXAMPLE_SRC) logger/logger.h
	$(CC) $(CFLAGS) -c $(EXAMPLE_SRC) -o $(EXAMPLE_OBJ)

# Link example program
logger_example: $(EXAMPLE_OBJ) $(LOGGER_OBJ)
	$(CC) $(EXAMPLE_OBJ) $(LOGGER_OBJ) -o logger_example $(LDFLAGS)

# Clean build files
clean:
	rm -f *.o logger_example app.log
	rm -f logger/*.o
	$(MAKE) -C $(SERVER_DIR) clean
	$(MAKE) -C $(CLIENT_DIR) clean

# Run the example
run: logger_example
	./logger_example

# Install logger library (optional)
install: $(LOGGER_OBJ)
	ar rcs liblogger.a $(LOGGER_OBJ)
	cp logger.h /usr/local/include/
	cp liblogger.a /usr/local/lib/

# Uninstall
uninstall:
	rm -f /usr/local/include/logger.h /usr/local/lib/liblogger.a

.PHONY: all clean run install uninstall linux_server linux_client
