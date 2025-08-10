CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2 -fPIC
LDFLAGS = -lpthread

# Source files
LOGGER_SRC = logger.c
LOGGER_OBJ = logger.o
EXAMPLE_SRC = logger_example.c
EXAMPLE_OBJ = logger_example.o

# Targets
all: logger_example liblogger.a

# Static library
liblogger.a: $(LOGGER_OBJ)
	ar rcs liblogger.a $(LOGGER_OBJ)

# Shared library (optional)
liblogger.so: $(LOGGER_OBJ)
	$(CC) -shared -o liblogger.so $(LOGGER_OBJ) $(LDFLAGS)

# Compile logger
$(LOGGER_OBJ): $(LOGGER_SRC) logger.h
	$(CC) $(CFLAGS) -c $(LOGGER_SRC) -o $(LOGGER_OBJ)

# Compile example
$(EXAMPLE_OBJ): $(EXAMPLE_SRC) logger.h
	$(CC) $(CFLAGS) -c $(EXAMPLE_SRC) -o $(EXAMPLE_OBJ)

# Link example
logger_example: $(EXAMPLE_OBJ) $(LOGGER_OBJ)
	$(CC) $(EXAMPLE_OBJ) $(LOGGER_OBJ) -o logger_example $(LDFLAGS)

# Clean
clean:
	rm -f *.o *.a *.so logger_example app.log

# Install (requires sudo)
install: liblogger.a
	sudo cp logger.h /usr/local/include/
	sudo cp liblogger.a /usr/local/lib/
	sudo ldconfig

# Uninstall
uninstall:
	sudo rm -f /usr/local/include/logger.h /usr/local/lib/liblogger.a
	sudo ldconfig

.PHONY: all clean install uninstall
