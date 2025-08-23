CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2 -fPIC
LDFLAGS = -lpthread

# Source files
LOGGER_SRC = src/logger.c
LOGGER_OBJ = build/logger.o
EXAMPLE_SRC = examples/logger_example.c
EXAMPLE_OBJ = build/logger_example.o

# Build directories
BUILD_DIR = ../build
BUILD_LIB = $(BUILD_DIR)/lib
BUILD_BIN = $(BUILD_DIR)/bin
BUILD_INCLUDE = $(BUILD_DIR)/include

# Local build directories
LOCAL_BUILD_LIB = build/lib
LOCAL_BUILD_BIN = build/bin
LOCAL_BUILD_INCLUDE = build/include

# Targets
all: $(BUILD_LIB)/liblogger.a $(BUILD_LIB)/liblogger.so $(BUILD_BIN)/logger_example $(LOCAL_BUILD_LIB)/liblogger.a $(LOCAL_BUILD_LIB)/liblogger.so $(LOCAL_BUILD_BIN)/logger_example
	$(MAKE) -C tests

# Create build directories
$(BUILD_LIB):
	mkdir -p $(BUILD_LIB)

$(BUILD_BIN):
	mkdir -p $(BUILD_BIN)

$(BUILD_INCLUDE):
	mkdir -p $(BUILD_INCLUDE)

$(LOCAL_BUILD_LIB):
	mkdir -p $(LOCAL_BUILD_LIB)

$(LOCAL_BUILD_BIN):
	mkdir -p $(LOCAL_BUILD_BIN)

$(LOCAL_BUILD_INCLUDE):
	mkdir -p $(LOCAL_BUILD_INCLUDE)

# Static library (main build)
$(BUILD_LIB)/liblogger.a: $(LOGGER_OBJ) | $(BUILD_LIB)
	ar rcs $@ $<

# Shared library (main build)
$(BUILD_LIB)/liblogger.so: $(LOGGER_OBJ) | $(BUILD_LIB)
	$(CC) -shared -o $@ $< $(LDFLAGS)

# Static library (local build)
$(LOCAL_BUILD_LIB)/liblogger.a: $(LOGGER_OBJ) | $(LOCAL_BUILD_LIB)
	ar rcs $@ $<

# Shared library (local build)
$(LOCAL_BUILD_LIB)/liblogger.so: $(LOGGER_OBJ) | $(LOCAL_BUILD_LIB)
	$(CC) -shared -o $@ $< $(LDFLAGS)

# Compile logger
$(LOGGER_OBJ): $(LOGGER_SRC) src/logger.h | $(LOCAL_BUILD_LIB)
	$(CC) $(CFLAGS) -c $(LOGGER_SRC) -o $(LOGGER_OBJ)

# Compile example
$(EXAMPLE_OBJ): $(EXAMPLE_SRC) src/logger.h | $(LOCAL_BUILD_BIN)
	$(CC) $(CFLAGS) -c $(EXAMPLE_SRC) -o $(EXAMPLE_OBJ)

# Link example (main build)
$(BUILD_BIN)/logger_example: $(EXAMPLE_OBJ) $(LOGGER_OBJ) | $(BUILD_BIN)
	$(CC) $(EXAMPLE_OBJ) $(LOGGER_OBJ) -o $@ $(LDFLAGS)

# Link example (local build)
$(LOCAL_BUILD_BIN)/logger_example: $(EXAMPLE_OBJ) $(LOGGER_OBJ) | $(LOCAL_BUILD_BIN)
	$(CC) $(EXAMPLE_OBJ) $(LOGGER_OBJ) -o $@ $(LDFLAGS)

# Clean - only remove logger-specific files
clean:
	rm -f *.o *.a *.so logger_example app.log
	rm -f $(LOGGER_OBJ) $(EXAMPLE_OBJ)
	rm -f $(BUILD_LIB)/liblogger.* $(BUILD_BIN)/logger_example
	rm -f $(LOCAL_BUILD_LIB)/liblogger.* $(LOCAL_BUILD_BIN)/logger_example
	rm -rf build/
	$(MAKE) -C tests clean

# Install (requires sudo)
install: $(BUILD_LIB)/liblogger.so
	install -d /usr/local/lib /usr/local/include
	install -m 755 $(BUILD_LIB)/liblogger.so /usr/local/lib/
	install -m 644 ./src/logger.h /usr/local/include/
	@echo "Running ldconfig to update shared library cache (requires root)..."
	@sudo ldconfig

# Uninstall
uninstall:
	rm -f /usr/local/lib/liblogger.so /usr/local/include/logger.h

.PHONY: all clean install uninstall
