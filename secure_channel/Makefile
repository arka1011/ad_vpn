# Compiler & Flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC
INCLUDES = -I. -I/usr/include
LIBS = -lcrypto -lpthread

# Source Files
SRC = src/secure_channel.c
OBJ = build/secure_channel.o

# Build directories
BUILD_DIR = ../build
BUILD_LIB = $(BUILD_DIR)/lib
BUILD_BIN = $(BUILD_DIR)/bin
BUILD_INCLUDE = $(BUILD_DIR)/include

# Local build directories
LOCAL_BUILD_LIB = build/lib
LOCAL_BUILD_BIN = build/bin
LOCAL_BUILD_INCLUDE = build/include

# Library names
STATIC_LIB = $(BUILD_LIB)/libsecure_channel.a
SHARED_LIB = $(BUILD_LIB)/libsecure_channel.so
LOCAL_STATIC_LIB = $(LOCAL_BUILD_LIB)/libsecure_channel.a
LOCAL_SHARED_LIB = $(LOCAL_BUILD_LIB)/libsecure_channel.so

# Default target
all: $(STATIC_LIB) $(SHARED_LIB) $(LOCAL_STATIC_LIB) $(LOCAL_SHARED_LIB)

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

# Build object files
$(OBJ): $(SRC) src/secure_channel.h | $(LOCAL_BUILD_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(SRC) -o $(OBJ)

# Static library (main build)
$(STATIC_LIB): $(OBJ) | $(BUILD_LIB)
	ar rcs $@ $(OBJ)

# Shared library (main build)
$(SHARED_LIB): $(OBJ) | $(BUILD_LIB)
	$(CC) -shared -o $@ $(OBJ) $(LIBS)

# Static library (local build)
$(LOCAL_STATIC_LIB): $(OBJ) | $(LOCAL_BUILD_LIB)
	ar rcs $@ $(OBJ)

# Shared library (local build)
$(LOCAL_SHARED_LIB): $(OBJ) | $(LOCAL_BUILD_LIB)
	$(CC) -shared -o $@ $(OBJ) $(LIBS)

# Clean
clean:
	rm -rf $(BUILD_DIR) build/ *.o

# Install (optional)
install: all
	cp $(STATIC_LIB) /usr/local/lib/
	cp $(SHARED_LIB) /usr/local/lib/
	cp src/secure_channel.h /usr/local/include/
	ldconfig

.PHONY: all clean install
