CC = gcc
CFLAGS = -O2 -Wall -Wextra -fPIC
INCLUDES = -I../logger
# Source files
SRC = src/tun_utils.c
OBJ = build/tun_utils.o

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
LIB_STATIC = $(BUILD_LIB)/libtun_utils.a
LIB_SHARED = $(BUILD_LIB)/libtun_utils.so
LOCAL_LIB_STATIC = $(LOCAL_BUILD_LIB)/libtun_utils.a
LOCAL_LIB_SHARED = $(LOCAL_BUILD_LIB)/libtun_utils.so

all: $(LIB_STATIC) $(LIB_SHARED) $(LOCAL_LIB_STATIC) $(LOCAL_LIB_SHARED)

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

$(OBJ): $(SRC) src/tun_utils.h | $(LOCAL_BUILD_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(SRC) -o $(OBJ)

$(LIB_STATIC): $(OBJ) | $(BUILD_LIB)
	ar rcs $@ $^

$(LIB_SHARED): $(OBJ) | $(BUILD_LIB)
	$(CC) -shared -o $@ $^

$(LOCAL_LIB_STATIC): $(OBJ) | $(LOCAL_BUILD_LIB)
	ar rcs $@ $^

$(LOCAL_LIB_SHARED): $(OBJ) | $(LOCAL_BUILD_LIB)
	$(CC) -shared -o $@ $^

clean:
	rm -f $(OBJ) $(LIB_STATIC) $(LIB_SHARED)
	rm -rf $(BUILD_DIR) build/

install: $(LIB_SHARED)
	install -d /usr/local/lib /usr/local/include
	install -m 755 $(LIB_SHARED) /usr/local/lib/
	install -m 644 tun_utils.h /usr/local/include/
	@echo "Running ldconfig to update shared library cache (requires root)..."
	@sudo ldconfig

uninstall:
	rm -f /usr/local/lib/libtun_utils.so /usr/local/include/tun_utils.h
