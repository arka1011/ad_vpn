CC = gcc
CFLAGS = -O2 -Wall -Wextra -fPIC
LDFLAGS =
INCLUDES = -I../logger
SRC = tun_utils.c
OBJ = tun_utils.o
LIB_STATIC = libtun_utils.a
LIB_SHARED = libtun_utils.so
LOGGER_SRC = ../logger/logger.c
LOGGER_OBJ = ../logger/logger.o
LOGGER_INC = -I../logger
TARGET = tun_utils

all: $(LIB_STATIC) $(LIB_SHARED) $(TARGET)

$(OBJ): tun_utils.c tun_utils.h
	$(CC) $(CFLAGS) $(INCLUDES) -c tun_utils.c -o $(OBJ)

$(LIB_STATIC): $(OBJ)
	ar rcs $@ $^

$(LIB_SHARED): $(OBJ)
	$(CC) -shared -o $@ $^

$(LOGGER_OBJ): $(LOGGER_SRC)
	$(CC) $(CFLAGS) $(LOGGER_INC) -c $(LOGGER_SRC) -o $(LOGGER_OBJ)

$(TARGET): tun_utils.c tun_utils.h $(LOGGER_SRC) $(LOGGER_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ tun_utils.c $(LOGGER_SRC)

clean:
	rm -f $(TARGET) $(OBJ) $(LIB_STATIC) $(LIB_SHARED) $(LOGGER_OBJ)
