CC = gcc
CFLAGS = -O2 -Wall -Wextra
LDFLAGS =
INCLUDES = -I../logger
SRC = tun_utils.c ../logger/logger.c
TARGET = tun_utils

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
