CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Werror -g -Iinclude
LDFLAGS = -lpcap

TARGET = PacketScope

SRC = src/main.c
OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OBJ)
	rm -rf *.dSYM

.PHONY: all clean
