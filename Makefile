CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -g -Iinclude
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