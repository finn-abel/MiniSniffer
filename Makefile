CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -g
INCLUDES = -Iinclude
LDLIBS = -lpcap

TARGET = PacketScope

# Add normal project source files here.
SRC = src/main.c src/config.c src/cli.c src/common.c src/capture.c src/parser.c src/filter.c

# Add test source files here.
TEST_SRC = tests/test_config.c tests/test_cli.c tests/test_common.c tests/test_capture.c tests/test_parser.c tests/test_filter.c

OBJ = $(SRC:.c=.o)

# Source files needed for tests should not include src/main.c,
# because each test file has its own main function.
TEST_SUPPORT_SRC = $(filter-out src/main.c, $(SRC))
TEST_SUPPORT_OBJ = $(TEST_SUPPORT_SRC:.c=.o)

TEST_TARGETS = $(TEST_SRC:tests/%.c=%)
TEST_OBJ = $(TEST_SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%: tests/%.o $(TEST_SUPPORT_OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

test: $(TEST_TARGETS)
	@set -e; \
	for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		./$$test; \
		echo ""; \
	done; \
	$(MAKE) clean

clean:
	rm -f $(OBJ) $(TEST_SUPPORT_OBJ) $(TEST_OBJ) $(TARGET) $(TEST_TARGETS)
	rm -rf *.dSYM tests/*.dSYM

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run test
