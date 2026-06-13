CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -g
INCLUDES = -Iinclude
LDLIBS = -lpcap
COVERAGE_CFLAGS = -Wall -Wextra -Werror -std=c11 -g -O0 -fprofile-instr-generate -fcoverage-mapping
COVERAGE_DIR ?= /tmp/packetscope-coverage
LLVM_PROFDATA ?= xcrun llvm-profdata
LLVM_COV ?= xcrun llvm-cov

TARGET = MiniSniffer

# Add normal project source files here.
SRC = src/main.c src/config.c src/cli.c src/common.c src/capture.c src/parser.c src/filter.c src/filters.c src/flow.c src/stream_buffer.c src/tcp_reassembly.c src/logger.c src/csv_logger.c src/output.c src/stats.c src/app_decoder.c src/app_http.c src/app_dns.c src/app_tls.c src/byte_reader.c

# Add test source files here.
TEST_SRC = tests/test_config.c tests/test_cli.c tests/test_common.c tests/test_capture.c tests/test_parser.c tests/test_filter.c tests/test_filters.c tests/test_flow.c tests/test_stream_buffer.c tests/test_tcp_reassembly.c tests/test_flow_app_decode.c tests/test_flow_filters.c tests/test_logger.c tests/test_csv_logger.c tests/test_output.c tests/test_stats.c tests/test_app_decoder.c tests/test_app_http.c tests/test_app_dns.c tests/test_app_tls.c tests/test_byte_reader.c

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

coverage:
	@set -e; \
	$(MAKE) clean; \
	$(MAKE) CFLAGS='$(COVERAGE_CFLAGS)' $(TARGET) $(TEST_TARGETS); \
	mkdir -p '$(COVERAGE_DIR)'; \
	rm -f '$(COVERAGE_DIR)'/*.profraw '$(COVERAGE_DIR)'/*.profdata \
		'$(COVERAGE_DIR)'/*.out '$(COVERAGE_DIR)'/coverage.txt \
		'$(COVERAGE_DIR)'/summary.json; \
	for test in $(TEST_TARGETS); do \
		LLVM_PROFILE_FILE='$(COVERAGE_DIR)'/$$test-%p.profraw ./$$test \
			>'$(COVERAGE_DIR)'/$$test.out 2>&1; \
	done; \
	LLVM_PROFILE_FILE='$(COVERAGE_DIR)'/main-help-%p.profraw ./$(TARGET) --help \
		>'$(COVERAGE_DIR)'/main-help.out 2>&1; \
	if LLVM_PROFILE_FILE='$(COVERAGE_DIR)'/main-invalid-%p.profraw ./$(TARGET) \
		--packetscope-invalid-option \
		>'$(COVERAGE_DIR)'/main-invalid.out 2>&1; then \
		echo "Coverage smoke test unexpectedly accepted an invalid option."; \
		exit 1; \
	fi; \
	if LLVM_PROFILE_FILE='$(COVERAGE_DIR)'/main-defaults-%p.profraw ./$(TARGET) \
		--interface packetscope-no-such-interface \
		>'$(COVERAGE_DIR)'/main-defaults.out 2>&1; then \
		echo "Coverage smoke test unexpectedly opened a missing interface."; \
		exit 1; \
	fi; \
	if LLVM_PROFILE_FILE='$(COVERAGE_DIR)'/main-options-%p.profraw ./$(TARGET) \
		--interface packetscope-no-such-interface --count 1 --protocol tcp \
		--port 80 --host 127.0.0.1 --payload --payload-bytes 64 \
		--payload-contains GET --payload-hex 474554 \
		--log '$(COVERAGE_DIR)'/packets.csv --decode-app --reassemble \
		--max-flows 10 --stream-buffer-bytes 1024 --flow-timeout 5 \
		--app http --http-host example.com --http-method GET \
		--dns-query example.com --dns-type A --tls-sni example.com \
		--tls-alpn h2 --stats \
		>'$(COVERAGE_DIR)'/main-options.out 2>&1; then \
		echo "Coverage smoke test unexpectedly opened a missing interface."; \
		exit 1; \
	fi; \
	$(LLVM_PROFDATA) merge -sparse '$(COVERAGE_DIR)'/*.profraw \
		-o '$(COVERAGE_DIR)'/coverage.profdata; \
	$(LLVM_COV) report ./$(TARGET) \
		$(foreach test,$(TEST_TARGETS),-object=./$(test)) \
		-instr-profile='$(COVERAGE_DIR)'/coverage.profdata \
		-ignore-filename-regex='tests/'; \
	$(LLVM_COV) show ./$(TARGET) \
		$(foreach test,$(TEST_TARGETS),-object=./$(test)) \
		-instr-profile='$(COVERAGE_DIR)'/coverage.profdata \
		-ignore-filename-regex='tests/' \
		-show-line-counts-or-regions -show-branches=count \
		>'$(COVERAGE_DIR)'/coverage.txt; \
	$(LLVM_COV) export ./$(TARGET) \
		$(foreach test,$(TEST_TARGETS),-object=./$(test)) \
		-instr-profile='$(COVERAGE_DIR)'/coverage.profdata \
		-ignore-filename-regex='tests/' -summary-only \
		>'$(COVERAGE_DIR)'/summary.json; \
	$(MAKE) clean

clean:
	rm -f $(OBJ) $(TEST_SUPPORT_OBJ) $(TEST_OBJ) $(TARGET) $(TEST_TARGETS)
	rm -rf *.dSYM tests/*.dSYM

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean coverage run test
