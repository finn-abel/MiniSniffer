CC = gcc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man1
BASH_COMPLETION_DIR ?= $(PREFIX)/share/bash-completion/completions
ZSH_COMPLETION_DIR ?= $(PREFIX)/share/zsh/site-functions
FISH_COMPLETION_DIR ?= $(PREFIX)/share/fish/vendor_completions.d
PKG_CONFIG ?= pkg-config
CLANG_FORMAT ?= $(shell command -v clang-format 2>/dev/null || xcrun --find clang-format 2>/dev/null || true)
CFLAGS ?= -Wall -Wextra -Werror -std=c11 -g
PCAP_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpcap 2>/dev/null)
PCAP_LIBS := $(shell $(PKG_CONFIG) --libs libpcap 2>/dev/null)
ifeq ($(strip $(PCAP_LIBS)),)
PCAP_LIBS = -lpcap
endif
INCLUDES = -Iinclude $(PCAP_CFLAGS)
TEST_INCLUDES = $(INCLUDES) -Itests
BENCH_INCLUDES = $(INCLUDES) -Ibench
FUZZ_INCLUDES = $(INCLUDES) -Ifuzz
FUZZ_SANITIZE_CFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
FUZZ_CI_SECONDS ?= 20
LDLIBS ?= $(PCAP_LIBS)
ifeq ($(WITH_LIBIDN2),1)
CFLAGS += -DMINISNIFFER_WITH_LIBIDN2
LDLIBS += -lidn2
endif
COVERAGE_CFLAGS = -Wall -Wextra -Werror -std=c11 -g -O0 -fprofile-instr-generate -fcoverage-mapping
COVERAGE_DIR ?= /tmp/minisniffer-coverage
LLVM_PROFDATA ?= xcrun llvm-profdata
LLVM_COV ?= xcrun llvm-cov
SANITIZE_CFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer

TARGET = MiniSniffer

# Add normal project source files here.
SRC = src/main.c src/config.c src/cli.c src/common.c src/capture.c src/parser.c src/filter.c src/filters.c src/flow.c src/stream_buffer.c src/tcp_reassembly.c src/ipv4_frag.c src/logger.c src/csv_logger.c src/output.c src/stats.c src/app_decoder.c src/app_http.c src/app_dns.c src/app_tls.c src/app_dhcp.c src/app_quic.c src/byte_reader.c

# Add test source files here.
TEST_SRC = tests/test_config.c tests/test_cli.c tests/test_common.c tests/test_capture.c tests/test_offline_pcap.c tests/test_parser.c tests/test_filter.c tests/test_filters.c tests/test_flow.c tests/test_stream_buffer.c tests/test_tcp_reassembly.c tests/test_ipv4_frag.c tests/test_flow_app_decode.c tests/test_flow_filters.c tests/test_logger.c tests/test_csv_logger.c tests/test_output.c tests/test_stats.c tests/test_app_decoder.c tests/test_app_http.c tests/test_app_dns.c tests/test_app_tls.c tests/test_app_dhcp.c tests/test_app_quic.c tests/test_byte_reader.c

# Add lightweight benchmark source files here.
BENCH_SRC = bench/bench_parser.c bench/bench_app_decoder.c bench/bench_filters.c bench/bench_reassembly.c

# Add libFuzzer-compatible harness source files here. Each defines exactly one
# LLVMFuzzerTestOneInput and no main(); see fuzz/fuzz_standalone_main.c.
FUZZ_SRC = fuzz/fuzz_parser.c fuzz/fuzz_dns.c fuzz/fuzz_http.c fuzz/fuzz_tls.c fuzz/fuzz_app_dispatch.c fuzz/fuzz_reassembly.c fuzz/fuzz_pcap_offline.c
FUZZ_STANDALONE_MAIN_SRC = fuzz/fuzz_standalone_main.c
FUZZ_STANDALONE_MAIN_OBJ = $(FUZZ_STANDALONE_MAIN_SRC:.c=.o)

OBJ = $(SRC:.c=.o)

# Source files needed for tests should not include src/main.c,
# because each test file has its own main function.
TEST_SUPPORT_SRC = $(filter-out src/main.c, $(SRC))
TEST_SUPPORT_OBJ = $(TEST_SUPPORT_SRC:.c=.o)

TEST_TARGETS = $(TEST_SRC:tests/%.c=%)
TEST_OBJ = $(TEST_SRC:.c=.o)
BENCH_TARGETS = $(BENCH_SRC:bench/%.c=%)
BENCH_OBJ = $(BENCH_SRC:.c=.o)
FUZZ_TARGETS = $(FUZZ_SRC:fuzz/%.c=%)
FUZZ_SMOKE_TARGETS = $(addsuffix _smoke,$(FUZZ_TARGETS))
FUZZ_OBJ = $(FUZZ_SRC:.c=.o)
FORMAT_FILES = $(SRC) $(TEST_SRC) $(BENCH_SRC) $(FUZZ_SRC) $(FUZZ_STANDALONE_MAIN_SRC) $(wildcard include/*.h tests/*.h bench/*.h fuzz/*.h)
STATIC_FILES = $(SRC) $(TEST_SRC) $(BENCH_SRC) $(FUZZ_SRC) $(FUZZ_STANDALONE_MAIN_SRC)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) $(TEST_INCLUDES) -c $< -o $@

bench/%.o: bench/%.c
	$(CC) $(CFLAGS) $(BENCH_INCLUDES) -c $< -o $@

fuzz/%.o: fuzz/%.c
	$(CC) $(CFLAGS) $(FUZZ_INCLUDES) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%: tests/%.o $(TEST_SUPPORT_OBJ)
	$(CC) $(CFLAGS) $(TEST_INCLUDES) -o $@ $^ $(LDLIBS)

# Static pattern rule restricted to BENCH_TARGETS so it cannot be confused
# with the generic tests/%.o rule above for a target of the same name.
$(BENCH_TARGETS): %: bench/%.o $(TEST_SUPPORT_OBJ)
	$(CC) $(CFLAGS) $(BENCH_INCLUDES) -o $@ $^ $(LDLIBS)

# Real libFuzzer binaries: no custom main, since -fsanitize=fuzzer supplies
# its own via the linked runtime. Built by fuzz-build.
$(FUZZ_TARGETS): %: fuzz/%.o $(TEST_SUPPORT_OBJ)
	$(CC) $(CFLAGS) $(FUZZ_INCLUDES) -o $@ $^ $(LDLIBS)

# Standalone replay binaries: identical harness object, linked with our own
# main instead of a libFuzzer runtime. Built by fuzz-smoke.
$(FUZZ_SMOKE_TARGETS): %_smoke: fuzz/%.o $(FUZZ_STANDALONE_MAIN_OBJ) $(TEST_SUPPORT_OBJ)
	$(CC) $(CFLAGS) $(FUZZ_INCLUDES) -o $@ $^ $(LDLIBS)

test: $(TEST_TARGETS)
	@set -e; \
	for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		./$$test; \
		echo ""; \
	done; \
	$(MAKE) clean

bench: $(BENCH_TARGETS)
	@set -e; \
	for b in $(BENCH_TARGETS); do \
		echo "Running $$b..."; \
		./$$b; \
		echo ""; \
	done; \
	$(MAKE) clean

# Builds real libFuzzer binaries (fuzz_parser, fuzz_dns, ...) and leaves them
# in place for interactive fuzzing, e.g.:
#   ./fuzz_parser -max_total_time=300 fuzz/corpus/parser
# Skips gracefully, rather than failing the build, when $(CC) has no linked
# libFuzzer runtime (this is common outside Linux clang+llvm toolchains).
fuzz-build:
	@if printf 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){(void)d;(void)n;return 0;}\n' | \
	   $(CC) -x c -fsanitize=fuzzer -o /tmp/minisniffer_fuzzer_probe - >/dev/null 2>&1; then \
		rm -f /tmp/minisniffer_fuzzer_probe; \
		$(MAKE) $(FUZZ_TARGETS) CFLAGS='$(CFLAGS) -fsanitize=fuzzer,address,undefined'; \
	else \
		rm -f /tmp/minisniffer_fuzzer_probe; \
		echo "fuzz-build: skipped; $(CC) has no linked libFuzzer runtime for -fsanitize=fuzzer"; \
		echo "fuzz-build: install clang+llvm (Linux) or a full Xcode install (macOS) to enable it"; \
	fi

# Short, deterministic smoke check: replays every seed corpus file once
# through each harness under AddressSanitizer/UndefinedBehaviorSanitizer,
# using fuzz/fuzz_standalone_main.c instead of a real libFuzzer runtime, so
# this works even on toolchains fuzz-build has to skip.
fuzz-smoke:
	$(MAKE) $(FUZZ_SMOKE_TARGETS) CFLAGS='$(CFLAGS) $(FUZZ_SANITIZE_CFLAGS)'
	@set -e; \
	for target in $(FUZZ_TARGETS); do \
		corpus_dir="fuzz/corpus/$${target#fuzz_}"; \
		echo "Running $${target}_smoke over $$corpus_dir..."; \
		./$${target}_smoke "$$corpus_dir"/*; \
		echo ""; \
	done; \
	$(MAKE) clean

# Brief bounded real fuzzing run for CI: a few seconds per target against the
# seed corpus, using -fsanitize=fuzzer when fuzz-build succeeded, or a no-op
# skip message otherwise. Not a substitute for a long-running fuzzing setup.
fuzz-ci: fuzz-build
	@set -e; \
	for target in $(FUZZ_TARGETS); do \
		if [ -x ./$$target ]; then \
			echo "Fuzzing $$target for $(FUZZ_CI_SECONDS)s..."; \
			./$$target -max_total_time=$(FUZZ_CI_SECONDS) -max_len=4096 \
				fuzz/corpus/$${target#fuzz_}; \
		else \
			echo "Skipping $$target (not built; libFuzzer unsupported)"; \
		fi; \
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
		--minisniffer-invalid-option \
		>'$(COVERAGE_DIR)'/main-invalid.out 2>&1; then \
		echo "Coverage smoke test unexpectedly accepted an invalid option."; \
		exit 1; \
	fi; \
	if LLVM_PROFILE_FILE='$(COVERAGE_DIR)'/main-defaults-%p.profraw ./$(TARGET) \
		--interface minisniffer-no-such-interface \
		>'$(COVERAGE_DIR)'/main-defaults.out 2>&1; then \
		echo "Coverage smoke test unexpectedly opened a missing interface."; \
		exit 1; \
	fi; \
	if LLVM_PROFILE_FILE='$(COVERAGE_DIR)'/main-options-%p.profraw ./$(TARGET) \
		--interface minisniffer-no-such-interface --count 1 --protocol tcp \
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
	rm -f $(OBJ) $(TEST_SUPPORT_OBJ) $(TEST_OBJ) $(BENCH_OBJ) $(FUZZ_OBJ) $(FUZZ_STANDALONE_MAIN_OBJ) \
		$(TARGET) $(TEST_TARGETS) $(BENCH_TARGETS) $(FUZZ_TARGETS) $(FUZZ_SMOKE_TARGETS)
	rm -rf *.dSYM tests/*.dSYM bench/*.dSYM fuzz/*.dSYM

run: $(TARGET)
	./$(TARGET)

format:
	@test -n '$(CLANG_FORMAT)' || \
		{ echo "format: install clang-format or set CLANG_FORMAT=/path/to/clang-format"; exit 1; }
	$(CLANG_FORMAT) -i $(FORMAT_FILES)

format-check:
	@if test -n '$(CLANG_FORMAT)'; then \
		$(CLANG_FORMAT) --dry-run --Werror $(FORMAT_FILES); \
	else \
		echo "format-check: skipped; clang-format not found"; \
	fi

sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='$(CFLAGS) $(SANITIZE_CFLAGS)' test

static-check:
	@if command -v clang-tidy >/dev/null 2>&1; then \
		clang-tidy $(STATIC_FILES) -- $(CFLAGS) $(INCLUDES); \
	elif command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=warning,style,performance,portability --std=c11 \
			$(INCLUDES) src include tests; \
	else \
		echo "static-check: skipped; clang-tidy and cppcheck not found"; \
	fi

check: test sanitize format-check static-check

install: $(TARGET)
	install -d '$(DESTDIR)$(BINDIR)'
	install -m 0755 $(TARGET) '$(DESTDIR)$(BINDIR)/$(TARGET)'
	install -d '$(DESTDIR)$(MANDIR)'
	install -m 0644 man/minisniffer.1 '$(DESTDIR)$(MANDIR)/minisniffer.1'
	install -d '$(DESTDIR)$(BASH_COMPLETION_DIR)'
	install -m 0644 completions/minisniffer.bash '$(DESTDIR)$(BASH_COMPLETION_DIR)/minisniffer'
	install -d '$(DESTDIR)$(ZSH_COMPLETION_DIR)'
	install -m 0644 completions/_minisniffer '$(DESTDIR)$(ZSH_COMPLETION_DIR)/_minisniffer'
	install -d '$(DESTDIR)$(FISH_COMPLETION_DIR)'
	install -m 0644 completions/minisniffer.fish '$(DESTDIR)$(FISH_COMPLETION_DIR)/minisniffer.fish'

uninstall:
	rm -f '$(DESTDIR)$(BINDIR)/$(TARGET)'
	rm -f '$(DESTDIR)$(MANDIR)/minisniffer.1'
	rm -f '$(DESTDIR)$(BASH_COMPLETION_DIR)/minisniffer'
	rm -f '$(DESTDIR)$(ZSH_COMPLETION_DIR)/_minisniffer'
	rm -f '$(DESTDIR)$(FISH_COMPLETION_DIR)/minisniffer.fish'

.PHONY: all bench check clean coverage format format-check fuzz-build fuzz-ci fuzz-smoke install run sanitize static-check test uninstall
