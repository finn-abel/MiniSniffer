#include <assert.h>
#include <stdio.h>

#include "cli.h"
#include "config.h"

static void test_cli_parse_args_accepts_no_args(void) {
    AppConfig config;
    char *argv[] = {"PacketScope"};

    config_init_defaults(&config);

    assert(cli_parse_args(1, argv, &config) == 0);
}

static void test_cli_parse_args_accepts_help(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--help"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) == 0);
}

static void test_cli_parse_args_rejects_unknown_flag(void) {
    AppConfig config;
    char *argv[] = {"PacketScope", "--badflag"};

    config_init_defaults(&config);

    assert(cli_parse_args(2, argv, &config) != 0);
}

static void test_cli_print_usage_accepts_null_program_name(void) {
    cli_print_usage(NULL);
}

int main(void) {
    test_cli_parse_args_accepts_no_args();
    test_cli_parse_args_accepts_help();
    test_cli_parse_args_rejects_unknown_flag();
    test_cli_print_usage_accepts_null_program_name();

    printf("All cli tests passed.\n");

    return 0;
}
