#include <stdio.h>
#include <string.h>

#include "cli.h"

void cli_print_usage(const char *program_name) {
    const char *name = program_name == NULL ? "PacketScope" : program_name;

    /* Keep usage text in one place so errors and --help stay consistent. */
    printf("Usage: %s [--help]\n", name);
}

int cli_parse_args(int argc, char **argv, AppConfig *config) {
    const char *program_name = argc > 0 ? argv[0] : "PacketScope";
    int i;

    (void)config;

    /* This skeleton only accepts --help until real options are implemented. */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            cli_print_usage(program_name);
            return 0;
        }

        cli_print_usage(program_name);
        return 1;
    }

    return 0;
}
