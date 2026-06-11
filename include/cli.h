#ifndef CLI_H
#define CLI_H

#include "config.h"

/*
 * Parses command-line arguments into AppConfig.
 * Returns 0 when parsing succeeds or help was requested.
 * Returns non-zero when an unsupported option is provided.
 */
int cli_parse_args(int argc, char **argv, AppConfig *config);

/*
 * Prints supported MiniSniffer command-line usage.
 * program_name is shown in the usage examples.
 */
void cli_print_usage(const char *program_name);

#endif
