/* fuzz_opts.c -- libFuzzer target for the command line parser.
 *
 * Splits the input on nul bytes into an argv[] and runs parse_options()
 * with it. parse_options() must never crash, whatever the arguments, and
 * must not send anything (no socket is opened at parse time). Output is
 * redirected to /dev/null once.
 *
 * Build:  make fuzz
 * Run:    tests/fuzz_opts -max_len=256 corpusdir
 *
 * Copyright GPL v2. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "hping2.h"
#include "globals.h"

static int devnull = -1;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *buf, *argv[64];
	int argc = 1, saved_out, saved_err;
	size_t i, start = 0;

	if (size > 4096)
		return 0;
	buf = malloc(size + 1);
	if (buf == NULL)
		return 0;
	memcpy(buf, data, size);
	buf[size] = '\0';

	argv[0] = "styxwire";
	for (i = 0; i <= size && argc < 63; i++) {
		if (i == size || buf[i] == '\0') {
			if (i > start)
				argv[argc++] = buf + start;
			start = i + 1;
		}
	}
	argv[argc] = NULL;

	if (devnull == -1)
		devnull = open("/dev/null", O_WRONLY);
	saved_out = dup(1); saved_err = dup(2);
	if (devnull != -1) { dup2(devnull, 1); dup2(devnull, 2); }

	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);
	parse_options(argc, argv);
	hping_destroy();

	if (saved_out != -1) { dup2(saved_out, 1); close(saved_out); }
	if (saved_err != -1) { dup2(saved_err, 2); close(saved_err); }
	free(buf);
	return 0;
}
