/* fuzz_apd.c -- libFuzzer target for the APD parser (text -> packet).
 *
 * Feeds arbitrary nul-terminated text to ars_d_build() and, on success,
 * ars_compile(): the APD grammar and every ars_d_set_* field setter.
 *
 * Build:  make fuzz
 * Run:    tests/fuzz_apd -max_len=512 corpusdir
 *
 * Deterministic, fast, no socket. Copyright GPL v2. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ars.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ars_packet p;
	char *s = malloc(size + 1);

	if (s == NULL)
		return 0;
	memcpy(s, data, size);
	s[size] = '\0';

	ars_init(&p);
	if (ars_d_build(&p, s) == -ARS_OK)
		ars_compile(&p);
	ars_destroy(&p);
	free(s);
	return 0;
}
