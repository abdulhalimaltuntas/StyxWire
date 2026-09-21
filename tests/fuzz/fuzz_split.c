/* fuzz_split.c -- libFuzzer target for the ARS packet splitter/serializer.
 *
 * Feeds arbitrary bytes to ars_split_packet() (binary -> layers) and then
 * ars_d_from_ars() (layers -> APD text): the receive/describe path that
 * historically over-read truncated and malformed packets. The first byte
 * chooses the hex/str data rendering, the rest is the packet.
 *
 * Build:  make fuzz          (clang, -fsanitize=fuzzer,address,undefined)
 * Run:    tests/fuzz_split -max_len=2048 corpusdir
 *
 * Deterministic, fast, no socket. Copyright GPL v2. */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "ars.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ars_packet p;
	char *d;
	int hexdata;

	if (size < 1)
		return 0;
	hexdata = data[0] & 1;
	data++; size--;

	ars_init(&p);
	if (hexdata)
		ars_set_option(&p, ARS_OPT_RAPD_HEXDATA);
	if (ars_split_packet((void*) data, size, 0, &p) == -ARS_OK) {
		d = malloc(65536*2+4096);
		if (d) {
			ars_d_from_ars(d, 65536*2+4096, &p);
			free(d);
		}
	}
	ars_destroy(&p);
	return 0;
}
