/* libars_link.c -- links against libars.a only.
 *
 * Proves that the ARS packet library is usable on its own: build a packet
 * from an APD description, split the bytes back and print the
 * description. No hping object is linked (tests/libars.sh). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ars.h"

int main(void)
{
	struct ars_packet p, q;
	unsigned char *pkt;
	size_t size;
	char apd[] = "ip(saddr=10.0.0.1,daddr=10.0.0.2,ttl=7)+udp(sport=53,dport=1024)+data(str=hi)";
	char d[1024];

	ars_init(&p);
	if (ars_d_build(&p, apd) != -ARS_OK || ars_compile(&p) != -ARS_OK ||
	    ars_build_packet(&p, &pkt, &size) != -ARS_OK) {
		fprintf(stderr, "build failed: %s\n", p.p_error ? p.p_error : "?");
		return 1;
	}
	ars_destroy(&p);
	ars_init(&q);
	if (ars_split_packet(pkt, size, 0, &q) != -ARS_OK ||
	    ars_d_from_ars(d, sizeof(d), &q) != -ARS_OK) {
		fprintf(stderr, "split failed\n");
		return 1;
	}
	ars_destroy(&q);
	free(pkt);
	printf("%s\n", d);
	return strstr(d, "+udp(sport=53,dport=1024,") != NULL &&
	       strstr(d, "+data(str=hi)") != NULL ? 0 : 1;
}
