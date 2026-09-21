/* Glue between hping and the ars engine */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ars.h"
#include "hping2.h"

/* --apd-send: build, compile and send the APD described packet.
 * Returns 0 when the packet was sent, -1 on error (message printed). */
int hping_ars_send(const char *apd)
{
	struct ars_packet p;
	char *copy;
	int s, rc = -1;

	ars_init(&p);
	copy = strdup(apd); /* ars_d_build() parses in place */
	if (copy == NULL) {
		fprintf(stderr, "APD error: out of memory\n");
		return -1;
	}
	s = ars_open_rawsocket(&p);
	if (s == -ARS_ERROR) {
		perror("Opening raw socket");
		free(copy);
		ars_destroy(&p);
		return -1;
	}
	if (ars_d_build(&p, copy) != -ARS_OK)
		fprintf(stderr, "APD error: %s\n", p.p_error);
	else if (ars_compile(&p) != -ARS_OK)
		fprintf(stderr, "APD error compiling: %s\n", p.p_error);
	else if (ars_send(s, &p, NULL, 0) != -ARS_OK)
		perror("Sending the packet");
	else
		rc = 0;
	close(s);
	free(copy);
	ars_destroy(&p);
	return rc;
}
