/* stub_send.c -- test double for send_ip_handler().
 *
 * The real sendip_handler.c hands packets to send_ip(), which writes to
 * the raw socket. The test-suite links this file instead: the last packet
 * built by send_tcp()/send_udp()/send_icmp()/... is copied into
 * stub_last_packet, the (possibly fake) monotonic time of every send is
 * recorded, and a failure can be simulated. Nothing leaves the host. */

#include <string.h>
#include "hping2.h"
#include "globals.h"
#include "stub_send.h"

unsigned char stub_last_packet[IP_MAX_SIZE];
unsigned int stub_last_size = 0;
unsigned int stub_send_calls = 0;
int stub_send_fail = 0; /* when set, every send reports an error */

/* the (monotonic, possibly fake) time of the last STUB_MAX_TIMES sends */
long long stub_send_us[STUB_MAX_TIMES];

/* destination port of the last STUB_MAX_TIMES TCP/UDP probes */
int stub_send_dport[STUB_MAX_TIMES];

int send_ip_handler(char *packet, unsigned int size)
{
	if (stub_send_calls < STUB_MAX_TIMES) {
		unsigned char *p = (unsigned char*) packet;
		stub_send_us[stub_send_calls] = hping_monotonic_us();
		stub_send_dport[stub_send_calls] = size >= 4 ? (p[2] << 8) | p[3] : -1;
	}
	stub_send_calls++;
	stub_last_size = size > IP_MAX_SIZE ? IP_MAX_SIZE : size;
	memcpy(stub_last_packet, packet, stub_last_size);
	return stub_send_fail ? -1 : 0;
}

void stub_send_reset(void)
{
	stub_send_calls = 0;
	stub_last_size = 0;
	stub_send_fail = 0;
	memset(stub_send_us, 0, sizeof(stub_send_us));
	memset(stub_send_dport, 0, sizeof(stub_send_dport));
}

/* how many of the recorded probes went to 'dport' */
int stub_probes_to(int dport)
{
	unsigned int i, n = 0;

	for (i = 0; i < stub_send_calls && i < STUB_MAX_TIMES; i++)
		n += stub_send_dport[i] == dport;
	return (int) n;
}
