/* $Id: cksum.c,v 1.3 2004/04/14 12:30:18 antirez Exp $  */

#include <string.h>
#include "hping2.h"	/* only for arch semi-indipendent data types */
#include "globals.h"

/*
 * from R. Stevens's Network Programming
 */
__u16 cksum(__u16 *buf, int nbytes)
{
	__u32 sum;

	sum = 0;
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		/* the last byte is the high byte of a word padded with zero */
		unsigned char pad[2];
		__u16 w;
		pad[0] = *((__u8*)buf);
		pad[1] = 0;
		memcpy(&w, pad, 2);
		sum += w;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	/* return a bad checksum with --badcksum option */
	if (cfg.opt_badcksum) sum ^= 0x5555;

	return (__u16) ~sum;
}
