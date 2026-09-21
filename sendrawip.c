/* $Id: sendrawip.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"
#include "globals.h"

int send_rawip(void)
{
	int rc;
	char *packet;

	packet = malloc(cfg.data_size);
	if (packet == NULL) {
		perror("[send_rawip] malloc()");
		return -1;
	}
	memset(packet, 0, cfg.data_size);
	data_handler(packet, cfg.data_size);
	rc = send_ip_handler(packet, cfg.data_size);
	free(packet);
	return rc;
}
