/* 
 * $smu-mark$ 
 * $name: main.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 8$ 
 */ 

/*
 * StyxWire: https://github.com/abdulhalimaltuntas/StyxWire
 * (continuation of hping3, originally at http://www.hping.org)
 * Covered by GPL version 2, Read the COPYING file for more information
 */

/* $Id: main.c,v 1.4 2004/06/18 09:53:11 antirez Exp $ */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "hping2.h"
#include "globals.h"

/* The command line entry point: parse, init, run, destroy.
 *
 * Exit status: what hping_run() returns (see hping_exit_code()), 1 on a
 * usage error or when initialisation fails, 0 after --help/--version. */
int main(int argc, char **argv)
{
	int rc;

	hping_config_init(&cfg);
	hping_context_init(&ctx);
	hping_stats_init(&stats);

	/* Check for the scripting mode */
	if (argc == 1 || (argc > 1 && !strcmp(argv[1], "exec"))) {
#ifdef USE_TCL
		if (argc != 1) {
			argv++;
			argc--;
		}
		hping_script(argc, argv);
		return 0; /* unreached */
#else
		fprintf(stderr, "Sorry, this styxwire binary was compiled "
				"without TCL scripting support\n");
		return 1;
#endif
	}

	rc = parse_options(argc, argv);
	if (rc == HPING_PARSE_ERROR)
		return 1;
	if (rc == HPING_PARSE_DONE)
		return 0;

	/* --apd-send: build and send the described packet, nothing else */
	if (cfg.apd_send != NULL) {
		rc = hping_ars_send(cfg.apd_send);
		hping_destroy();
		return rc == 0 ? 0 : 1;
	}

	if (hping_init() == -1) {
		hping_destroy();
		return 1;
	}
	rc = hping_run();
	hping_destroy();
	return rc;
}
