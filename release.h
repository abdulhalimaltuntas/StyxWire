/* 
 * $smu-mark$ 
 * $name: release.h$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  16 11:55:49 MET 1999$ 
 * $rev: 17$ 
 */ 

#ifndef _RELEASE_H
#define _RELEASE_H

/* StyxWire is the continuation of hping3. The product name, the program
 * name (binary, diagnostics prefix) and its own version live here; the
 * hping3 release this tree descends from is kept for reference and is
 * what the --version output reports as the base. */
#define STYXWIRE_NAME		"StyxWire"
#define STYXWIRE_PROG		"styxwire"
#define STYXWIRE_VERSION	"0.3.0"

#define RELEASE_VERSION "3.0.0-alpha-1"	/* hping3 base version */
#define RELEASE_DATE "$Id: release.h,v 1.4 2004/04/09 23:38:56 antirez Exp $"
#define CONTACTS "<antirez@invece.org>"

#endif /* _RELEASE_H */
