/* 
 * $smu-mark$ 
 * $name: memstr.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 4$ 
 */ 

/* $Id: memstr.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <string.h>
#include <stdlib.h> /* NULL macro */

/* Search the nul terminated string 'needle' inside the first 'size' bytes
 * of 'haystack' (which may contain nul bytes). Returns a pointer to the
 * first match, or NULL. An empty needle matches at the start. */
char *memstr(char *haystack, char *needle, int size)
{
	char *p;
	size_t needlesize = strlen(needle);
	size_t hsize;

	if (size < 0)
		return NULL;
	hsize = (size_t) size;
	if (needlesize > hsize)
		return NULL;

	for (p = haystack; (size_t)(p - haystack) <= hsize - needlesize; p++)
	{
		if (memcmp(p, needle, needlesize) == 0)
			return p; /* found */
	}
	return NULL;
}
