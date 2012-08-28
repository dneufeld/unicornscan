/**********************************************************************
 * Copyright (C) 2005-2006 (Jack Louis) <jack@rapturesecurity.org>    *
 *                                                                    *
 * This program is free software; you can redistribute it and/or      *
 * modify it under the terms of the GNU General Public License        *
 * as published by the Free Software Foundation; either               *
 * version 2 of the License, or (at your option) any later            *
 * version.                                                           *
 *                                                                    *
 * This program is distributed in the hope that it will be useful,    *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the      *
 * GNU General Public License for more details.                       *
 *                                                                    *
 * You should have received a copy of the GNU General Public License  *
 * along with this program; if not, write to the Free Software        *
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.          *
 **********************************************************************/
#include <config.h>
#include <unilib/output.h>

#include "libunirainbow.h"

/* XXX should be more like the junk ops in xor_encode */
static const char nopstr[]={
#if 0
0x27			, /* daa		*/
0x2f			, /* das		*/
0x37			, /* aaa		*/
0x3f			, /* aas		*/
#endif
0x40			, /* inc %eax		*/ 
0x41			, /* inc %ecx		*/
0x42			, /* inc %edx		*/
0x43			, /* inc %ebx		*/
0x44			, /* inc %esp		*/
0x45			, /* inc %ebp		*/
0x46			, /* inc %esi		*/
0x47			, /* inc %edi		*/
0x48			, /* dec %eax		*/
0x49			, /* dec %ecx		*/
0x4a			, /* dec %edx		*/
0x4b			, /* dec %ebx		*/
0x4c			, /* dec %esp		*/
0x4d			, /* dec %ebp		*/
0x4e			, /* dec %esi		*/
0x4f			, /* dec %edi		*/
0x50			, /* push %eax		*/
0x51			, /* push %ecx		*/
0x52			, /* push %edx		*/
0x53			, /* push %ebx		*/
0x54			, /* push %esp		*/
0x55			, /* push %ebp		*/
0x56			, /* push %esi		*/
0x57			, /* push %edi		*/
0x58			, /* pop %eax		*/
0x59			, /* pop %ecx		*/
0x5a			, /* pop %edx		*/
0x5b			, /* pop %ebx		*/
0x5d			, /* pop %ebp		*/
0x5e			, /* pop %edi		*/
0x5f			, /* pop %esi		*/
#if 0
0x60			, /* pusha		*/ 
0x61			, /* popa		*/
#endif
0x90			, /* nop		*/
0x91			, /* xchg %eax, %ecx	*/
0x92			, /* xchg %eax, %edx	*/
0x93			, /* xchg %eax, %ebx	*/
0x95			, /* xchg %eax, %ebp	*/
0x96			, /* xchg %eax, %esi	*/
0x97			, /* xchg %eax, %edi	*/
#if 0
0x98			, /* cwtl		*/
0x99			, /* cltd		*/
0x9b			, /* fwait		*/
0x9c			, /* pushf		*/
0x9e			, /* safh		*/
0x9f			, /* lahf		*/
0xd6			, /* salc		*/
0xf5			, /* cmc		*/
0xf8			, /* clc		*/
0xf9			, /* stc		*/
0xfc			, /* cld		*/
#endif
};
#define NOPS_SIZE	sizeof(nopstr)

int x86_rand_nops(char *buffer, size_t nop_size, const char *banned) {
	char *walk=NULL;
	size_t j=0;
	unsigned int idx=0;
	int watchdog=0;

	assert(buffer != NULL);

	for (j=0, walk=buffer ; j < nop_size ; j++, walk++) {
		for (watchdog=0 ; watchdog < 1000 ; watchdog++) {
			idx=(unsigned int)lr_rand_get(NOPS_SIZE);
			assert(idx < NOPS_SIZE);
			*walk=nopstr[idx];
			if (banned == NULL) {
				break;
			}
			if (strchr(banned, *walk) == NULL) break;
		}
		if (watchdog == 999) {
			ERR("rand nops failed, banned too restrictive?\n");
			return -1;
		}
	}

	return 1;
}
