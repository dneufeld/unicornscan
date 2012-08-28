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
#include <unilib/xmalloc.h>

#include "libunirainbow.h"

#define JMP	0xeb

int x86_jump_sled(char *buffer, size_t buffer_size, const char *banned) {
	char *tmpsled=NULL;
	size_t j=0;

	/* XXX dont be so lazy you bastard!	*/
	assert(buffer != NULL);
	assert(buffer_size > 1);

	tmpsled=(char *)xmalloc(buffer_size);
	memset(tmpsled, 0x41, buffer_size);

	if (strchr(banned, 0x41) != NULL || strchr(banned, JMP) != NULL || strchr(banned, 0x04) != NULL) {
		ERR("cant make a jump sled with those characters banned!\n");
		return -1;
	}

	for (j=0 ; j < (buffer_size - 8); j++) {
		tmpsled[j]=JMP;
		tmpsled[++j]=0x04;	/* also add %eax, 0x???????? so we'll end up ok after we hit this */
	}

	/* here, have some popa's */
	memset(tmpsled + (buffer_size - 8), 0x61,	8);

	memcpy(buffer, tmpsled, buffer_size);
	free(tmpsled);

	return 1;
}
