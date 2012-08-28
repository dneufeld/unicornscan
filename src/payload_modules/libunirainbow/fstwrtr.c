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
#include <settings.h>

#include <unilib/output.h>
#include <unilib/xmalloc.h>

#include "libunirainbow.h"

char *fstwrtr_32(uint32_t write_loc, uint32_t write_val, int dpa_off, int flags) {
	union {
		uint8_t chr[4];
		uint32_t w;
	} w_u;
	char *outz=NULL;
	int j=0, j1=0;

	outz=(char *)xmalloc(256);
	memset(outz, 0, 256);

	if (flags & FLG_VERB) {
		DBG(M_PYL, "write Location 0x%08x write value 0x%08x offset %d\n", write_loc, write_val, dpa_off);
	}

	w_u.w=write_loc;

	for (j=0 ; j < 4 ; j++) {
		unsigned int off=0;

		off=j * 4;

		w_u.w=write_loc + j;

		for (j1=0 ; j1 < 4 ; j1++) {
			outz[off + j1]=w_u.chr[j1];
		}
	}

	w_u.w=write_val;

        sprintf(outz + 16,	"%%%du%%%d$n" 
				"%%%du%%%d$n"
				"%%%du%%%d$n"
				"%%%du%%%d$n",
                  w_u.chr[3] -         16 + 256, dpa_off    ,
                  w_u.chr[2] - w_u.chr[3] + 256, dpa_off + 1,
                  w_u.chr[1] - w_u.chr[2] + 256, dpa_off + 2,
                  w_u.chr[0] - w_u.chr[1] + 256, dpa_off + 3
	);

	return outz;
}
