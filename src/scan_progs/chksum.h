/**********************************************************************
 * Copyright (C) 2004-2006 (Jack Louis) <jack@rapturesecurity.org>    *
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
#ifndef _CHKSUM_H
# define CHKSUM_H

typedef struct _PACKED_ ip_pseudo_t {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
} ip_pseudo_t; /* precalculated ip pseudo header read inside the tcp|udp areas for checksumming */

uint16_t do_ipchksum(const uint8_t * /* ptr */, size_t /* count */);

/* this is to make the pseudo header chksum()ing less work, and to avoid copying memory */
struct chksumv {
	const uint8_t *ptr;
	size_t len;
};

uint16_t do_ipchksumv(const struct chksumv * /* chksum struct array */, int /* # of structs */);

#endif
