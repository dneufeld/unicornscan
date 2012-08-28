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
#include <config.h>

#include <scan_progs/chksum.h>

/*
 * Compute Internet Checksum for "count" bytes
 * beginning at location "addr".
 * adapted from rfc1071
 */
uint16_t do_ipchksum(const uint8_t *addr, size_t len) {
	union {
		const uint16_t *hw;
		const uint8_t *c;
	} a_u;
	int sum=0;
	uint16_t checksum=0;

	a_u.c=addr;

	while (len > 1) {
		sum += *a_u.hw; len -= 2; a_u.hw++;
	}

	if (len) {
		sum += htons(*a_u.c << 8);
	}

	sum=(sum & 0xffff) + (sum >> 16);
	sum += (sum >> 16);

	checksum=~(sum);

	return checksum;
}

uint16_t do_ipchksumv(const struct chksumv *array, int stlen) {
	union {
		const uint16_t *hw;
		const uint8_t *c;
	} a_u;
	int j=0, sum=0;
	size_t len=0;
	uint16_t checksum=0;

	if (stlen < 1) {
		return 0x0d1e; /* ;] */
	}

	for (j=0; j < stlen; j++) {
		len=array[j].len;
		a_u.c=array[j].ptr;

		while (len > 1) {
			sum += *a_u.hw; len -= 2; a_u.hw++;
		}

		if (len) {
			sum += htons(*a_u.c << 8);
		}
	}

	sum=(sum & 0xffff) + (sum >> 16);
	sum += (sum >> 16);

	checksum=~(sum);

	return checksum;
}
