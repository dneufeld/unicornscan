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

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>

#include <unilib/terminate.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/qfifo.h>
#include <scan_progs/packet_parse.h>

#include "common.h"

const uint8_t *p=	"\x00\x00\x00\x00\x00\x00\x00\x00" /* fake link layer header */
			"\x45\x00\x00\x3c\x00\x00\x40\x00\x3f\x06\x4e\x67\xc0\xa8\x0d\xdd" /* 16 * 3 */
			"\x0a\x00\x14\xd0\x00\x19\x54\xa7\x12\xef\x5b\xb4\x9a\x18\xde\x82"
			"\xa0\x12\x16\xa0\x29\x1a\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a" /* 48 + 12 */
			"\x54\xd2\x78\xda\x15\x4b\xfb\xe9\x01\x03\x03\x07"; /* 12 */
#define PKLEN 68


int main(int argc, char ** argv) {
	struct pcap_pkthdr ph;
	char *pdup=NULL;
	int off=0, trick=0;
	/* union {
		uint8_t *c;
		uint16_t hw;
		uint32_t w;
		uint64_t dw;
	} kitty; */

	startit();

	SET_SNIFF(1);

	ph.caplen=PKLEN;

	hexdump(p, PKLEN);

#define TRICKLEN 16

	if (1) {
		if (TRICKLEN % 2) {
			PANIC("GO have some coffee and come back when you can think again buddy");
		}
	}

	for (off=0; off < PKLEN; off++) {
		/* 0 -> -1 -2 -3 -4 , +1 +2 +3 +4 XX */ 
		for (trick=0; trick < TRICKLEN; trick++) {
			pdup=xmalloc(PKLEN);
			memcpy(pdup, p, PKLEN);

			if (trick == 0) {
				pdup[off]=0x00;
			}
			else if (trick < (TRICKLEN / 2)) {
				printf("SUB %d\n", (5 - trick));
				pdup[off] -= (uint8_t)((TRICKLEN / 2) - trick);
			}
			else if (trick < TRICKLEN) {
				pdup[off] += (uint8_t)((TRICKLEN / 2) + trick);
			}
			else {
				pdup[off]=0xFF;
			}

			pdup[off]=0xFF;
			parse_packet(NULL, (const struct pcap_pkthdr *)&ph, pdup);

			xfree(pdup);
		}
	}

	exit(0);
}
