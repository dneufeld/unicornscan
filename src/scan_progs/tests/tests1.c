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

#include <scan_progs/packet_slice.h>

#include "common.h"

int main(int argc, char ** argv) {
	char pktbuf[0x5ff];
	ssize_t rsize=0;
	size_t kittens=0;
	struct pcap_pkthdr ph;
	char *dup=NULL;
	int pfd=0, j=0;
	packetlayers_t plz[8];
	/* union {
		uint8_t *c;
		uint16_t hw;
		uint32_t w;
		uint64_t dw;
	} kitty; */

	startit();

	if (argc != 2) {
		fprintf(stderr, "thats not a banana, but i am!");
		exit(14);
	}
	if ((pfd=open(argv[1], O_RDONLY)) < 0) {
		terminate("cant eat `%s'", argv[1]);
	}

	if ((rsize=read(pfd, &pktbuf, sizeof(pktbuf))) < 0) {
		terminate("O brave new world, one with such errors in it");
	}

	SET_SNIFF(1);

	kittens=packet_slice(pktbuf, (size_t)rsize, &plz[0], 8, PKLTYPE_IP);

	for (j=0; j < 8; j++) {
		printf("type %s stat %s ptr %p len %u\n", strpklayer(plz[j].type), strpkstat(plz[j].stat), plz[j].ptr, plz[j].len);
		if (plz[j].len) hexdump(plz[j].ptr, plz[j].len);
	}

	exit(0);
}
