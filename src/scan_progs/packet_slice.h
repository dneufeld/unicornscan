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
#ifndef _PACKETSLICE_H
# define _PACKETSLICE_H

typedef struct packetlayers_t {
	uint8_t type;
#define PKLTYPE_ETH		1
#define PKLTYPE_ARP		2
#define PKLTYPE_IP		3
#define PKLTYPE_IPO		4
#define PKLTYPE_UDP		5
#define PKLTYPE_TCP		6
#define PKLTYPE_TCPOP		7
#define PKLTYPE_ICMP		8
#define PKLTYPE_PAYLOAD		9
#define PKLTYPE_JUNK		10

	uint8_t stat;
#define PKLSTAT_DMGED		1
#define PKLSTAT_TRUNC		2
#define PKLSTAT_LAST		3
#define PKLSTAT_UNSUP		4

	const uint8_t *ptr;
	size_t len;
} packetlayers_t;

size_t packet_slice(const uint8_t * /* packet */, size_t /* of packet */,
		    packetlayers_t * /* already allocated */, size_t /* sizeof struct packetlayers */,
		    int /* layer start ie PKLTYPE_IP */);

char *strpklayer(int /* PKLTYPE_? */);
char *strpkstat(int /* stat */);
#endif
