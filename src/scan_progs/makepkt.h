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
#ifndef _MAKEPKT_H
# define _MAKEPKT_H

void makepkt_clear(void);
int makepkt_getbuf(size_t *, const uint8_t **);

int makepkt_build_udp(	uint16_t	/* local port           */,
			uint16_t	/* remote port          */,
			uint16_t	/* chksum               */,
			const uint8_t *	/* payload              */,
			size_t		/* payload size         */);

int makepkt_build_tcp(	uint16_t	/* local_port           */,
			uint16_t	/* remote port          */,
			uint16_t	/* chksum               */,
			uint32_t	/* seq                  */,
			uint32_t	/* ack seq              */,
			uint16_t	/* tcphdr flags         */,
			uint16_t	/* window_size          */,
			uint16_t	/* urgent pointer       */,
			const uint8_t *	/* tcpoptions           */,
			size_t		/* tcpoptions size      */,
			const uint8_t * /* payload              */,
			size_t		/* payload size         */);

int makepkt_build_ipv4(	uint8_t		/* TOS                  */,
			uint16_t	/* IPID			*/,
			uint16_t	/* frag			*/,
			uint8_t		/* TTL			*/,
			uint8_t		/* proto		*/,
			uint16_t	/* chksum		*/,
			uint32_t	/* source		*/,
			uint32_t	/* dest			*/,
			const uint8_t * /* ip options		*/,
			size_t		/* ip opt size		*/,
			const uint8_t *	/* payload		*/,
			size_t		/* payload size		*/);

int makepkt_build_arp(	uint16_t	/* hw format            */,
			uint16_t	/* proto format         */,
			uint8_t		/* hw addr len          */,
			uint8_t		/* proto len            */,
			uint16_t	/* opcode		*/,
			const uint8_t *	/* senders hw addr      */,
			const uint8_t * /* senders proto addr   */,
			const uint8_t * /* targets hw addr      */,
			const uint8_t * /* targets proto addr   */);

int makepkt_build_ethernet(uint8_t addrlen,
			const uint8_t * /* dest hwaddr          */,
			const uint8_t * /* src hwaddr           */,
			uint16_t type); 

#endif
