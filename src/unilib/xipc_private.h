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
#ifndef _XIPC_PRIVATE_H
# define _XIPC_PRIVATE_H

#define MAX_SLACKSIZE		2048
#define IPC_MAGIC_HEADER	0xf0f1f2f3      /* to make endian mis-matches fault, as this is not mis-matched endian safe */
#define MAX_MSGS		(IPC_DSIZE / 8) /* close to maximum allowed */

typedef struct _PACKED_ ipc_msghdr_t {
	uint32_t header;
	uint8_t type;
	uint8_t status;
	size_t len;
} ipc_msghdr_t;

struct _PACKED_ message_s {
	ipc_msghdr_t hdr;
	uint8_t data[IPC_DSIZE - sizeof(ipc_msghdr_t)];
};

#endif
