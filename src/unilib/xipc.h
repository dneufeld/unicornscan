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
#ifndef _IPC_H
# define _IPC_H

#define MSG_ERROR		0
#define MSG_VERSIONREQ		1
#define MSG_VERSIONREPL		2
#define MSG_QUIT		3
#define MSG_WORKUNIT		4
#define MSG_WORKDONE		5
#define MSG_OUTPUT		6
#define MSG_READY		7
#define MSG_ACK			8
#define MSG_IDENT		9
#define MSG_IDENTSENDER		10
#define MSG_IDENTLISTENER	11
#define MSG_NOP			12
#define MSG_TERMINATE		13

#define MSG_STATUS_OK		0
#define MSG_STATUS_ERROR	1
#define MSG_STATUS_UNKNOWN	2

int ipc_init(void);

int send_message(int /* socket */, int /* type */, int /* status */, const uint8_t * /* data */, size_t /* datalen */);
int recv_messages(int /* socket */);
int get_message(int /* socket */, uint8_t * /* type */, uint8_t * /* status */, uint8_t ** /* data */, size_t * /* msg len */);
int get_singlemessage(int /* socket */, uint8_t * /* type */, uint8_t * /* status */, uint8_t ** /* data */, size_t * /* msg len */);

char *strmsgtype(int );

#define IPC_TYPE_MASTER		0
#define IPC_TYPE_LISTENER	1
#define IPC_TYPE_SENDER		2
#define IPC_TYPE_DISPLAY	3

#define IPC_LOCAL 1
#define IPC_REMOTE 2

#endif
