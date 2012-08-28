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
#ifndef _DRONE_H
# define _DRONE_H

typedef struct drone_t {
	int status;
#define DRONE_STATUS_UNKNOWN	0
#define DRONE_STATUS_CONNECTED	1
#define DRONE_STATUS_IDENT	2
#define DRONE_STATUS_READY	3
#define DRONE_STATUS_DEAD	4
#define DRONE_STATUS_WORKING	5
#define DRONE_STATUS_DONE	6

	int type;
#define DRONE_TYPE_UNKNOWN	0
#define DRONE_TYPE_SENDER	1
#define DRONE_TYPE_LISTENER	2
#define DRONE_TYPE_OUTPUT	4
#define DRONE_TYPE_SNODE	8

	uint16_t flags;
#define DRONE_IMMEDIATE		1

	uint32_t pps;

	char *uri;

	int s;
	int s_rw;

	int id;

	uint32_t wid; /* workunit id last sent */

	struct drone_t *next;
	struct drone_t *last;
} drone_t;

typedef struct drone_head_s {
	drone_t *head;
	unsigned int size;
} drone_head_t;

/* these are ipc messages sent back from the drones */
typedef struct listener_info_t {
	struct sockaddr_storage myaddr;
	struct sockaddr_storage mymask;
	uint8_t hwaddr[THE_ONLY_SUPPORTED_HWADDR_LEN];
	uint16_t mtu;
} listener_info_t;

/*
 * when a sender finishes a workunit, it sends back this structure
 */
#define DRONE_STATS_MAGIC	0x4211dccd

typedef struct send_stats_t {
	uint32_t magic;
	float pps;
	uint64_t packets_sent;
} send_stats_t;

typedef struct recv_stats_t {
	uint32_t magic;
	uint32_t packets_recv;
	uint32_t packets_dropped;
	uint32_t interface_dropped;
} recv_stats_t;

typedef struct drone_version_t {
	uint32_t magic;
#define DRONE_MAGIC 0x533f000d
	uint8_t  maj;
	uint16_t min;
	uint8_t  res;
} drone_version_t;

int drone_init(void);

/*
 * takes a string of drones to use for a scan, and constructs the drone_head structure in the settings structure
 */
int drone_parselist(const char *);

/* droneid or -1 fail */ int drone_add(const char *);
int drone_remove(int /* doneid */);

void drone_dumplist(void);

void drone_destroylist(void);

/* returns number of drones that could not be connected to */
int drone_connect(void);

/* marks the drone as non-functional, cause of an error or normal termination */
void drone_updatestate(drone_t * /* drone */, int /* status, dead or done */);

/* returns the number of readable drone sockets */
int drone_poll(int /* timeout */);

char *strdronetype(int /* type */);
char *strdronestatus(int /* status */);
char *strdroneopts(uint16_t /* options */);

#endif
