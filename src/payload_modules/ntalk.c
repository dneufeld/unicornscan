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

#include <settings.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/modules.h>

#include <scan_progs/scan_export.h>

typedef struct _PACKED_ ntalk_msg_t {
	uint8_t			vers;		/* version (1 default)		*/
	int8_t			type;		/* message type			*/
	uint16_t		pad;		/*				*/
	uint32_t		idnum;		/* server set ID number		*/
	struct sockaddr_in	dest;		/* IP mostly for dest		*/
	struct sockaddr_in	src;		/* IP+port of the local		*/
	uint32_t		pid;		/* callers PID			*/
	char			s_user[12];	/* caller's user name		*/
	char			d_user[12];	/* remote user			*/
	char			d_tty[16];	/* remote tty			*/
} ntalk_msg_t;

int create_payload(uint8_t **, uint32_t *, void *);
int init_module(mod_entry_t *);
void delete_module(void);
static mod_entry_t *_m=NULL;
static const settings_t *s=NULL;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "ntalk request");
	m->type=MI_TYPE_PAYLOAD;
	m->iver=0x0103;

	m->param_u.payload_s.sport=518;
	m->param_u.payload_s.dport=518;
	m->param_u.payload_s.proto=IPPROTO_UDP;
	m->param_u.payload_s.payload_group=1;
	_m=m;
	s=_m->s;
	return 1;
}

void delete_module(void) {
	return;
}

int create_payload(uint8_t **data, uint32_t *dlen, void *ir) {
	ntalk_msg_t *ret=NULL;
	union sock_u s_u, t_u;

	s_u.ss=&_m->s->vi[0]->myaddr;

	if (s_u.fs->family != AF_INET) {
		return NULL;
	}

	ret=(ntalk_msg_t *)xmalloc(sizeof(ntalk_msg_t));
	*dlen=sizeof(ntalk_msg_t);
	memset(ret, 0, *dlen);

	ret->vers=1;
	ret->type=1;
	ret->pad=0;
	ret->idnum=0; /* server fills this out */

	ret->pid=0x5590;

	ret->src.sin_port=htons(518);
	ret->src.sin_family=htons(AF_INET);
	ret->src.sin_addr.s_addr=s_u.sin->sin_addr.s_addr;

	ret->dest.sin_port=htons(518);
	ret->dest.sin_family=htons(AF_INET);
	/* XXX */
	ret->dest.sin_addr.s_addr=0;

	sprintf(ret->s_user, "%s", "root");
	sprintf(ret->d_user, "%s", "root");

	*data=(uint8_t *)ret;

	return 1;
}
