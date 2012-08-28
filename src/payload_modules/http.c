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

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/modules.h>

int create_payload(uint8_t **, uint32_t *, void *);
int init_module(mod_entry_t *);
void delete_module(void);

static mod_entry_t *_m=NULL;
static const settings_t *s=NULL;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "http 1.1 request");
	m->iver=0x0103;
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.sport=-1;
	m->param_u.payload_s.dport=80;
	m->param_u.payload_s.proto=IPPROTO_TCP;
	m->param_u.payload_s.payload_group=1;

	_m=m;
	s=_m->s;
	return 1;
}

void delete_module(void) {
	return;
}

#define REQUEST "GET / HTTP/1.1\r\n" \
		"Host: %s\r\n" \
		"User-Agent: Mozilla/4.0 (compatible; http://www.dyadsecurity.com/s_bot.html)\r\n" \
		"Connection: Close\r\n\r\n"

int create_payload(uint8_t **data, uint32_t *dlen, void *i) {
	union {
		void *p;
		ip_report_t *ir;
	} i_u;
	char request[256];
	struct in_addr ia;

	i_u.p=i;

	assert(i != NULL && i_u.ir->magic == IP_REPORT_MAGIC);

	ia.s_addr=i_u.ir->host_addr;
	snprintf(request, sizeof(request) -1, REQUEST, inet_ntoa(ia));

	*dlen=(uint32_t)strlen(request);
	*data=(uint8_t *)xstrdup(request);

	return 1;
}
