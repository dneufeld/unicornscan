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
#include <unilib/cidr.h>

#define PACKET	"M-SEARCH * HTTP/1.1\r\n" \
		"HOST: %s:1900\r\n" \
		"MAN: \"ssdp:discover\"\r\n" \
		"MX: 1\r\n" \
		"ST: ssdp:all\r\n\r\n"

int create_payload(uint8_t **, uint32_t *, void *);
int init_module(mod_entry_t *);
static mod_entry_t *_m=NULL;
static const settings_t *s=NULL;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "UPnP unicast payload");

	m->iver=0x0103; /* 1.1 */
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.payload_group=1;
	m->param_u.payload_s.proto=IPPROTO_UDP;
	m->param_u.payload_s.sport=1900;
	m->param_u.payload_s.dport=1900;

	_m=m;
	s=_m->s;
	return 1;
}

void delete_module(void) {
	return;
}

int create_payload(uint8_t **data, uint32_t *dlen, void *ir) {
	char pack[1024];
	union sock_u s_u;

	s_u.s=ir;

	snprintf(pack, sizeof(pack) -1, PACKET, cidr_saddrstr(s_u.s));

	*dlen=strlen(pack);
	*data=(uint8_t *)xmalloc(*dlen);
	memcpy(*data, pack, *dlen);

	return 1;
}
