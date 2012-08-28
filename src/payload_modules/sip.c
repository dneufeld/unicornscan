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

/*
working! check sip.stanaphone.com
*/

#define PACKET	"OPTIONS sip:%s SIP/2.0\r\n" \
		"Via: SIP/2.0/UDP %s:5060\r\n" \
		"From: Bob <sip:%s:5060>\r\n" \
		"To: <sip:%s:5060>\r\n" \
		"Call-ID: 12312312@%s\r\n" \
		"CSeq: 1 OPTIONS\r\n" \
		"Max-Forwards: 70\r\n\r\n"

int create_payload(uint8_t **, uint32_t *, void *);
int init_module(mod_entry_t *);
static mod_entry_t *_m=NULL;
static const settings_t *s=NULL;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "SIP unicast payload");

	m->iver=0x0103; /* 1.1 */
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.payload_group=1;
	m->param_u.payload_s.proto=IPPROTO_UDP;
	m->param_u.payload_s.sport=5060;
	m->param_u.payload_s.dport=5060;

	_m=m;
	s=_m->s;
	return 1;
}

void delete_module(void) {
	return;
}

int create_payload(uint8_t **data, uint32_t *dlen, void *ir) {
	char pack[1024];
	char src_ip[64], dst_ip[64];
	union sock_u s_u;

	s_u.ss=&s->vi[0]->myaddr;
	snprintf(src_ip, sizeof(src_ip) -1, "%s", cidr_saddrstr(s_u.s));

	s_u.s=ir;
	snprintf(dst_ip, sizeof(dst_ip) -1, "%s", cidr_saddrstr(s_u.s));

	snprintf(pack, sizeof(pack) -1, PACKET, src_ip, dst_ip, dst_ip, dst_ip, dst_ip);

	*dlen=strlen(pack);
	*data=(uint8_t *)xstrdup(pack);

	return 1;
}
