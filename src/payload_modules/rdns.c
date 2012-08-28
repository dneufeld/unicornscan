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

#include <unilib/prng.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/modules.h>

/* hey i did this with tcpdump cause im lazy */
typedef struct reverse_query_hdr {
	uint16_t x_id;		/* whatever		*/
	uint16_t flags;		/* 0x0000 or 0x0100	*/
	/*
	flags
	0x0000 -> no recursion
	0x0100 -> recursion
	*/
	uint16_t questions;
	uint16_t awns_rrs;
	uint16_t auth_rrs;
	uint16_t addit_rrs;
} rdns_hdr_t;

typedef struct reverse_question {
	/* query */
	/* char question[]; null terminated */
	uint16_t type; /* 0x000c */
	uint16_t qclass; /* 0x0001 */
} rdns_q_t;

int create_payload(uint8_t **, uint32_t *, void *);
int init_module(mod_entry_t *);
void delete_module(void);
static mod_entry_t *_m=NULL;
static const settings_t *s=NULL;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "rdns request");
	m->iver=0x0103;
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.sport=-1;
	m->param_u.payload_s.dport=53;
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
	rdns_hdr_t rhd;
	rdns_q_t rq;
	char question[32];
	uint8_t len1=0, len2=0, len3=0, len4=0, len5=7, len6=4;
	int len=0, plen=0;
	union {
		uint8_t ocs[4];
		uint32_t nfab;
	} k_u;
	union sock_u s_u;

	s_u.s=ir;

	if (s_u.fs->family != AF_INET) {
		*data=NULL;
		*dlen=0;
		return -1;
	}

	k_u.nfab=s_u.sin->sin_addr.s_addr;

	memset(&rhd, 0, sizeof(rhd)); memset(&rq, 0, sizeof(rq));

	rhd.x_id=(uint16_t)prng_get32() & 0xFFFF;
	rhd.flags=0x0000;	/* no recursion		*/
	rhd.questions=ntohs(1);	/* :P			*/
	rhd.awns_rrs=0;
	rhd.auth_rrs=0;
	rhd.addit_rrs=0;
	plen=sizeof(rhd);

	/* query */
	rq.type=ntohs(0x000c); /* 0x000c */
	rq.qclass=ntohs(0x0001); /* 0x0001 */

	if (k_u.ocs[3] < 10) { len1=1; } else if (k_u.ocs[3] < 100) { len1=2; } else { len1=3; }
	if (k_u.ocs[2] < 10) { len2=1; } else if (k_u.ocs[2] < 100) { len2=2; } else { len2=3; }
	if (k_u.ocs[1] < 10) { len3=1; } else if (k_u.ocs[1] < 100) { len3=2; } else { len3=3; }
	if (k_u.ocs[0] < 10) { len4=1; } else if (k_u.ocs[0] < 100) { len4=2; } else { len4=3; }
	len5=7; /* in-addr */ len6=4; /* arpa */

	len=snprintf(question, sizeof(question) - 1, "%c%d%c%d%c%d%c%d%cin-addr%carpa",
	len1, k_u.ocs[3], len2, k_u.ocs[2], len3,
	k_u.ocs[1], len4, k_u.ocs[0], len5, len6);

	plen += (len + 1 + 4); /* the 4 is the type and class in rq */

	*dlen=plen;

	*data=(uint8_t *)xmalloc(*dlen);
	memset(*data, 0, *dlen);
	memcpy(*data, &rhd, sizeof(rhd));
	memcpy((*data + sizeof(rhd)), question, (size_t )len + 1);
	memcpy((*data + sizeof(rhd) + (len + 1)), &rq.type, sizeof(rq.type));
	memcpy((*data + sizeof(rhd) + (len + 1) + sizeof(rq.type)), &rq.qclass, sizeof(rq.qclass));

	return 1;
}
