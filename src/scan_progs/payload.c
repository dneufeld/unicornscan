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
#include <scan_progs/payload.h>
#include <settings.h>

int init_payloads(void) {

	s->plh=(payload_lh_t *)xmalloc(sizeof(payload_lh_t));
	memset(s->plh, 0, sizeof(payload_lh_t));

	return 1;
}

int add_default_payload(uint16_t proto, int32_t local_port, const uint8_t *payload, uint32_t payload_size, int (*create_payload)(uint8_t **, uint32_t *, void *), uint16_t payload_group) {
	payload_t *dpl=NULL;

	assert(s->plh != NULL);

	DBG(M_PYL, "setting up default payload");

	dpl=(payload_t *)xmalloc(sizeof(payload_t));
	memset(dpl, 0, sizeof(payload_t));

	dpl->proto=proto;
	dpl->port=0;
	dpl->local_port=local_port;
	if (payload_size > 0) {
		if (payload == NULL) {
			PANIC("NULL pointer to payload with size > 0");
		}
		dpl->payload=(uint8_t *)xmalloc(payload_size);
		memcpy(dpl->payload, payload, payload_size);
	}
	else {
		if (create_payload == (int (*)(uint8_t **, uint32_t *, void *))NULL) {
			PANIC("no static payload given, but no payload function present");
		}
		dpl->payload=NULL;
	}
	dpl->payload_size=payload_size;
	dpl->create_payload=create_payload;
	dpl->payload_group=payload_group;

	dpl->next=NULL;
	dpl->over=NULL;

	if (s->plh->def != NULL) {
		payload_t *walk=NULL;

		for (walk=s->plh->def; walk->over != NULL; walk=walk->over) {
			;
		}
		walk->over=dpl;
	}
	else {
		s->plh->def=dpl;
	}

	return 1;
}

int add_payload(uint16_t proto, uint16_t port, int32_t local_port, const uint8_t *payload, uint32_t payload_size, int (*create_payload)(uint8_t **, uint32_t *, void *), uint16_t payload_group) {
	payload_t *pnew=NULL;

	if (s->plh == NULL) {
		PANIC("add_payload called before init_payloads!");
	}

	DBG(M_PYL,
		"add payload for proto %s port %u local port %d payload %p "
		"payload size %u create_payload %p payload group %u",
		proto == IPPROTO_TCP ? "TCP" : "UDP",
		port,
		local_port,
		payload,
		payload_size,
		create_payload,
		payload_group
	);

	pnew=(payload_t *)xmalloc(sizeof(payload_t));
	memset(pnew, 0, sizeof(payload_t));

	pnew->proto=proto;
	pnew->port=port;
	pnew->local_port=local_port;

	if (payload_size > 0) {
		if (payload == NULL) {
			PANIC("NULL pointer to payload with size > 0");
		}
		pnew->payload=(uint8_t *)xmalloc(payload_size);
		memcpy(pnew->payload, payload, payload_size);
	}
	else {
		if (create_payload == (int (*)(uint8_t **, uint32_t *, void *))NULL) {
			PANIC("no static payload given, but no payload function present");
		}
		pnew->payload=NULL;
	}
	pnew->payload_size=payload_size;
	pnew->create_payload=create_payload;
	pnew->payload_group=payload_group;
	pnew->next=NULL;
	pnew->over=NULL;

	if (s->plh->top != NULL) {
		payload_t *current=NULL, *last=NULL;

		for (current=s->plh->top; current != NULL; last=current, current=current->next) {
			if (current->port == port && current->proto == proto && current->payload_group == payload_group) {
				DBG(M_PYL, "extra payload for port %u proto %u", port, proto);
				while (current->over != NULL) {
					DBG(M_PYL, "steping over on payload list");
					current=current->over;
				}
				current->over=pnew;
				pnew->over=NULL;

				return 1;
			}
		}

		DBG(M_PYL, "added payload for port %u proto %s payload group %d", port, (proto == IPPROTO_TCP ? "TCP" : "UDP"), pnew->payload_group);
		last->next=pnew;
		assert(s->plh->bottom == last);
		s->plh->bottom=pnew;
	}
	else {
		DBG(M_PYL, "added first node to payload list for port %u proto %u", port, proto);
		s->plh->bottom=pnew;
		s->plh->top=pnew;
	}

	return 1;
}

int get_payload(uint16_t indx, uint16_t proto, uint16_t port, uint8_t **data, uint32_t *payload_s, int32_t *local_port, int (**payload_init)(uint8_t **, uint32_t *, void *), uint16_t payload_group) {
	payload_t *current=NULL;

	DBG(M_PYL, "payload for port %u proto %u group %u searching starting at %p...", port, proto, payload_group, s->plh->top);

	for (current=s->plh->top; current != NULL; current=current->next) {

		DBG(M_PYL, "searching plg %d -> %d port %u -> %u proto %u -> %u", current->payload_group, payload_group, current->port, port, current->proto, proto);

		if (current->port == port && current->proto == proto && current->payload_group == payload_group) {
			if (indx == 0) {
				DBG(M_PYL, "found a payload with size %u local port %d create_payload %p payload group %u and data %p", current->payload_size, current->local_port, current->create_payload, current->payload_group, current->payload);
				*payload_s=current->payload_size;
				*local_port=current->local_port;
				*payload_init=current->create_payload;
				*data=current->payload;
				return 1;
			}
			else {
				uint16_t pos=0;

				while (current->over != NULL) {
					current=current->over;
					pos++;
					if (pos == indx) {
						DBG(M_PYL, "found a payload with size %u local port %d create_payload %p payload group %u and data %p", current->payload_size, current->local_port, current->create_payload, current->payload_group, current->payload);
						*payload_s=current->payload_size;
						*local_port=current->local_port;
						*payload_init=current->create_payload;
						*data=current->payload;
						return 1;
					}
				}
			}
		}
	}

	if (GET_DEFAULT() && s->plh->def != NULL) {

		current=s->plh->def;

		if (indx == 0) {
			if (current->proto == proto && current->payload_group == payload_group) {
				*payload_s=current->payload_size;
				*local_port=current->local_port;
				*payload_init=current->create_payload;
				*data=current->payload;
				DBG(M_PYL, "found a default payload with size %u local port %d create_payload %p payload group %u and data %p", current->payload_size, current->local_port, current->create_payload, current->payload_group, current->payload);
				return 1;
			}
		}
		else {
			uint16_t pos=0;

			while (current->over != NULL) {
				current=current->over;
				pos++;
				if (pos == indx) {
					DBG(M_PYL, "found a default payload with size %u local port %d create_payload %p payload group %u and data %p", current->payload_size, current->local_port, current->create_payload, current->payload_group, current->payload);
					*payload_s=current->payload_size;
					*local_port=current->local_port;
					*payload_init=current->create_payload;
					*data=current->payload;
					return 1;
				}
			}
		}
	}

	DBG(M_PYL, "no payload found for port %u proto %u index %d", port, proto, indx);

	return 0;
}
