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

#include <netdb.h>

#include <settings.h>

#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/xpoll.h>
#include <unilib/drone.h>
#include <unilib/socktrans.h>

static int drone_validateuri(const char *);

int drone_parselist(const char *input) {
	char *ibuf=NULL, *tptr=NULL;

	if (input == NULL || strlen(input) < 1) {
		ERR("drone list null or 0 length, not parsing it");
		return -1;
	}

	ibuf=xstrdup(input);

	DBG(M_DRN, "parsing drone list `%s'", input);

	for (tptr=strtok(ibuf, ","); tptr != NULL; tptr=strtok(NULL, ",")) {
		DBG(M_DRN, "adding drone `%s'", tptr);
		/* transport context XXX */
		if (drone_validateuri(tptr) == 1) {
			if (drone_add(tptr) < 0) {
				ERR("drone `%s' cannot be added", tptr);
				return -1;
			}
		}
		else {
			ERR("drone `%s' is invalid", tptr);
		}
	}

	xfree(ibuf);
	return 1;
}

int drone_init(void) {
	assert(s->dlh == NULL);

	s->dlh=(drone_head_t *)xmalloc(sizeof(drone_head_t));

	s->dlh->head=NULL;
	s->dlh->size=0;

	return 1;
}

int drone_add(const char *uri) {
	drone_t *d=NULL,*l=NULL;

	if (s->dlh == NULL) {
		PANIC("drone head NULL");
	}

	d=(drone_t *)xmalloc(sizeof(drone_t));
	memset(d, 0, sizeof(drone_t));

	d->status=0;
	d->type=0;
	d->uri=xstrdup(uri);
	d->s=-1;
	d->s_rw=0;
	d->pps=0;
	d->id=0;

	d->next=NULL;
	d->last=NULL;

	/* XXX */
	if (GET_DOCONNECT()) {
		d->flags |= DRONE_IMMEDIATE;
	}

	if (s->dlh->head == NULL) {
		assert(s->dlh->size == 0);
		s->dlh->head=d;
		s->dlh->size=1;
		return 1;
	}

	for (l=s->dlh->head; l->next != NULL; ++d->id, l=l->next) {
	}
	++d->id;

	l->next=d;
	l->next->last=l;
	++s->dlh->size;

	return d->id;
}

int drone_remove(int drone_id) {
	drone_t *w=NULL;

	if (s->dlh == NULL) {
		return -1;
	}

	for (w=s->dlh->head; w != NULL; w=w->next) {
		if (w->id == drone_id) {

			if (w->uri != NULL) {
				xfree(w->uri);
			}

			if (w->last == NULL) {
				assert(w == s->dlh->head);
				s->dlh->head=w->next;
				if (w->next != NULL) {
					w->next->last=NULL;
				}
			}
			else if (w->next == NULL) {
				assert(w->last != NULL); /* cant be */
				w->last->next=NULL;
			}
			else {
				drone_t *l=NULL, *n=NULL;

				l=w->last;
				n=w->next;
				l->next=n;
				n->last=l;
			}

			xfree(w);
			--s->dlh->size;
			return 1;
		}
	}


	return -1;
}

int drone_connect(void) {
	drone_t *d=NULL;
	int dsock=-1, laggers=0;

	if (s->dlh == NULL) {
		return 0;
	}

	for (d=s->dlh->head; d != NULL; d=d->next) {
		if (d->status != DRONE_STATUS_UNKNOWN) {
			continue;
		}

		dsock=socktrans_connect(d->uri);

		if (dsock > 0) {
			d->s=dsock;
			d->s_rw=0;
			d->status=DRONE_STATUS_CONNECTED;
			if (d->flags & DRONE_IMMEDIATE) {
				DBG(M_DRN, "Setting up an immediate drone!");
				socktrans_immediate(d->s, 1);
			}
		}
		else {
			laggers++;
		}

	}

	return laggers;
}

void drone_dumplist(void) {
	drone_t *d=NULL;
	unsigned int node=0;

	if (s->dlh == NULL) {
		ERR("empty list, nothing to dump");
	}

	for (d=s->dlh->head; d != NULL; d=d->next) {
		DBG(M_DRN, "uri: `%s' id: %d", d->uri, d->id);
		node++;
	}

	if (node != s->dlh->size) {
		DBG(M_DRN, "mis-match for head size[%d] and counted size[%d]", s->dlh->size, node);
	}
	return;
}

void drone_destroylist(void) {
	drone_t *d=NULL, *l=NULL;

	if (s->dlh == NULL) {
		return;
	}

	for (d=s->dlh->head; d != NULL; l=d, d=d->next) {
		if (l != NULL) {
			xfree(l->uri);
			xfree(l);
		}
	}

	if (l != NULL) {
		xfree(l->uri);
		xfree(l);
	}

	xfree(s->dlh);
	s->dlh=NULL;

	return;
}

int drone_poll(int timeout) {
	int ret=0;
	uint32_t d_offset=0;
	xpoll_t p[MAX_CONNS];
	drone_t *d=NULL;

	if (s->dlh == NULL) {
		PANIC("drone head NULL");
	}

	for (d=s->dlh->head, d_offset=0; d != NULL; d=d->next, d_offset++) {
		if (d_offset > MAX_CONNS) {
			PANIC("too many drones bob");
		}
		p[d_offset].fd=d->s;
	}

	DBG(M_DRN, "polling %u sockets...", d_offset);

	if (xpoll(&p[0], d_offset, timeout) < 0) {
		return -1;
	}

	for (d=s->dlh->head, d_offset=0; d != NULL; d=d->next, d_offset++) {
		d->s_rw=0;

		if (d->status != DRONE_STATUS_DEAD && d->status != DRONE_STATUS_DONE) {
			d->s_rw=p[d_offset].rw;
			ret++;
		}
	}

	return ret;
}

void drone_updatestate(drone_t *d, int status) {
	assert(d != NULL);

	d->status=status;
	shutdown(d->s, SHUT_RDWR);
	close(d->s);
	d->s=-1;
	d->s_rw=0;

	switch (d->type) {
		case DRONE_TYPE_SENDER:
			--s->senders;
			break;

		case DRONE_TYPE_LISTENER:
			--s->listeners;
			break;

		default:
			break;
	}

}

static int drone_validateuri(const char *uri) {
	char host[256];
	uint16_t port=0;

	if (uri == NULL) {
		return -1;
	}

	if (sscanf(uri, "unix:%255[^/]", host) == 1) {
		return 1;
	}

	if (sscanf(uri, "%255[a-zA-Z0-9\\-_.]:%hu", host, &port) == 2) {
		DBG(M_DRN, "drone host `%s' port %hu is valid!", host, port);
		return 1;
	}

	return -1;
}

char *strdronetype(int type) {
	static char type_s[32];

	CLEAR(type_s);
	switch (type) {
		case DRONE_TYPE_UNKNOWN:
			strcat(type_s, "Unknown"); break;
		case DRONE_TYPE_SENDER:
			strcat(type_s, "Sender"); break;
		case DRONE_TYPE_LISTENER:
			strcat(type_s, "Listener"); break;
		case DRONE_TYPE_OUTPUT:
			strcat(type_s, "Output"); break;
		case DRONE_TYPE_SNODE:
			strcat(type_s, "SuperNode"); break;
		default:
			sprintf(type_s, "Unknown [%d]", type); break;
	}

	return type_s;
}

char *strdronestatus(int status) {
	static char stat_s[32];

	CLEAR(stat_s);
	switch (status) {
		case DRONE_STATUS_UNKNOWN:
			strcat(stat_s, "Unknown"); break;
		case DRONE_STATUS_CONNECTED:
			strcat(stat_s, "Connected"); break;
		case DRONE_STATUS_IDENT:
			strcat(stat_s, "Ident"); break;
		case DRONE_STATUS_READY:
			strcat(stat_s, "Ready"); break;
		case DRONE_STATUS_DEAD:
			strcat(stat_s, "Dead"); break;
		case DRONE_STATUS_WORKING:
			strcat(stat_s, "Working"); break;
		case DRONE_STATUS_DONE:
			strcat(stat_s, "Done"); break;
		default:
			sprintf(stat_s, "Unknown [%d]", status); break;

	}

	return stat_s;
}

char *strdroneopts(uint16_t flags) {
	static char opts_s[128];

	CLEAR(opts_s);
	snprintf(opts_s, sizeof(opts_s) -1, "%s", (flags & DRONE_IMMEDIATE ? "Immediate" : "Batch"));

	return opts_s;
}
