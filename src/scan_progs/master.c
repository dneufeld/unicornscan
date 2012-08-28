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

#include <errno.h>
#include <ctype.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>
#include <packageinfo.h>

#include <scan_progs/master.h>
#include <scan_progs/recv_packet.h>
#include <scan_progs/init_packet.h>
#include <scan_progs/packets.h>
#include <scan_progs/connect.h>
#include <scan_progs/portfunc.h>
#include <scan_progs/workunits.h>
#include <scan_progs/report.h>
#include <unilib/drone.h>
#include <unilib/qfifo.h>
#include <unilib/chtbl.h>
#include <unilib/rbtree.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/xipc.h>
#include <unilib/xpoll.h>
#include <unilib/terminate.h>
#include <unilib/socktrans.h>
#include <unilib/modules.h>

#define MASTER_START			0
#define MASTER_SENT_LISTEN_WORKUNITS	1
#define MASTER_SENT_SENDER_WORKUNITS	2
#define MASTER_WAIT_SENDER		3
#define MASTER_IN_TIMEOUT		4
#define MASTER_DONE			5
static int master_state=0;

static unsigned int send_workunits_complete=0, listen_workunits_complete=0;
static int listener_stats=0;

static void master_read_drones(void);
static void master_updatestate(int );
static int dispatch_work_units(void);
static int senders_done(void);
static void terminate_listeners(void);

static void master_updatestate(int state) {

	DBG(M_MST, "switching from state %d to %d", master_state, state);

	if (master_state != MASTER_DONE && (state - master_state) != 1) {
		PANIC("invalid state transition");
	}

	master_state=state;
	return;
}

void run_drone(void) {
	int lsock=-1, csock=-1;
	uint8_t msg_type=0, *tmpptr=NULL, status=0;
	size_t msg_len=0;
	union {
		drone_version_t *v;
		uint8_t *ptr;
	} d_u;
	union {
		listener_info_t *l;
		uint8_t *ptr;
	} l_u;
	drone_version_t dv;
	xpoll_t spdf[2];

	d_u.v=&dv;
	dv.maj=DRONE_MAJ;
	dv.min=DRONE_MIN;
	dv.magic=DRONE_MAGIC;

	if (GET_SENDDRONE()) {
		if (s->senders == 0) {
			ERR("im not going to make a good send drone relay without any senders, back to the drawing board");
			return;
		}
		if (s->senders != 1 && s->listeners != 0) {
			ERR("send drone unsupported configuration");
			return;
		}
	}
	else if (GET_LISTENDRONE()) {
		if (s->listeners == 0 && GET_LISTENDRONE()) {
			ERR("im not going to make a good listen drone relay without any listeners, back to the drawing board");
			return;
		}
		if (s->listeners != 1 && s->senders != 0) {
			ERR("listen drone unsupported configuration");
			return;
		}
	}
	else {
		ERR("not send nor listen drone?");
		return;
	}

	lsock=socktrans_bind(s->listen_addr);
	if (lsock < 0) {
		ERR("cant bind");
		return;
	}

	csock=socktrans_accept(lsock, 0);
	if (csock < 0) {
		ERR("cant accept");
		return;
	}

	DBG(M_MST, "got connection");

	if (get_singlemessage(csock, &msg_type, &status, &tmpptr, &msg_len) != 1) {
		ERR("unexpected message sequence from parent while looking for ident request, exiting");
		return;
	}

	if (msg_type != MSG_IDENT || status != MSG_STATUS_OK) {
		ERR("bad message from parent, wrong type `%s' or bad status %d, exiting", strmsgtype(msg_type), status);
		return;
	}

	if (send_message(csock, (GET_SENDDRONE() ? MSG_IDENTSENDER : MSG_IDENTLISTENER),
		MSG_STATUS_OK, d_u.ptr, sizeof(drone_version_t)) < 0) {
		ERR("cant send back msgident to parent");
		return;
	}

	if (get_singlemessage(csock, &msg_type, &status, &tmpptr, &msg_len) != 1) {
		ERR("unexpected message sequence from parent while looking for ident request, exiting");
		return;
	}

	if (msg_type != MSG_ACK || status != MSG_STATUS_OK) {
		ERR("bad message from parent, wrong type `%s' or bad status %d, exiting", strmsgtype(msg_type), status);
		return;
	}

	if (GET_SENDDRONE()) {
		if (send_message(csock, MSG_READY, MSG_STATUS_OK, NULL, 0) < 0) {
			ERR("cant send ready message to master");
			return;
		}
	}
	else {
		l_u.l=(listener_info_t *)xmalloc(sizeof(listener_info_t));
		memcpy(&l_u.l->myaddr, &s->vi[0]->myaddr, sizeof(struct sockaddr_storage));
		memcpy(&l_u.l->mymask, &s->vi[0]->mymask, sizeof(struct sockaddr_storage));
		memcpy(l_u.l->hwaddr, s->vi[0]->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
		l_u.l->mtu=s->vi[0]->mtu;

		if (send_message(csock, MSG_READY, MSG_STATUS_OK, l_u.ptr, sizeof(listener_info_t)) < 0) {
			ERR("cant send ready message to master");
			return;
		}
	}

	while (1) {
		drone_t *d=NULL;
		int j=0, getret=0;

		spdf[1].fd=csock;
		spdf[0].fd=-1;
		for (d=s->dlh->head; d != NULL; d=d->next) {
			if ((d->type == DRONE_TYPE_SENDER && GET_SENDDRONE()) ||
			(d->type == DRONE_TYPE_LISTENER && GET_LISTENDRONE())) {
				spdf[0].fd=d->s; break;
			}
		}

		assert(spdf[0].fd != -1 && spdf[1].fd != -1);

		if (xpoll(&spdf[0], 2, -1) < 0) {
			ERR("xpoll fails: %s", strerror(errno));
			continue;
		}

		for (j=0; j < 2; j++) {
			if (spdf[j].rw & XPOLL_DEAD) {
				ERR("socket %d is dead?: %s", spdf[j].rw, strerror(errno));
				return;
			}
			if (spdf[j].rw & XPOLL_READABLE) {
				if (recv_messages(spdf[j].fd) < 0) {
					ERR("cant recieve messages!");
					return;
				}
				while (1) {
					getret=get_message(spdf[j].fd, &msg_type, &status, &tmpptr, &msg_len);
					if (getret < 1) break;
					if (send_message(spdf[(j == 0 ? 1 : 0)].fd, msg_type, status, tmpptr, msg_len) < 0) {
						ERR("cant relay message");
						return;
					}
				}
			}
		}
	}

	return;
}

void run_scan(void) {
	int readable=0;
	time_t wait_stime=0;

	s->pri_work=fifo_init();

	assert(s->dlh->size <= MAX_CONNS);

	if (s->dlh->size < 1) {
		ERR("no drones to do work, exiting");
		return;
	}

	if (ISDBG(M_WRK)) {
		workunit_dump();
	}

	DBG(M_MST, "scan iteration %u of %u with %d senders and %d listeners", s->cur_iter, s->scan_iter, s->senders, s->listeners);

	for (master_state=MASTER_START; (s->senders + s->listeners) > 0 ;) {

		/* if we are not waiting for the senders to finish, we can dispatch work */
		if (master_state == MASTER_SENT_LISTEN_WORKUNITS || master_state == MASTER_START) {
			int w_sent=0;

			w_sent=dispatch_work_units();

			if (w_sent > 0 ) {
				DBG(M_WRK, "sent %d workunits", w_sent);
			}

			if (w_sent == 0 && master_state == MASTER_SENT_SENDER_WORKUNITS) {
				master_updatestate(MASTER_WAIT_SENDER);
			}
		}

		/* fill in the drone list with socket readable information */
		readable=drone_poll(s->master_tickrate);
		if (readable) {
			master_read_drones();
		}

		if (master_state == MASTER_WAIT_SENDER && senders_done()) {
			time(&wait_stime);
			master_updatestate(MASTER_IN_TIMEOUT);
		}

		if (master_state == MASTER_IN_TIMEOUT) {
			time_t tnow;

			time(&tnow);
			if ((tnow - wait_stime) > s->ss->recv_timeout) {
				if (GET_DOCONNECT()) {
					/* cant wait if we are connecting, in case a connection hasnt started yet */
					connect_closeopen(s->pri_work);
				}

				do {
					DBG(M_MST, "clearing pri work");
				} while (dispatch_pri_work());

				DBG(M_MST, "done, updatestate");

				master_updatestate(MASTER_DONE);
				break;
			}
		}

		/* pri work is created by reading so we do it here */
		if (s->senders > 0 && master_state > MASTER_SENT_SENDER_WORKUNITS) {
			dispatch_pri_work();
		}

	} /* walk from state START to SCAN DONE */

	fifo_destroy(s->pri_work);

	listener_stats=0;

	terminate_listeners();

	do {
		DBG(M_MST, "reading drones for listener statistics");
		readable=drone_poll(s->master_tickrate);
		if (readable > 0) {
			master_read_drones();
		}
	} while (s->listeners != listener_stats);

	return;
}

static void master_read_drones(void) {
	uint8_t msg_type=0, status=0;
	size_t msg_len=0;
	drone_t *c=NULL;
	union {
		uint8_t *p;
		send_stats_t *s;
		recv_stats_t *r;
	} d_u;

	for (c=s->dlh->head; c != NULL; c=c->next) {
		if (c->s > 0 && c->s_rw & XPOLL_READABLE) {
			int getret=0;

			DBG(M_MST,
				"reading file descriptor: %d type: `%s' status `%s' [ %d senders left | "
				"%d listeners left ]",
				c->s,
				strdronetype(c->type),
				strdronestatus(c->status),
				s->senders,
				s->listeners
			);

			if (recv_messages(c->s) < 1) {
				ERR("cant recieve messages from fd %d, marking as dead", c->s);
				drone_updatestate(c, DRONE_STATUS_DEAD);
				continue;
			}

			for (;c->s > 0;) {
				getret=get_message(c->s, &msg_type, &status, &d_u.p, &msg_len);
				if (getret < 1) {
					break;
				}
				DBG(M_IPC, "msg type %s status %u from drone type %s on fd %d",
					strmsgtype(msg_type),
					status,
					strdronetype(c->type),
					c->s
				);
				if (msg_type == MSG_ERROR || status != MSG_STATUS_OK) {
					ERR("drone on fd %d is dead, closing socket and marking dead", c->s);
					drone_updatestate(c, DRONE_STATUS_DEAD);
					break;
				}
				else if (msg_type == MSG_WORKDONE) {
					char smsg[1024];

					if (c->wid == 0) {
						PANIC("drone finished without having any work");
					}

					if (c->type == DRONE_TYPE_SENDER) {
						workunit_stats_t ws;

						workunit_destroy_sp(c->wid);

						if (msg_len != sizeof(send_stats_t)) {
							ERR("bad send status message, too short");
							drone_updatestate(c, DRONE_STATUS_DEAD);
							break;
						}

						snprintf(smsg, sizeof(smsg) -1,
							"%.1f pps with %llu packets sent total",
							d_u.s->pps,
							d_u.s->packets_sent
						);

						ws.magic=WKS_SEND_MAGIC;
						ws.wid=c->wid;
						ws.msg=xstrdup(smsg);
						push_output_modules(&ws);

						VRB(0, "sender statistics %s", smsg);

						send_workunits_complete++;
						DBG(M_MST, "setting sender back to ready state after workdone message");
						c->status=DRONE_STATUS_READY;
					}
					else if (c->type == DRONE_TYPE_LISTENER) {
						workunit_stats_t ws;

						workunit_destroy_lp(c->wid);

						if (msg_len != sizeof(recv_stats_t)) {
							ERR("bad recv status message, too short");
							drone_updatestate(c, DRONE_STATUS_DEAD);
							break;
						}

						snprintf(smsg, sizeof(smsg) -1,
							"%u packets recieved %u packets droped and %u interface drops",
							d_u.r->packets_recv,
							d_u.r->packets_dropped,
							d_u.r->interface_dropped
						);

						ws.magic=WKS_RECV_MAGIC;
						ws.wid=c->wid;
						ws.msg=xstrdup(smsg);
						push_output_modules(&ws);

						VRB(0, "listener statistics %s", smsg);

						listener_stats++;
						listen_workunits_complete++;
						DBG(M_MST, "setting listener back to ready state after workdone message");
						c->status=DRONE_STATUS_READY;
					}

					c->wid=0;
				}
				else if (msg_type == MSG_OUTPUT && c->type == DRONE_TYPE_LISTENER) {
					if (deal_with_output(d_u.p, msg_len) < 0) {
						ERR("cant deal with output from drone, marking as dead");
						drone_updatestate(c, DRONE_STATUS_DEAD);
						break;
					}
				}
				else {
					ERR("unhandled message from `%s' drone message type `%s' with status %d",
						strdronetype(c->type),
						strmsgtype(msg_type),
						status
					);
				}
				if (getret == 0) break;
			} /* multiple message read loop */
		} /* readable fd */
	} /* for each drone */

	return;
}

/*
 * used inside of connect too
 */
int deal_with_output(void *msg, size_t msg_len) {
	union {
		void *ptr;
		ip_report_t *i;
		arp_report_t *a;
		uint32_t *magic;
	} r_u;

	assert(msg != NULL);

	r_u.ptr=msg;

	if (*r_u.magic == IP_REPORT_MAGIC) {
		if (r_u.i->doff > s->vi[0]->mtu) {
			ERR("impossible packet length %u with mtu %u", r_u.i->doff, s->vi[0]->mtu);
			return -1;
		}

		if (msg_len < sizeof(ip_report_t) + r_u.i->doff) {
			ERR("IP report claims impossible length");
			return -1;
		}

		DBG(M_RPT, "IP report has a %u byte packet attached to it", r_u.i->doff);

		r_u.i->od_q=fifo_init();

		push_jit_report_modules(r_u.ptr);

		if (r_u.i->proto == IPPROTO_TCP && GET_DOCONNECT()) {
			connect_do(s->pri_work, (const ip_report_t *)r_u.i);
		}
	}
	else if (*r_u.magic == ARP_REPORT_MAGIC) {
		if (r_u.a->doff > s->vi[0]->mtu) {
			ERR("impossible packet length %u with mtu %u", r_u.a->doff, s->vi[0]->mtu);
			return -1;
		}

		if (msg_len < sizeof(arp_report_t) + r_u.a->doff) {
			ERR("ARP report claims impossible length");
			return -1;
		}

		DBG(M_RPT, "ARP report has a %u byte packet attached to it", r_u.i->doff);

		r_u.a->od_q=fifo_init();

		push_jit_report_modules(r_u.ptr);
	}
	else {
		ERR("unknown report format %04x", *r_u.magic);
		return -1;
	}

	if (report_add(r_u.ptr, msg_len) < 0) {
		ERR("unable to add report");
		return -1;
	}

	return 1;
}

static int senders_done(void) {
	int ret=0;


	ret=workunit_check_sp();

	DBG(M_MST, "workunits_check_sp = %d", ret);

	return ret;
}

static void terminate_listeners(void) {
	drone_t *c=NULL;
	uint8_t *ptr=NULL;

	for (c=s->dlh->head; c != NULL; c=c->next) {
		if (c->type == DRONE_TYPE_LISTENER && (c->status == DRONE_STATUS_READY || c->status == DRONE_STATUS_WORKING)) {
			if (send_message(c->s, MSG_TERMINATE, MSG_STATUS_OK, ptr, 0) < 0) {
				ERR("cant tell %s %s drone on fd %d to terminate, marking dead",
					strdronestatus(c->status),
					strdronetype(c->type),
					c->s
				);
				drone_updatestate(c, DRONE_STATUS_DEAD);
				workunit_reject_lp(c->wid);
				c->wid=0;
			}
		}
		DBG(M_MST, "drone %s is state %s", strdronetype(c->type), strdronestatus(c->status));
	}
}

int dispatch_pri_work(void) {
	union {
		void *ptr;
		uint8_t *cr;
		send_pri_workunit_t *w;
	} pw_u;
	uint32_t pri_len=0, wuc=0, rem=0;
	drone_t *c=NULL;

	pw_u.ptr=NULL;
	pri_len=fifo_length(s->pri_work);

	/*
	 * always empty regardless of int / leftovers, only works cause if NULL check in fifo_pop
	 */
	if ((rem=pri_len % s->senders)) {
		pri_len += (s->senders - rem);
	}

	for (c=s->dlh->head; c != NULL; c=c->next) {
		if (c->type == DRONE_TYPE_SENDER && (c->status == DRONE_STATUS_READY || c->status == DRONE_STATUS_WORKING)) {

			for (wuc=0; (pw_u.ptr=fifo_pop(s->pri_work)) != NULL && wuc < (pri_len / s->senders); wuc++) {
				if (send_message(c->s, MSG_WORKUNIT, MSG_STATUS_OK, pw_u.cr, (sizeof(send_pri_workunit_t) + pw_u.w->doff)) < 0) {
					ERR("cant send priority workunit to sender on fd %d, marking dead", c->s);
					drone_updatestate(c, DRONE_STATUS_DEAD);
				}
			}
		}
	}

	return wuc;
}

static int dispatch_work_units(void) {
	drone_t *c=NULL;
	union {
		uint8_t *cr;
		send_workunit_t *s;
		recv_workunit_t *l;
	} w_k;
	int sent=0;
	uint8_t msg_type=0, status=0, *ptr=NULL;
	size_t wk_len=0, msg_len=0;
	uint32_t wid=0;

	/* >= for clarity; we send listener workunits, then sender workunits, then we are done */
	if (master_state >= MASTER_SENT_SENDER_WORKUNITS) {
		DBG(M_MST, "no more work to dispatch");
		return 0;
	}

#if 0
	if (master_state == MASTER_START) {
		if (GET_RNDSRCIP() /* || XXX */) {
			master_updatestate(MASTER_SENT_LISTEN_WORKUNITS);
		}
	}
#endif

	for (c=s->dlh->head; c != NULL; c=c->next) {
		if (c->status != DRONE_STATUS_READY && c->status != DRONE_STATUS_WORKING /* so we can flag state changes */) {
			DBG(M_MST, "skipping %s drone with status %s", strdronetype(c->type), strdronestatus(c->status));
			continue;
		}
		if (c->wid != 0 && c->type == DRONE_TYPE_SENDER) {
			DBG(M_MST, "skipping working sender drone has wid %u outstanding", c->wid);
			continue;
		}


		if (master_state == MASTER_START && c->type == DRONE_TYPE_LISTENER) {
			static int lwu_mixed=0;

			DBG(M_MST, "sending listener workunits");

			w_k.cr=NULL;

			if (lwu_mixed == 0) {
				workunit_stir_lp();
				lwu_mixed++;
			}

			if ((w_k.l=workunit_get_lp(&wk_len, &wid)) != NULL) {
				if (wid == 0) {
					PANIC("got 0 wid");
				}
				DBG(M_MST, "got listener workunit of size " STFMT ", sending to listener", wk_len);

				if (send_message(c->s, MSG_WORKUNIT, MSG_STATUS_OK, w_k.cr, wk_len) < 0) {
					ERR("cant send workunit to listener on fd %d", c->s);
					workunit_reject_lp(wid);
					drone_updatestate(c, DRONE_STATUS_DEAD);
					continue;
				}

				if (get_singlemessage(c->s, &msg_type, &status, &ptr, &msg_len) != 1) {
					ERR("unexpected sequence of messages from listener on fd %d, marking dead", c->s);
					workunit_reject_lp(wid);
					drone_updatestate(c, DRONE_STATUS_DEAD);
					continue;
				}

				if (status != MSG_STATUS_OK) {
					ERR("bad status `%d' from listener on fd %d, marking as dead", status, c->s);
					workunit_reject_lp(wid);
					drone_updatestate(c, DRONE_STATUS_DEAD);
					continue;
				}

				if (msg_type != MSG_READY) {
					ERR("bad message `%s' from listener on fd %d, marking as dead", strmsgtype(msg_type), c->s);
					workunit_reject_lp(wid);
					drone_updatestate(c, DRONE_STATUS_DEAD);
					continue;
				}

				c->wid=wid;
				sent++;

				DBG(M_WRK, "sent workunit WID %u to listener on fd %d", wid, c->s);

				c->status=DRONE_STATUS_WORKING;

			} /* if we have a workunit for it */
			else {
				DBG(M_MST, "done sending listener workunits");
				master_updatestate(MASTER_SENT_LISTEN_WORKUNITS);
				workunit_stir_sp();
			}
		} /* if its a valid listener and we havent emptied the listener workunit pool */
		else if (master_state == MASTER_SENT_LISTEN_WORKUNITS && c->type == DRONE_TYPE_SENDER) {

			DBG(M_MST, "sending sender workunits");

			if ((w_k.s=workunit_get_sp(&wk_len, &wid)) != NULL) {
				DBG(M_WRK, "got sender workunit of size " STFMT ", sending to sender", wk_len);

				if (send_message(c->s, MSG_WORKUNIT, MSG_STATUS_OK, w_k.cr, wk_len) < 0) {
					ERR("cant Send Workunit to sender on fd %d", c->s);
					workunit_reject_sp(wid);
					drone_updatestate(c, DRONE_STATUS_DEAD);
					continue;
				}
				/* send workunits have no startup time or `ack' */

				c->wid=wid;
				sent++;

				DBG(M_WRK, "sent workunit WID %u to sender on fd %d", wid, c->s);

				c->status=DRONE_STATUS_WORKING;
			} /* if we have a workunit for it and we already sent workunits to the listeners but not yet senders */
			else {
				DBG(M_MST, "done sending sender workunits");
				master_updatestate(MASTER_SENT_SENDER_WORKUNITS);
			}
		} /* if we still have workunits to send to the senders */
	} /* for every drone */

	return sent;
}
