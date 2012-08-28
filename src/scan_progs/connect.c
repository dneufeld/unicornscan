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
#include <scan_progs/packet_slice.h>
#include <settings.h>

#include <scan_progs/master.h>
#include <scan_progs/recv_packet.h>
#include <scan_progs/init_packet.h>
#include <scan_progs/packets.h>
#include <scan_progs/connect.h>
#include <scan_progs/portfunc.h>
#include <scan_progs/workunits.h>
#include <scan_progs/tcphash.h>
#include <unilib/drone.h>
#include <unilib/modules.h>
#include <unilib/qfifo.h>
#include <unilib/chtbl.h>
#include <unilib/rbtree.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/xipc.h>
#include <unilib/xpoll.h>
#include <unilib/pktutil.h>

/*
 * these are for the connection code, one is a "workunit" queue to send to the sender
 * the other is a tcp connection state table to base workunits from
 */

/* ripped from SCO OpenServer `fireball'
 *      TCP_ESTABLISHED         connection established
 *
 *      TCP_FIN_WAIT1           our side has shutdown, waiting to complete
 *                              transmission of remaining buffered data
 *
 *      TCP_FIN_WAIT2           all buffered data sent, waiting for remote
 *                              to shutdown
 *
 *      TCP_CLOSING             both sides have shutdown but we still have
 *                              data we have to finish sending
 *
 *      TCP_TIME_WAIT           timeout to catch resent junk before entering
 *                              closed, can only be entered from FIN_WAIT2
 *                              or CLOSING.  Required because the other end
 *                              may not have gotten our last ACK causing it
 *                              to retransmit the data packet (which we ignore)
 *
 *      TCP_CLOSE_WAIT          remote side has shutdown and is waiting for
 *                              us to finish writing our data and to shutdown
 *                              (we have to close() to move on to LAST_ACK)
 *
 *      TCP_LAST_ACK            out side has shutdown after remote has
 *                              shutdown.  There may still be data in our
 *                              buffer that we have to finish sending
 *
 *      TCP_CLOSE               socket is finished
*/
static void *state_tbl=NULL; /* rbtree, or chtbl */

static unsigned int a_conns=0;

typedef struct connection_status_t {
	int status;
#define U_TCP_ESTABLISHED	1
#define U_TCP_FIN_WAIT1		2
#define U_TCP_FIN_WAIT2		3
#define U_TCP_CLOSING		4
#define U_TCP_TIME_WAIT		5
#define U_TCP_CLOSE_WAIT	6
#define U_TCP_LAST_ACK		7
#define U_TCP_CLOSE		8
	int ack_pending;
	uint32_t window;
	uint16_t mss;
	uint32_t tseq;
	uint32_t mseq;
	uint32_t t_tstamp;
	uint32_t m_tstamp;
	uint32_t send_ip;

	size_t recv_stseq;
	size_t recv_len;
	uint8_t *recv_buf;

#define	OOSM	32
	struct {
		uint8_t *buf;
		size_t len;
		uint32_t sseq;
	} outoforder_segments_s[OOSM];

	size_t send_len;
	uint8_t *send_buf;
} connection_status_t;

static char *strconnstatus(int /* status */);

static uint64_t get_connectionkey(const ip_report_t *);
static size_t try_and_extract_tcp_data(const uint8_t * /* packet data */, size_t /* packet length */, connection_status_t * /* connection */);
static void send_connect(uint64_t /* state key */, connection_status_t *, void * /* pri_work */, const ip_report_t * /* report */);
static int kill_connection(uint64_t /* state key */, void * /* connection_status_t ptr */, void * /* callback data */);

void connect_init(void) {
	state_tbl=rbinit(111);
	return;
}

void connect_destroy(void) {
	rbdestroy(state_tbl);
}

void connect_grabbanners(ip_report_t *r) {
	union {
		void *ptr;
		connection_status_t *c;
	} c_u;
	uint64_t state_key=0;
	uint8_t *c_ptr=NULL;
	output_data_t *e_out=NULL;
	char pchars[256];
	size_t p_off=0, j=0;

	state_key=get_connectionkey(r);

	if (rbfind(state_tbl, state_key, &c_u.ptr) > 0) {

		memset(pchars, 0, sizeof(pchars));

		for (j=0, p_off=0, c_ptr=c_u.c->recv_buf; j < c_u.c->recv_len; j++, c_ptr++) {
			if (isgraph(*c_ptr) || *c_ptr == ' ') {
				pchars[p_off++]=(char )*c_ptr;
			}
			if (p_off > (sizeof(pchars) -2)) break;
		}

		if (p_off > 0) {
			e_out=(output_data_t *)xmalloc(sizeof(output_data_t));
			e_out->type=OD_TYPE_BANNER;
			e_out->t_u.banner=xstrdup(pchars);

			fifo_push(r->od_q, (void *)e_out);
		}
	}

	return;
}

static uint64_t get_connectionkey(const ip_report_t *r) {
	union {
		uint64_t state_key;
		struct {
			uint32_t dhost;
			uint16_t sport;
			uint16_t dport;
		} s;
	} k_u;

	assert(r != NULL);

	k_u.s.dhost=r->host_addr;
	k_u.s.dport=r->dport;
	k_u.s.sport=r->sport;

	return k_u.state_key;
}

void connect_do(void *pri_work, const ip_report_t *r) {
	char shost_s[32];
	union {
		void *ptr;
		send_pri_workunit_t *w;
		uint8_t *inc;
	} w_u;
	union {
		void *ptr;
		connection_status_t *c;
	} c_u;
	union {
		const uint8_t *packet;
		const ip_report_t *r;
		const uint16_t *len;
	} r_u;
	struct in_addr ia;
	uint64_t state_key=0;
	size_t dlen=0, pk_len=0;
	uint32_t dhost=0, shost=0;
	uint16_t sport=0, dport=0;

	if (r == NULL) {
		PANIC("r ptr NULL");
	}
	if (state_tbl == NULL) {
		PANIC("state table null");
	}
	if (pri_work == NULL) {
		PANIC("pri_work NULL");
	}

	if (r->magic != IP_REPORT_MAGIC) {
		ERR("wrong magic number for IP report");
		return;
	}

	state_key=get_connectionkey(r);

	dhost=r->host_addr;
	dport=r->sport;
	sport=r->dport;
	shost=r->send_addr;

	if (rbfind(state_tbl, state_key, &c_u.ptr) > 0) {
		DBG(M_CON, "connection with flags are %s status is %d", strtcpflgs(r->type), c_u.c->status);

		r_u.r=r;

		if (r_u.r->doff) {
			pk_len=r_u.r->doff;
			r_u.packet += sizeof(ip_report_t);
			if (*r_u.len != pk_len) {
				ERR("report is damaged?, packet seems broken");
				return;
			}
			else {
				r_u.len++;

				dlen=try_and_extract_tcp_data(r_u.packet, pk_len, c_u.c);
				if (dlen > 0) {
					c_u.c->tseq += dlen;
				}
			}
		}

		if (c_u.c->m_tstamp == 0 || c_u.c->t_tstamp == 0) {
			c_u.c->m_tstamp=0;
			c_u.c->t_tstamp=0;
		}
		else {
			c_u.c->m_tstamp++; /* XXX good enough for testing */
		}


		if (dlen < c_u.c->window) c_u.c->window -= dlen;

		if (r->type & TH_RST) {
			c_u.c->status=U_TCP_CLOSE;
			s->stats.stream_remote_abort++;
			a_conns--;
		}

		switch (c_u.c->status) {
			case U_TCP_ESTABLISHED:

				if (r->type & TH_PSH) {
					w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
					w_u.w->magic=PRI_4SEND_MAGIC;
					w_u.w->dhost=dhost;
					w_u.w->dport=dport;
					w_u.w->sport=sport;
					w_u.w->shost=c_u.c->send_ip;
					w_u.w->tseq=c_u.c->tseq;
					w_u.w->mseq=c_u.c->mseq;
					w_u.w->window_size=c_u.c->window;
					w_u.w->flags=TH_ACK|TH_FIN;
					w_u.w->doff=0;
					w_u.w->t_tstamp=c_u.c->t_tstamp;
					w_u.w->m_tstamp=c_u.c->m_tstamp;
					c_u.c->m_tstamp++;

					DBG(M_CON, "setting connection state into FIN_WAIT2 and sending ACK|FIN");

					c_u.c->status=U_TCP_FIN_WAIT2;

					fifo_push(pri_work, w_u.ptr);
					s->stats.stream_segments_sent++;
					c_u.c->mseq++;
					w_u.ptr=NULL;
				}
				else if (r->type & TH_FIN) {

					c_u.c->tseq += 1; /* FIN eats a seq ;] */

					w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
					w_u.w->magic=PRI_4SEND_MAGIC;
					w_u.w->dhost=dhost;
					w_u.w->dport=dport;
					w_u.w->sport=sport;
					w_u.w->shost=c_u.c->send_ip;
					w_u.w->tseq=c_u.c->tseq;
					w_u.w->mseq=c_u.c->mseq;
					w_u.w->window_size=c_u.c->window;
					w_u.w->flags=TH_ACK;
					w_u.w->doff=0;
					w_u.w->t_tstamp=c_u.c->t_tstamp;
					w_u.w->m_tstamp=c_u.c->m_tstamp;

					DBG(M_CON, "acking FIN");

					fifo_push(pri_work, w_u.ptr);
					s->stats.stream_segments_sent++;

					w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
					w_u.w->magic=PRI_4SEND_MAGIC;
					w_u.w->dhost=dhost;
					w_u.w->dport=dport;
					w_u.w->sport=sport;
					w_u.w->shost=c_u.c->send_ip;
					w_u.w->tseq=c_u.c->tseq;
					w_u.w->mseq=c_u.c->mseq;
					w_u.w->window_size=c_u.c->window;
					w_u.w->flags=TH_ACK|TH_FIN;
					w_u.w->doff=0;
					w_u.w->t_tstamp=c_u.c->t_tstamp;
					w_u.w->m_tstamp=c_u.c->m_tstamp;

					c_u.c->m_tstamp++;

					DBG(M_CON, "setting connection into state closed and sending ACK|FIN");
					fifo_push(pri_work, w_u.ptr);
					s->stats.stream_segments_sent++;

					c_u.c->status=U_TCP_CLOSE;

					fifo_push(pri_work, w_u.ptr);
					s->stats.stream_segments_sent++;
					w_u.ptr=NULL;
					c_u.c->mseq++;
					a_conns--;
				}
				break; /* U_TCP_ESTABLISHED: */

			case U_TCP_CLOSE:
				if (r->type == TH_ACK) {
					break;
				}

				DBG(M_CON, "reseting a packet type %s (no connection entry)", strtcpflgs(r->type));

				s->stats.stream_closed_alien_pkt++;

				w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
				w_u.w->magic=PRI_4SEND_MAGIC;
				w_u.w->dhost=dhost;
				w_u.w->dport=dport;
				w_u.w->sport=sport;
				w_u.w->shost=c_u.c->send_ip;
				w_u.w->tseq=c_u.c->tseq;
				w_u.w->mseq=c_u.c->mseq;
				w_u.w->window_size=c_u.c->window;
				w_u.w->flags=TH_RST;
				w_u.w->doff=0;
				w_u.w->t_tstamp=c_u.c->t_tstamp;
				w_u.w->m_tstamp=c_u.c->m_tstamp;
				c_u.c->m_tstamp++;

				DBG(M_CON, "reseting packed to closed connection");
				fifo_push(pri_work, w_u.ptr);
				s->stats.stream_segments_sent++;
				w_u.ptr=NULL;
				break; /* U_TCP_CLOSE */

			case U_TCP_FIN_WAIT2:

				if (r->type & TH_FIN) {
					/* ok its closed both ways, lets ack the fin and be done with it */

					c_u.c->tseq += 1;

					w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
					w_u.w->magic=PRI_4SEND_MAGIC;
					w_u.w->dhost=dhost;
					w_u.w->dport=dport;
					w_u.w->sport=sport;
					w_u.w->shost=c_u.c->send_ip;
					w_u.w->tseq=c_u.c->tseq;
					w_u.w->mseq=c_u.c->mseq;
					w_u.w->window_size=c_u.c->window;
					w_u.w->flags=TH_ACK;
					w_u.w->doff=0;
					w_u.w->t_tstamp=c_u.c->t_tstamp;
					w_u.w->m_tstamp=c_u.c->m_tstamp;
					c_u.c->m_tstamp++;

					c_u.c->status=U_TCP_CLOSE;

					fifo_push(pri_work, w_u.ptr);
					s->stats.stream_segments_sent++;
					w_u.ptr=NULL;
					DBG(M_CON, "Setting connection to closed and acking final fin");
				}
				break; /* U_TCP_FIN_WAIT2 */
# if 0
				if (r->type & (TH_ACK|TH_SYN)) {
				}
				break;
			case U_TCP_FIN_WAIT1:
			case U_TCP_FIN_WAIT2:
			case U_TCP_CLOSING:
			case U_TCP_TIME_WAIT:
			case U_TCP_CLOSE_WAIT:
			case U_TCP_LAST_ACK:
			case U_TCP_CLOSE:
# endif
			default:
				ERR("I have no code. I have no code");
				break;
		}

	} /* found in state table */
	else if ((r->type & (TH_ACK|TH_SYN)) == (TH_ACK|TH_SYN)) { /* should it be in state table */
		DBG(M_CON, "Connection with flags %s", strtcpflgs(r->type));

		/* yes this is a new connection */
		c_u.ptr=xmalloc(sizeof(connection_status_t));
		memset(c_u.ptr, 0, sizeof(connection_status_t));

		c_u.c->status=U_TCP_ESTABLISHED;

		c_u.c->send_ip=shost; /* Our IP */
		c_u.c->recv_len=0;
		c_u.c->send_len=0;
		c_u.c->send_buf=NULL;
		c_u.c->recv_buf=NULL;
		c_u.c->recv_stseq=0;
		c_u.c->tseq=r->tseq;
		c_u.c->mseq=r->mseq;
		c_u.c->window=r->window_size; /* XXX wscale */
		c_u.c->t_tstamp=r->t_tstamp;
		c_u.c->m_tstamp=r->m_tstamp;
		c_u.c->ack_pending=1;

		if (GET_IMMEDIATE()) {
			ia.s_addr=shost;
			snprintf(shost_s, sizeof(shost_s) -1, "%s", inet_ntoa(ia));
			ia.s_addr=dhost;
			VRB(0, "connected %s:%u -> %s:%u", shost_s, sport, inet_ntoa(ia), dport);
		}

		s->stats.stream_connections_est++;

		rbinsert(state_tbl, state_key, c_u.ptr);
		a_conns++;

		send_connect(state_key, c_u.c, pri_work, r);
	} /* looks like something we want to connect to ;] */
	else {
		s->stats.stream_completely_alien_packet++;
		DBG(M_CON, "ignoring packet with flags %s", strtcpflgs(r->type));
	}

	return;
}

static void send_connect(uint64_t state_key, connection_status_t *c, void *pri_work, const ip_report_t *r) {
	union {
		void *ptr;
		send_pri_workunit_t *w;
		uint8_t *inc;
	} w_u;
	union {
		uint64_t state_key;
		struct {
			uint32_t dhost;
			uint16_t sport;
			uint16_t dport;
		} s;
	} k_u;
	uint32_t pay_size=0;
	uint8_t *pay_ptr=NULL;
	int (*create_payload)(uint8_t **, uint32_t *, void *)=NULL;
	int32_t na=0;
	int dyn=0;

	k_u.state_key=state_key;

	c->tseq++;

	if (get_payload(0, IPPROTO_TCP, k_u.s.sport, &pay_ptr, &pay_size, &na, &create_payload, s->payload_group) == 1) {
		int err=0;

		/* payload trigger */
		DBG(M_CON, "pay size %u ptr %p conv %d create_payload %p", pay_size, pay_ptr, na, create_payload);

		if ((pay_size < 1 && pay_ptr == NULL) && create_payload == NULL) {
			ERR("pay size %u pay_ptr %p and create payload %p", pay_size, pay_ptr, create_payload);
			err++;
		}

		if (create_payload != NULL) {
			DBG(M_CON, "running create tcp payload at %p", create_payload);

			/* XXX */
			if (create_payload(&pay_ptr, &pay_size, (void *)r) < 0) {
				ERR("create payload for port %u fails", k_u.s.sport);
				err++;
			}
			dyn++;
		}

		if (pay_size > 1460) {
			ERR("payload too big");
			err++;
		}

		if (err == 0 && pay_size) {
			/* XXX if the payload is small use the 3-way handshake to send data */
			w_u.ptr=xmalloc(sizeof(send_pri_workunit_t) + pay_size);
			w_u.w->magic=PRI_4SEND_MAGIC;
			w_u.w->dhost=k_u.s.dhost;
			w_u.w->dport=k_u.s.sport;
			w_u.w->sport=k_u.s.dport;
			w_u.w->shost=c->send_ip;
			w_u.w->tseq=c->tseq;
			w_u.w->mseq=c->mseq;
			w_u.w->window_size=c->window;
			w_u.w->flags=TH_ACK;
			w_u.w->doff=0;
			w_u.w->t_tstamp=c->t_tstamp;
			w_u.w->m_tstamp=c->m_tstamp;
			memcpy(w_u.inc + sizeof(send_pri_workunit_t), pay_ptr, pay_size);

			s->stats.stream_segments_sent++;

			fifo_push(pri_work, w_u.ptr);
			w_u.ptr=xmalloc(sizeof(send_pri_workunit_t) + pay_size);
			w_u.w->magic=PRI_4SEND_MAGIC;
			w_u.w->dhost=k_u.s.dhost;
			w_u.w->dport=k_u.s.sport;
			w_u.w->sport=k_u.s.dport;
			w_u.w->shost=c->send_ip;
			w_u.w->tseq=c->tseq;
			w_u.w->mseq=c->mseq;
			w_u.w->window_size=c->window;
			w_u.w->flags=TH_ACK|TH_PSH;
			w_u.w->doff=pay_size;
			w_u.w->t_tstamp=c->t_tstamp;
			w_u.w->m_tstamp=c->m_tstamp;
			memcpy(w_u.inc + sizeof(send_pri_workunit_t), pay_ptr, pay_size);

			/* PSH is set, lets increment our seq */

			fifo_push(pri_work, w_u.ptr);

			c->ack_pending=0;

			s->stats.stream_segments_sent++;
			s->stats.stream_triggers_sent++;
			if (dyn) {
				s->stats.stream_dynamic_triggers_sent++;
			}

			c->mseq += pay_size;

			DBG(M_CON, "sending trigger to port %u", w_u.w->dport);

			w_u.ptr=NULL;
		}
		else { /* no payload so well just ack the connection */

			w_u.ptr=xmalloc(sizeof(send_pri_workunit_t) + pay_size);
			w_u.w->magic=PRI_4SEND_MAGIC;
			w_u.w->dhost=k_u.s.dhost;
			w_u.w->dport=k_u.s.sport;
			w_u.w->sport=k_u.s.dport;
			w_u.w->shost=c->send_ip;
			w_u.w->tseq=c->tseq;
			w_u.w->mseq=c->mseq;
			w_u.w->window_size=c->window;
			w_u.w->flags=TH_ACK;
			w_u.w->doff=0;
			w_u.w->t_tstamp=c->t_tstamp;
			w_u.w->m_tstamp=c->m_tstamp;
			memcpy(w_u.inc + sizeof(send_pri_workunit_t), pay_ptr, pay_size);
			fifo_push(pri_work, w_u.ptr);
			s->stats.stream_segments_sent++;
			c->ack_pending=0;

			DBG(M_CON, "sending trigger to port %u", w_u.w->dport);

			w_u.ptr=NULL;
		}
	} /* get_payload */
	else {
		w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
		w_u.w->magic=PRI_4SEND_MAGIC;
		w_u.w->dhost=k_u.s.dhost;
		w_u.w->dport=k_u.s.sport;
		w_u.w->sport=k_u.s.dport;
		w_u.w->shost=c->send_ip;
		w_u.w->tseq=c->tseq + 1; /* SYN incs */
		w_u.w->mseq=c->mseq;
		w_u.w->window_size=c->window;
		w_u.w->flags=TH_ACK;
		w_u.w->doff=0;
		w_u.w->t_tstamp=c->t_tstamp;
		w_u.w->m_tstamp=c->m_tstamp;
		c->m_tstamp++;

		fifo_push(pri_work, w_u.ptr);
		s->stats.stream_segments_sent++;
		c->ack_pending=0;

		w_u.ptr=NULL;
	}

	return;
}

void connect_wait(void *pri_work) {
	drone_t *d=NULL;
	xpoll_t spdf[8];
	unsigned int spdf_off=0;
	int pret=0, getret=0;
	uint8_t msg_type=0, status=0;
	size_t msg_len=0;
	uint8_t *ptr=NULL;
	time_t s_time=0, e_time=0;

	VRB(1, "waiting for connections to finish");

	if (s->dlh == NULL || s->dlh->head == NULL) {
		PANIC("waiting for connections with no drones?");
	}

	for (s_time=time(NULL);;) {
		int livesocks=0;

		for (d=s->dlh->head, spdf_off=0; d != NULL; d=d->next, spdf_off++) {
			if (d->s) livesocks++;
			spdf[spdf_off].fd=d->s;
		}

		DBG(M_CON, "polling %d sockets......", livesocks);

		if ((pret=xpoll(&spdf[0], s->dlh->size, 5000)) < 0) {
			ERR("poll drone fd's fail: %s", strerror(errno));
		}

		time(&e_time);

		if ((e_time - s_time) > s->ss->recv_timeout) {
			break;
		}

		for (d=s->dlh->head, spdf_off=0; d != NULL; d=d->next, spdf_off++) {
                        d->s_rw=0;
                        if (d->status != DRONE_STATUS_DEAD && d->status != DRONE_STATUS_DONE) {
                                d->s_rw=spdf[spdf_off].rw;
                        }
                        if (spdf[spdf_off].rw & XPOLL_READABLE) {
                                DBG(M_CON, "socket type %s is readable", strdronetype(d->type));
                        }
                }

		for (d=s->dlh->head; d != NULL; d=d->next) {
			DBG(M_CON, "drone type %s drone status %s", strdronetype(d->type), strdronestatus(d->status));
			if (d->type == DRONE_TYPE_LISTENER && (d->status == DRONE_STATUS_READY || d->status == DRONE_STATUS_WORKING)) {
				/* i just moved this here cause the line above was ugly */
				if ((d->s_rw & XPOLL_READABLE) == XPOLL_READABLE) {
					if (recv_messages(d->s) < 1) {
						ERR("cant recv_messages from ready listener");
						drone_updatestate(d, DRONE_STATUS_DEAD);
						continue;
					}

					while (1) {
						getret=get_message(d->s, &msg_type, &status, &ptr, &msg_len);
						if (getret < 1) {
							break;
						}
						if (msg_type == MSG_ERROR || status != MSG_STATUS_OK) {
							ERR("drone on fd %d is dead, closing socket and marking dead", d->s);
							drone_updatestate(d, DRONE_STATUS_DEAD);
							break;
						}
						else if (msg_type == MSG_OUTPUT) {
							deal_with_output(ptr, msg_len);
						}
						else {
							ERR("unhandled message from Listener drone message type `%s' with status %d", strmsgtype(msg_type), status);
						}
					}
				}
			}
			else if (d->type == DRONE_TYPE_SENDER && d->status == DRONE_STATUS_READY) {
				union {
					uint8_t *pw_ptr;
					void *ptr;
					send_pri_workunit_t *p;
				} pw_u;

				while ((pw_u.ptr=fifo_pop(pri_work)) != NULL) {

					DBG(M_CON, "sending pri work to sender in wait connections");
					if (send_message(
							d->s,
							MSG_WORKUNIT,
							MSG_STATUS_OK,
							pw_u.pw_ptr,
							sizeof(send_pri_workunit_t) + pw_u.p->doff
						) < 0) {
						ERR("cant send priority workunit to sender on fd %d, marking dead", d->s);
						drone_updatestate(d, DRONE_STATUS_DEAD);
						fifo_push(pri_work, pw_u.ptr);
						continue;
					}
					xfree(pw_u.ptr);
				}
			}

			if (s->senders == 0 || s->listeners == 0) {
				PANIC(s->senders == 0 ? "no senders" : "no listeners");
			}
		}

	}

	VRB(1, "connections timeout");
}

void connect_closeopen(void *pri_work) {

	rbwalk(state_tbl, kill_connection, 1, pri_work);

	if (a_conns) {
		VRB(1, "%u connections left hanging", a_conns);
	}

	VRB(2, "TCP STATS:\n"
		"\tConnect related TCP Segments sent: %d\n"
		"\tStream Reassembly aborted due to damaged tcp segment: %d\n"
		"\tStream death due to remote reset: %d\n"
		"\tTCP Segments to a Closed socket: %d\n"
		"\tTCP Segments out of window: %d\n"
		"\tTCP Segments with data truncated that went past window: %d\n"
		"\tTCP Seqments recieved out of order: %d\n"
		"\tConnections Established: %d\n"
		"\tTCP Triggers sent: %d\n"
		"\tTCP Dynamic Triggers sent: %d\n"
		"\tTCP segments to non-existant sockets: %d",
		s->stats.stream_segments_sent,
		s->stats.stream_reassembly_abort_badpkt,
		s->stats.stream_remote_abort,
		s->stats.stream_closed_alien_pkt,
		s->stats.stream_out_of_window_pkt,
		s->stats.stream_trunc_past_window,
		s->stats.stream_out_of_order_segment,
		s->stats.stream_connections_est,
		s->stats.stream_triggers_sent,
		s->stats.stream_dynamic_triggers_sent,
		s->stats.stream_completely_alien_packet
	);

	return;
}

static int kill_connection(uint64_t key, void *cptr, void *pri_work) {
	union {
		void *ptr;
		connection_status_t *c;
	} c_u;
	union {
		uint64_t state_key;
		struct {
			uint32_t dhost;
			uint16_t sport;
			uint16_t dport;
		} s;
	} k_u;
	union {
		void *ptr;
		send_pri_workunit_t *w;
		uint8_t *inc;
	} w_u;
	struct in_addr ia;
	char shost_s[32];

	if (cptr == NULL) {
		PANIC("state table has NULL entry");
	}
	if (pri_work == NULL) {
		PANIC("pri_work is NULL");
	}

	c_u.ptr=cptr;
	k_u.state_key=key;

	ia.s_addr=c_u.c->send_ip;
	snprintf(shost_s, sizeof(shost_s) -1, "%s", inet_ntoa(ia));
	ia.s_addr=k_u.s.dhost;

	if (c_u.c->status != U_TCP_CLOSE) {
		DBG(M_CON, "%s:%u -> %s:%u hanging in %s", shost_s, k_u.s.dport, inet_ntoa(ia), k_u.s.sport, strconnstatus(c_u.c->status));

		w_u.ptr=xmalloc(sizeof(send_pri_workunit_t));
		w_u.w->magic=PRI_4SEND_MAGIC;
		w_u.w->dhost=k_u.s.dhost;
		w_u.w->dport=k_u.s.dport;
		w_u.w->sport=k_u.s.sport;
		w_u.w->shost=c_u.c->send_ip;
		w_u.w->tseq=c_u.c->tseq + (c_u.c->window / 2);
		w_u.w->mseq=c_u.c->mseq;
		w_u.w->window_size=0;
		w_u.w->flags=TH_RST;
		w_u.w->doff=0;
		w_u.w->t_tstamp=c_u.c->t_tstamp;
		w_u.w->m_tstamp=c_u.c->m_tstamp + 1;

		fifo_push(pri_work, w_u.ptr);
		s->stats.stream_segments_sent++;
		w_u.ptr=NULL;
	}

	return 1;
}

static size_t try_and_extract_tcp_data(const uint8_t *packet, size_t pk_len, connection_status_t *c) {
	union {
		const struct mytcphdr *t;
		const struct myiphdr *i;
		const uint8_t *ptr;
	} p_u;
	packetlayers_t pls[8];
	const uint8_t *dptr=NULL;
	size_t sret=0, j=0, ret=0;
	uint32_t seq_max=0, seq_min=0;
	uint32_t sseq=0, eseq=0;

	sret=packet_slice(packet, pk_len, pls, 8, PKLTYPE_IP);

	for (j=0; j < sret; j++) {
		if (pls[j].stat != 0 && pls[j].stat != PKLSTAT_LAST) {
			ERR("bad packet, not extracting data");
			s->stats.stream_reassembly_abort_badpkt++;
			return 0;
		}

		if (pls[j].type == PKLTYPE_TCP) {
			p_u.ptr=pls[j].ptr;
			assert(pls[j].len == sizeof(struct mytcphdr)); /* shouldnt happen unless things are bad */
			sseq=ntohl(p_u.t->seq);

			seq_max=c->tseq + c->window;
			seq_min=c->tseq;

		}

		if (pls[j].type == PKLTYPE_PAYLOAD) {
			ret=pls[j].len;
			if (ret == 0) {
				return 0;
			}
			eseq=(uint32_t )ret + sseq;
			dptr=pls[j].ptr;
		}
	}

	if (! SEQ_WITHIN(sseq, seq_min, seq_max)) {
		s->stats.stream_out_of_window_pkt++;
		DBG(M_CON, "packet out of window with sequence %u:%u with min %u and max %u",
			sseq, eseq, seq_min, seq_max
		);
		return 0;
	}
	else {
		/*
		 * we know
		 *	a) the sseq is = or greater than our min
		 *	b) its less than our max
		 */
		DBG(M_CON, "packet in window with sequence %u:%u with min %u and max %u",
			sseq, eseq, seq_min, seq_max
		);

		if (eseq - sseq != ret) {
			/* XXX */
			DBG(M_CON, "eseq %u sseq %u and len " STFMT , eseq, sseq, ret);
			return 0;
		}

		if (eseq > seq_max) {
			ret=c->window;

			eseq=seq_max;

			s->stats.stream_trunc_past_window++;
			ERR("recieved segment that slips past our window!");
		}

		/*
		 * dptr = data pointer inside packet area (tcp payload)
		 */
		if (c->recv_len == 0) {
			c->recv_buf=(uint8_t *)xmalloc(ret + 1);
			memcpy(c->recv_buf, dptr, ret);
			c->recv_buf[ret]='\0';
			c->recv_len=ret;
			c->recv_stseq=sseq;
		}
		else {
			uint8_t *nbuf=NULL;
			size_t newsize=0;
			uint32_t lowseq=0, highseq=0;

			lowseq=MIN(c->recv_stseq, sseq);
			highseq=MAX(c->recv_stseq, eseq);

			DBG(M_CON, "new low seq is %u and high is %u", lowseq, highseq);

			assert(lowseq < highseq);
			assert((highseq - lowseq) < 0x3FFFF);

			newsize=(size_t)highseq - lowseq;
			nbuf=(uint8_t *)xmalloc(newsize + 1);
			memset(nbuf, 0, newsize);

			/* XXX FIXME */
			/* now copy the low data */
			if (sseq < c->recv_stseq) {
				uint32_t oldeseq=0;

				oldeseq=c->recv_stseq + c->recv_len;
				memcpy(nbuf, dptr, ret);
				memcpy((nbuf + newsize) - (oldeseq - c->recv_stseq), c->recv_buf, c->recv_len);
				xfree(c->recv_buf);
			}
			else {
				if (newsize < c->recv_len) {
					ERR("error, newsize is " STFMT " and recv_len is " STFMT ", dumping buffer!!", newsize, c->recv_len);
					newsize=c->recv_len;
					nbuf=c->recv_buf;
				}
				else {
					memcpy(nbuf, c->recv_buf, c->recv_len);
					//memcpy((nbuf + newsize) - (eseq - sseq), dptr, eseq - sseq);
					xfree(c->recv_buf);
				}
			}

			c->recv_buf=nbuf;
			c->recv_len=newsize;
		}
	}

	DBG(M_CON, "got " STFMT " bytes of data from packet", ret);

	return ret;
}

static char *strconnstatus(int cstat) {
	static char strstat[64];

	switch (cstat) {
		case U_TCP_ESTABLISHED:
			sprintf(strstat, "Established"); break;
		case U_TCP_FIN_WAIT1:
			sprintf(strstat, "Fin Wait1"); break;
		case U_TCP_FIN_WAIT2:
			sprintf(strstat, "Fin Wait2"); break;
		case U_TCP_CLOSING:
			sprintf(strstat, "Closing"); break;
		case U_TCP_TIME_WAIT:
			sprintf(strstat, "Time Wait"); break;
		case U_TCP_CLOSE_WAIT:
			sprintf(strstat, "Close Wait"); break;
		case U_TCP_LAST_ACK:
			sprintf(strstat, "Last Ack"); break;
		case U_TCP_CLOSE:
			sprintf(strstat, "Closed"); break;
		default:
			sprintf(strstat, "Unknown[%d]", cstat); break;
	}

	return strstat;
}
