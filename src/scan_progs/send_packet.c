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
#include <dnet.h>

#include <scan_progs/send_packet.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>
#include <packageinfo.h>

#include <scan_progs/packets.h>

#ifdef __linux__
#include <sys/resource.h>
#endif

#define MIN_LOCALPORT 4096

#include <unilib/terminate.h>
#include <unilib/xmalloc.h>
#include <unilib/prng.h>
#include <unilib/xpoll.h>
#include <unilib/xipc.h>
#include <unilib/output.h>
#include <unilib/xdelay.h>
#include <unilib/modules.h>
#include <unilib/pktutil.h>
#include <unilib/socktrans.h>
#include <unilib/cidr.h>
#include <scan_progs/payload.h>
#include <scan_progs/portfunc.h>
#include <scan_progs/workunits.h>
#include <scan_progs/init_packet.h>
#include <scan_progs/makepkt.h>
#include <scan_progs/tcphash.h>
#include <scan_progs/entry.h>
#include <parse/parse.h>

#define CTVOID 1
#define CTPAYL 2

typedef struct fl_t {
	void (*init)(void);
	uint8_t c_t;
	union {
		int (*cmp)(void);
		int (*gpl)(uint16_t /* dport */, uint8_t ** /* data */, uint32_t * /* dsize */, int32_t * /* local_port */, int (** /*create payload */)(uint8_t **, uint32_t *, void *), uint16_t /* payload group */);
	} c_u;
	void (*inc)(void);
	struct fl_t *next;
} fl_t;
static fl_t *flhead=NULL;

static int add_loop_logic(const fl_t * /* new loop logic to add, added to end */);
static void destroy_loop_logic(void);
static void _send_packet(void);
static void loop_list(fl_t * /* start of loop logic list */);
static void priority_send_packet(const send_pri_workunit_t *);
static void open_link(int , struct sockaddr_storage * /* target */, struct sockaddr_storage * /* targetmask */);

static struct {
	uint32_t curround;			/* -R repeats			*/

	struct sockaddr_storage	curhost;
	uint32_t ipv4_mix;
	struct sockaddr_storage curhost_cnt;	/* 1 -> 255 for example		*/

	int32_t curport;
	int16_t plindex;

	uint8_t curttl;

	int32_t local_port;

	int c_socket;

	/* udp payload stuff */
	int (*create_payload)(uint8_t **, uint32_t *, void *);
	uint8_t *payload;
	uint32_t payload_size;

	uint8_t esrc[THE_ONLY_SUPPORTED_HWADDR_LEN];

	uint64_t packets_sent;

	int sockmode;
#define SOCK_LL 1
#define SOCK_IP 2
	union {
		ip_t *ipsock;
		eth_t *llsock;
	} s_u;
} sl;

#undef IDENT
#define IDENT "[SEND]"

static void init_nextttl(void);
static int   cmp_nextttl(void);
static void  inc_nextttl(void);
static void init_nexthost(void);
static int   cmp_nexthost(void);
static void  inc_nexthost(void);
static void init_nextround(void);
static int   cmp_nextround(void);
static void  inc_nextround(void);
static void init_nextport(void);
static int   cmp_nextport(void);
static void  inc_nextport(void);
static void init_payload(void);
static int   cmp_payload(uint16_t /*port*/, uint8_t ** /*data*/, uint32_t * /*payload_s*/, int32_t * /*local_port*/, int (** /*create payload */)(uint8_t **, uint32_t *, void *), uint16_t /* payload group */);
static void  inc_payload(void);

/* for ( init; cmp; inc ) { logic for ttl requested */
static void init_nextttl(void) {
	sl.curttl=s->ss->minttl;
}

static int   cmp_nextttl(void) {
	if (sl.curttl > s->ss->maxttl) {
		return 0;
	}
	return 1;
}

static void  inc_nextttl(void) {
	++sl.curttl;
}

/* for ( init; cmp; inc ) { logic for scan repeats requested */
static void init_nextround(void) {
	sl.curround=0;
}

static int   cmp_nextround(void) {
	if (sl.curround >= s->repeats) {
		return 0;
	}
	return 1;
}

static void  inc_nextround(void) {
	++sl.curround;
}

/* for ( init; cmp; inc ) { logic for scan port list requested */
static void init_nextport(void) {
	reset_getnextport();
}

static int   cmp_nextport(void) {
	if (get_nextport(&sl.curport) == -1) {
		return 0;
	}
	return 1;
}

static void  inc_nextport(void) {
	/* XXX do nothing, get_nextport incr's itself */
	return;
}

/* for ( init; cmp; inc ) { logic for scan payloads requested */
static void init_payload(void) {
	sl.plindex=0;
}

static int   cmp_payload(uint16_t port, uint8_t **data, uint32_t *payload_size, int32_t *lport, int (**create_payload)(uint8_t ** /* data */, uint32_t * /* size */, void *), uint16_t payload_group) {
	return get_payload(sl.plindex, IPPROTO_UDP, port, data, payload_size, lport, create_payload, payload_group);
}

static void  inc_payload(void) {
	sl.plindex++;
}

/* for ( init; cmp; inc ) { logic for scan hosts requested */
static void init_nexthost(void) {
	union sock_u su;

	memcpy(&sl.curhost, &s->ss->target, sizeof(struct sockaddr_storage));
	su.ss=&sl.curhost;

	if (su.fs->family == AF_INET) {
		union {
			struct sockaddr_in *sin;
			struct sockaddr_storage *ss;
		} curhost_u, cnt_u, targetmask_u;

		cnt_u.ss=&sl.curhost_cnt;

		targetmask_u.ss=&s->ss->targetmask;

		sl.ipv4_mix=prng_get32() & ~(targetmask_u.sin->sin_addr.s_addr);

		memcpy(&sl.curhost_cnt, &s->ss->target, sizeof(struct sockaddr_storage));

		curhost_u.ss=&sl.curhost;
		cnt_u.ss=&sl.curhost_cnt;

		curhost_u.sin->sin_addr.s_addr=cnt_u.sin->sin_addr.s_addr ^ sl.ipv4_mix;
	}
	else {
		PANIC("nyi");
	}

	return;
}

static int   cmp_nexthost(void) {

	return cidr_within((const struct sockaddr *)&sl.curhost_cnt, (const struct sockaddr *)&s->ss->target, (const struct sockaddr *)&s->ss->targetmask);

}

static void  inc_nexthost(void) {
	union sock_u su;

	su.ss=&sl.curhost;

	if (su.fs->family == AF_INET) {
		union {
			struct sockaddr_storage *ss;
			struct sockaddr_in *sin;
		} cur_u, cnt_u;

		cidr_inchost((struct sockaddr *)&sl.curhost_cnt);

		cur_u.ss=&sl.curhost;
		cnt_u.ss=&sl.curhost_cnt;

		cur_u.sin->sin_addr.s_addr=cnt_u.sin->sin_addr.s_addr ^ sl.ipv4_mix;
	}
	else {
		PANIC("nyi");
	}

	return;
}

void send_packet(void) {
	char conffile[512], *tmpchr=NULL;
	float pps=0.00, tt=0.00;
	uint8_t msg_type=0, *tmpptr=NULL, status=0;
	int s_socket=0, worktodo=0;
	size_t msg_len=0;
	union {
		drone_version_t *v;
		uint8_t *ptr;
	} d_u;
	drone_version_t dv;
	union {
		send_workunit_t *s;
		send_pri_workunit_t *p;
		uint8_t *cr;
		uint32_t *magic;
	} wk_u;
	size_t wku_len=0, port_str_len=0;
	struct timeval start, end, total_time;
	fl_t fnew;
	send_stats_t send_stats;

	if (init_modules() < 0) {
		terminate("cant initialize module structures, quiting");
	}

	close_output_modules();
	close_report_modules();

	memset(&dv, 0, sizeof(dv));
	d_u.v=&dv;
	dv.maj=DRONE_MAJ;
	dv.min=DRONE_MIN;
	dv.magic=DRONE_MAGIC;

	if (ipc_init() < 0) {
		terminate("cant initialize IPC");
	}

	if ((s_socket=socktrans_bind(s->ipcuri)) < 0) {
		terminate("cant create listener socket");
	}

	parent_sync();

	DBG(M_CLD, "waiting for main to connect");

	sl.c_socket=socktrans_accept(s_socket, DEF_SOCK_TIMEOUT);
	if (sl.c_socket < 0) {
		terminate("main didnt connect, exiting");
	}

	DBG(M_CLD, "got connection");

	if (get_singlemessage(sl.c_socket, &msg_type, &status, &tmpptr, &msg_len) != 1) {
		terminate("unexpected message sequence from parent while looking for ident request, exiting");
	}
	if (msg_type != MSG_IDENT || status != MSG_STATUS_OK) {
		terminate("bad message from parent, wrong type `%s' or bad status %d, exiting", strmsgtype(msg_type), status);
	}

	if (send_message(sl.c_socket, MSG_IDENTSENDER, MSG_STATUS_OK, d_u.ptr, sizeof(drone_version_t)) < 0) {
		terminate("cant send back msgident to parent");
	}

	if (get_singlemessage(sl.c_socket, &msg_type, &status, &tmpptr, &msg_len) != 1) {
		terminate("unexpected message sequence from parent while looking for ident request, exiting");
	}
	if (msg_type != MSG_ACK || status != MSG_STATUS_OK) {
		terminate("bad message from parent, wrong type `%s' or bad status %d, exiting", strmsgtype(msg_type), status);
	}

#if 0
	/* we dont want to pick a fight with the tasklets here, they are running at 19, so we will too */
	DBG(M_SND, "adjusting process priority to 19");
	if (setpriority(PRIO_PROCESS, 0, 19) < 0) {
		ERR("cant adjust priority, expect some evilness: %s", strerror(errno));
	}
#endif
	if (init_payloads() < 0) {
		terminate("cant initialize payload structures, quiting");
	}

	if (init_payload_modules(&add_payload) < 0) {
		terminate("cant initialize module payload structures, quiting");
	}

	/* get some payloads from the config files hopefully */
	snprintf(conffile, sizeof(conffile) -1, CONF_FILE, s->profile);
	readconf(conffile);

	if (send_message(sl.c_socket, MSG_READY, MSG_STATUS_OK, NULL, 0) < 0) {
		terminate("cant send ready message to parent");
	}

	DBG(M_CLD, "sender pid `%d' starting workunit loop", getpid());

	worktodo=1;

	while (worktodo) {
		if (recv_messages(sl.c_socket) < 1) {
			ERR("recv_messages fails, *shrug* no more work todo");
			worktodo=0;
			break;
		}

		while (get_message(sl.c_socket, &msg_type, &status, &(wk_u.cr), &msg_len) > 0) {

			DBG(M_IPC, "got a message `%s' with status %u from parent", strmsgtype(msg_type), status);

			if (msg_type == MSG_QUIT) {
				worktodo=0;
				break;
			}

			if (msg_type != MSG_WORKUNIT) {
				ERR("i was expecting a work unit or quit message, i got a `%s' message, ignoring", strmsgtype(msg_type));
				continue;
			}

			DBG(M_WRK, "workunit `%s'", strworkunit(wk_u.cr, msg_len));

			if (msg_len < 4) {
				ERR("short workunit (way too short) ignoring");
				continue;
			}

			if (*wk_u.magic == PRI_4SEND_MAGIC) {
				union {
					struct sockaddr_storage ss;
					struct sockaddr_in sin;
				} s_u;
				struct in_addr ia;

				if (msg_len < sizeof(send_pri_workunit_t)) {
					ERR("short pri workunit, ignoring");
					continue;
				}

				DBG(M_WRK, "got priority send workunit");

				if (s->ss->mode != MODE_TCPSCAN) {
					ERR("pri workunit outside of tcp mode");
					continue;
				}

				memset(&s_u.ss, 0, sizeof(struct sockaddr_storage));
				s_u.sin.sin_addr.s_addr=wk_u.p->dhost;
				s_u.sin.sin_family=AF_INET;

				open_link(SOCK_IP, &s_u.ss, NULL);

				ia.s_addr=wk_u.p->dhost;

				DBG(M_WRK, "send %s to host seq %08x %u -> %s:%u flags %08x seq %u window size %u",
					strtcpflgs(wk_u.p->flags),
					wk_u.p->mseq,
					wk_u.p->sport,
					inet_ntoa(ia),
					wk_u.p->dport,
					wk_u.p->flags,
					wk_u.p->tseq,
					wk_u.p->window_size
				);

				start_tslot();

				priority_send_packet((const send_pri_workunit_t *)wk_u.p);

				end_tslot();
				continue;
			} /* PRI send magic */

			if (msg_len < sizeof(send_workunit_t)) {
				ERR("short workunit, ignoring");
				continue;
			}

			DBG(M_WRK, "got batch workunit `%s'", strworkunit((const void *)wk_u.cr, msg_len));

			sl.packets_sent=0;

			if (s->ss->port_str != NULL) {
				xfree(s->ss->port_str);
				s->ss->port_str=NULL;
			}

			s->repeats=wk_u.s->repeats;
			s->send_opts=wk_u.s->send_opts;
			s->pps=wk_u.s->pps;
			s->delay_type_exp=wk_u.s->delay_type;
			memcpy(&s->vi[0]->myaddr, &wk_u.s->myaddr, sizeof(struct sockaddr_storage));
			memcpy(&s->vi[0]->mymask, &wk_u.s->mymask, sizeof(struct sockaddr_storage));
			memcpy(&sl.esrc, &wk_u.s->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
			s->vi[0]->mtu=wk_u.s->mtu;

			memcpy(&s->ss->target, &wk_u.s->target, sizeof(struct sockaddr_storage));
			memcpy(&s->ss->targetmask, &wk_u.s->targetmask, sizeof(struct sockaddr_storage));
			s->ss->tos=wk_u.s->tos;
			s->ss->minttl=wk_u.s->minttl;
			s->ss->maxttl=wk_u.s->maxttl;
			s->ss->ip_off=wk_u.s->ip_off;
			s->ss->fingerprint=wk_u.s->fingerprint;
			s->ss->src_port=wk_u.s->src_port;

			s->ss->tcphdrflgs=wk_u.s->tcphdrflgs;
			s->ss->tcpoptions_len=MIN(wk_u.s->tcpoptions_len, sizeof(s->ss->tcpoptions));
			memset(s->ss->tcpoptions, 0, sizeof(s->ss->tcpoptions));
			memcpy(s->ss->tcpoptions, wk_u.s->tcpoptions, s->ss->tcpoptions_len);
			s->ss->window_size=wk_u.s->window_size;
			s->ss->syn_key=wk_u.s->syn_key;

			wku_len=sizeof(send_workunit_t);
			port_str_len=wk_u.s->port_str_len;

			sl.local_port=s->ss->src_port;

			if (*wk_u.magic == TCP_SEND_MAGIC) {

				open_link(SOCK_IP, &s->ss->target, &s->ss->targetmask);

				DBG(M_WRK, "got tcp workunit");
				s->ss->mode=MODE_TCPSCAN;

			}
			else if (*wk_u.magic == UDP_SEND_MAGIC) {

				open_link(SOCK_IP, &s->ss->target, &s->ss->targetmask);

				DBG(M_WRK, "got udp workunit");
				s->ss->mode=MODE_UDPSCAN;

			}
			else if (*wk_u.magic == ARP_SEND_MAGIC) {

				open_link(SOCK_LL, &s->ss->target, &s->ss->targetmask);

				DBG(M_WRK, "got arp workunit");
				s->ss->mode=MODE_ARPSCAN;

			} /* ARP send magic */
			else {
				ERR("unknown workunit type 0x%08x, ignoring", *wk_u.magic);
				continue;
			}

			/* s->pps shouldnt be negative, but well just check anyhow */
			if (s->pps < 1) PANIC("pps too low");

			init_packet(); /* setup tcpoptions, ip chars etc */
			init_tslot(s->pps, s->delay_type_exp);

			if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
				uint8_t *psrc=NULL;

				psrc=wk_u.cr;
				psrc += wku_len;

				if ((size_t)(wku_len + port_str_len) < msg_len) {
					terminate("mismatched msg_len of %u compared to length of packet %d", (uint32_t)msg_len, (uint32_t)(wku_len + port_str_len));
				}

				if (s->ss->port_str) {
					xfree(s->ss->port_str);
				}
				s->ss->port_str=xstrdup(psrc);
			}

#if 0
	WHY DID THIS HAPPEN?
			/* XXX
			 * kludged for icc, it was crashing with movzbl (junk esi) inside
			 * __find_specmb in libc before (its part of printf to locate specifiers)
			 */
			tmpchr=inet_ntoa(s->vi[0]->myaddr.sin_addr);
			assert(tmpchr != NULL);
			s->vi[0]->myaddr_s[sizeof(s->vi[0]->myaddr_s) -1]='\0';
			strncpy(s->vi[0]->myaddr_s, tmpchr, sizeof(s->vi[0]->myaddr_s) -1);
			/* __asm__("int3"); */
#endif
			CLEAR(s->vi[0]->myaddr_s);
			tmpchr=cidr_saddrstr((const struct sockaddr *)&s->vi[0]->myaddr);
			assert(tmpchr != NULL);
			strncpy(s->vi[0]->myaddr_s, tmpchr, sizeof(s->vi[0]->myaddr_s) - 1);

			if (s->ss->mode == MODE_UDPSCAN || s->ss->mode == MODE_TCPSCAN) {
				if (s->ss->port_str[0] == 'q' || s->ss->port_str[0] == 'Q') {
					if (s->ss->mode == MODE_UDPSCAN) {
						parse_pstr(s->udpquickports, NULL);
					}
					else {
						parse_pstr(s->tcpquickports, NULL);
					}
				}
				else {
					DBG(M_PRT, "user port range requested, range `%s'", s->ss->port_str);
					parse_pstr(s->ss->port_str, NULL);
				}

				if (GET_SHUFFLE()) {
					shuffle_ports();
				}
			}

			start.tv_sec=0;
			start.tv_usec=0;
			if (gettimeofday(&start, NULL) < 0) {
				ERR("gettimeofday fails with :%s", strerror(errno));
				/* *shrug*, we shall keep going? , ctrl-c rules the day here */
			}

			if (flhead) {
				destroy_loop_logic();
			}

			/* repeats */
			fnew.init=&init_nextround;
			fnew.c_t=CTVOID;
			fnew.c_u.cmp=&cmp_nextround;
			fnew.inc=&inc_nextround;
			fnew.next=NULL;
			add_loop_logic((const fl_t *)&fnew);

			if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
				/* port */
				fnew.init=&init_nextport;
				fnew.c_t=CTVOID;
				fnew.c_u.cmp=&cmp_nextport;
				fnew.inc=&inc_nextport;
				fnew.next=NULL;
				add_loop_logic((const fl_t *)&fnew);

				/* ttl XXX normally only 1 iter */
				fnew.init=&init_nextttl;
				fnew.c_t=CTVOID;
				fnew.c_u.cmp=&cmp_nextttl;
				fnew.inc=&inc_nextttl;
				fnew.next=NULL;
				add_loop_logic((const fl_t *)&fnew);
			}

			/* payload */
			if (s->ss->mode == MODE_UDPSCAN) {
				fnew.init=&init_payload;
				fnew.c_t=CTPAYL;
				fnew.c_u.gpl=&cmp_payload;
				fnew.inc=&inc_payload;
				fnew.next=NULL;
				add_loop_logic((const fl_t *)&fnew);
			}

			/* host */
			fnew.init=&init_nexthost;
			fnew.c_t=CTVOID;
			fnew.c_u.cmp=&cmp_nexthost;
			fnew.inc=&inc_nexthost;
			fnew.next=NULL;
			add_loop_logic((const fl_t *)&fnew);

			/*
			 * do the work
			 */
			loop_list(flhead);

			end.tv_sec=0;
			end.tv_usec=0;
			if (gettimeofday(&end, NULL) < 0) {
				ERR("gettimeofday[2] fails with :%s", strerror(errno));
				/* *shrug*, we shall keep going? , ctrl-c rules the day here */
			}

			total_time.tv_sec=(end.tv_sec - start.tv_sec);
			total_time.tv_usec=(end.tv_usec - start.tv_usec);

			tt=(double)total_time.tv_sec + ((double)total_time.tv_usec / 1000000);
			if (tt > 0.0) {
				pps=sl.packets_sent / tt;
			}
			else {
				pps=0;
			}

			send_stats.pps=pps;
			send_stats.packets_sent=sl.packets_sent;

			DBG(M_IPC, "sender sending message done");

			if (send_message(sl.c_socket, MSG_WORKDONE, MSG_STATUS_OK, (void *)&send_stats, sizeof(send_stats)) < 0) {
				terminate("cant send workdone message to parent, exiting");
			}

		} /* while get_message */

	} /* while worktodo */

	uexit(0);
}

static void _send_packet(void) {
	uint16_t n_chksum=0, t_chksum=0, rport=0;
	int ipv4=0, ipv6=0;
	union sock_u ipvchk;
	struct sockaddr_storage src;
	union sock_u target_u, myaddr_u;

	start_tslot();

	if (GET_SENDERINTR()) {
		xpoll_t intrp;
		int getret=0;
		uint8_t msg_type=0, status=0;
		size_t msg_len=0;
		union {
			uint8_t *ptr;
			send_pri_workunit_t *w;
		} w_u;

		DBG(M_IPC, "sender can be interupted, checking for data");
		intrp.fd=sl.c_socket;

		if (xpoll(&intrp, 1, 0) < 0) {
			ERR("xpoll fails: %s", strerror(errno));
		}

		if (intrp.rw & XPOLL_READABLE) {
			if (recv_messages(sl.c_socket) < 0) {
				ERR("recv messages fails in send prio loop");
				return;
			}
			while (1) {
				getret=get_message(sl.c_socket, &msg_type, &status, &w_u.ptr, &msg_len);
				if (getret < 1) {
					break;
				}
				if (msg_type == MSG_WORKUNIT) {
					struct in_addr ia;

					if (msg_len < sizeof(send_pri_workunit_t)) {
						ERR("pri workunit too short");
						break;
					}
					if (w_u.w->magic != PRI_4SEND_MAGIC) {
						ERR("pri workunit has wrong magic %08x", w_u.w->magic);
						break;
					}

					ia.s_addr=w_u.w->dhost;

					DBG(M_WRK, "send %s to host seq %08x %u -> %s:%u flags %08x seq %u window size %u",
						strtcpflgs(w_u.w->flags),
						w_u.w->mseq,
						w_u.w->sport,
						inet_ntoa(ia),
						w_u.w->dport,
						w_u.w->flags,
						w_u.w->tseq,
						w_u.w->window_size
					);
					priority_send_packet((const send_pri_workunit_t *)w_u.w);

					end_tslot();
					start_tslot();
				}
				else {
					ERR("unknown workunit type `%s', ignoring", strmsgtype(msg_type));
				}
			}
		}
	}

	ipvchk.ss=&s->vi[0]->myaddr;
	if (ipvchk.fs->family == AF_INET) {
		ipv4=1;
	}
	else if (ipvchk.fs->family == AF_INET6) {
		ipv6=1;
	}
	else {
		PANIC("nyi");
	}

	myaddr_u.ss=&src;
	/*
	 * this does nothing if we have a null mask
	 */
	cidr_randhost(
		(struct sockaddr *)myaddr_u.s,
		(const struct sockaddr *)&s->vi[0]->myaddr,
		(const struct sockaddr *)&s->vi[0]->mymask
	);

	target_u.ss=&sl.curhost;

	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
		rport=(uint16_t)sl.curport;

		if (s->ss->src_port == -1) {
			sl.local_port=0;

			sl.local_port=(uint16_t)(prng_get32() % 0xffff);
			if (sl.local_port < MIN_LOCALPORT) {
				sl.local_port += MIN_LOCALPORT;
			}
		}
		else {
			sl.local_port=(uint16_t)s->ss->src_port;
		}

		if (sl.create_payload != NULL) {
			DBG(M_SND, "running create payload");

			if (sl.create_payload(&sl.payload, &sl.payload_size, target_u.s) < 0) {
				ERR("create payload for port %d fails", rport);
				return;
			}
		}
	}

	makepkt_clear();

	if (GET_BROKENTRANS() || GET_BROKENNET()) {
		union {
			struct {
				uint16_t a;
				uint16_t b;
			} s;
			uint32_t c;
		} w_u;

		w_u.c=prng_get32();

		if (GET_BROKENTRANS()) {
			t_chksum=w_u.s.b;
		}

		if (GET_BROKENNET()) {
			n_chksum=w_u.s.a;
		}
	}

	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
		/****************************************************************
		 *			BUILD IP HEADER				*
		 ****************************************************************/
		if (ipv4 == 1) {
			/* XXX */
			assert(target_u.fs->family == AF_INET && myaddr_u.fs->family == AF_INET);

			makepkt_build_ipv4(	s->ss->tos,
						(uint16_t)prng_get32()		/* IPID */,
						s->ss->ip_off,
						sl.curttl,
						s->ss->mode == MODE_TCPSCAN ? IPPROTO_TCP : IPPROTO_UDP,
						n_chksum,
						myaddr_u.sin->sin_addr.s_addr,
						target_u.sin->sin_addr.s_addr,
						NULL				/* ip options */,
						0				/* ipopt size */,
						NULL				/* payload */,
						0				/* payload size */
			);
		}
		else if (ipv6 == 1) {
			PANIC("NYI");
		}
		else {
			PANIC("no!");
		}
	}
	else if (s->ss->mode == MODE_ARPSCAN) {
		uint8_t ethbk[6]={ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

		/****************************************************************
		 *			BUILD ETH HEADER			*
		 ****************************************************************/
		makepkt_build_ethernet(	6,
					(const uint8_t *)&ethbk[0],
					(const uint8_t *)sl.esrc,
					ETHERTYPE_ARP
		);
	}

	if (s->ss->mode == MODE_UDPSCAN) {
		/****************************************************************
		 *			BUILD UDP HEADER			*
		 ****************************************************************/

		/* XXX need to disable checksums somehow by not using 0 as random */
		makepkt_build_udp(	(uint16_t)sl.local_port,
					rport,
					t_chksum,
					sl.payload,
					(uint16_t)sl.payload_size
		);
	}
	else if (s->ss->mode == MODE_TCPSCAN) {
		uint32_t seq=0;

		/****************************************************************
		 *			BUILD TCP HEADER			*
		 ****************************************************************/
		TCPHASHTRACK(seq, target_u.sin->sin_addr.s_addr, rport, sl.local_port, s->ss->syn_key);

		makepkt_build_tcp(	(uint16_t)sl.local_port,
					rport,
					t_chksum,
					seq,
					0,			/* XXX ackseq = seq oddity */
					s->ss->tcphdrflgs,
					s->ss->window_size,
					0,			/* urg ptr */
					s->ss->tcpoptions,
					s->ss->tcpoptions_len,
					NULL,			/* payload */
					0			/* payload size */
		);
	}
	else if (s->ss->mode == MODE_ARPSCAN) {
		/****************************************************************
		 *			BUILD ARP HEADER			*
		 ****************************************************************/
		uint8_t arpbk[6]={ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		if (ipv4 == 1) {
			makepkt_build_arp(	ARPHRD_ETHER,
						ETHERTYPE_IP,
						6,
						4,
						ARPOP_REQUEST,
						(const uint8_t *)sl.esrc,
						(const uint8_t *)&myaddr_u.sin->sin_addr.s_addr,
						(const uint8_t *)&arpbk[0],
						(const uint8_t *)&target_u.sin->sin_addr.s_addr
			);
		}
		else {
			PANIC("nyi");
		}
	}

	if (ISDBG(M_SND)) {
		char myhost[256];

		snprintf(myhost, sizeof(myhost) -1, "%s", cidr_saddrstr((const struct sockaddr *)myaddr_u.s));

		if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
			DBG(M_SND, "sending to `%s:%d' from `%s:%u'",
				cidr_saddrstr((const struct sockaddr *)&sl.curhost),
				sl.curport,
				myhost,
				(uint16_t)sl.local_port
			);
		}
		else {
			DBG(M_SND, "asking for `%s' from `%s'", cidr_saddrstr((const struct sockaddr *)&sl.curhost), myhost);
		}
	}

	if (sl.sockmode == SOCK_IP) {
		size_t buf_size=0;
		const uint8_t *pbuf=NULL;

		makepkt_getbuf(&buf_size, &pbuf);
		if (pbuf != NULL && buf_size) {
			ssize_t ips=0;

			ips=ip_send(sl.s_u.ipsock, pbuf, buf_size);
			if (ips < 0 || (size_t)ips != buf_size) {
				hexdump(pbuf, buf_size);
				terminate("ip send fails somehow");
			}
		}
		else {
			terminate("ip buffer NULL");
		}
	}
	else if (sl.sockmode == SOCK_LL) {
		size_t buf_size;
		const uint8_t *pbuf=NULL;

		makepkt_getbuf(&buf_size, &pbuf);

		if (pbuf != NULL && buf_size) {
			ssize_t ets=0;

			ets=eth_send(sl.s_u.llsock, pbuf, buf_size);

			if (ets < 0 || (size_t)ets != buf_size) {
				terminate("ethernet send fails somehow");
			}
		}
		else {
			terminate("ethernet buffer NULL");
		}
	}
	else {
		PANIC("socket is not anything i know about, impossible");
	}

	sl.packets_sent++;

	if (sl.create_payload != NULL && sl.payload != NULL) {
		DBG(M_SND, "freeing payload");
		xfree(sl.payload);
		sl.payload=NULL;
	}

	end_tslot();

	return;
}

static void destroy_loop_logic(void) {
	fl_t *ptr=NULL;

	for (; flhead != NULL; ) {
		ptr=flhead->next;
		xfree(flhead);
		if (ptr == NULL) {
			break;
		}
		flhead=ptr;
	}

	flhead=NULL;
}

static int add_loop_logic(const fl_t *fnew) {
	fl_t *item=NULL;

	if (flhead == NULL) {
		DBG(M_SND, "adding new logic list head");
		flhead=(fl_t *)xmalloc(sizeof(fl_t));
		item=flhead;
	}
	else {
		DBG(M_SND, "adding new logic list node");
		item=flhead;
		while (item->next != NULL) {
			item=item->next;
		}
		item->next=(fl_t *)xmalloc(sizeof(fl_t));
		item=item->next;
	}

	memset(item, 0, sizeof(fl_t));
	item->next=NULL;
	item->init=fnew->init;
	item->c_t=fnew->c_t;
	switch (item->c_t) {
		case CTVOID:
			item->c_u.cmp=fnew->c_u.cmp;
			break;
		case CTPAYL:
			item->c_u.gpl=fnew->c_u.gpl;
			break;
		default:
			terminate("unknown function prototype for loop logic %x", item->c_t);
	}
	item->inc=fnew->inc;

	return 1;
}

void loop_list(fl_t *node) {
	assert(node != NULL);

	switch (node->c_t) {
		case CTVOID:
			for (node->init(); node->c_u.cmp(); node->inc()) {
				if (node->next) {
					loop_list(node->next);
				}
				else {
					/* inside function call */
					_send_packet();
				}
			}
			break;

		case CTPAYL:
			for (node->init(); node->c_u.gpl((uint16_t)sl.curport, &sl.payload, &sl.payload_size, &sl.local_port, &sl.create_payload, s->payload_group); node->inc()) { 
				if (node->next) {
					loop_list(node->next);
				}
				else {
					/* inside function call */
					_send_packet();
				}
			}
			break;

		default:
			terminate("runtime error looping list, unknown compare function prototype in list `%c'", node->c_t);
			break;
	}

	return;
}


void priority_send_packet(const send_pri_workunit_t *w) {
	union {
		const send_pri_workunit_t *w;
		const uint8_t *data;
	} pw_u;
	const uint8_t *dptr=NULL, *pbuf=NULL;
	size_t dlen=0, buf_size=0;

	assert(w != NULL);
	assert(w->magic == PRI_4SEND_MAGIC);

	get_postoptions(w->t_tstamp, w->m_tstamp);	/* inside init_packet for now */

	pw_u.w=w;
	if (w->doff) {
		dptr=pw_u.data + sizeof(send_pri_workunit_t);
		dlen=w->doff;
	}

	makepkt_clear();

	/****************************************************************
	 *			BUILD IP HEADER				*
	 ****************************************************************/
	makepkt_build_ipv4(	s->ss->tos				/* TOS */,
				(uint16_t)prng_get32() & 0xffff		/* IPID */,
				s->ss->ip_off				/* FRAG */,
				s->ss->maxttl				/* TTL XXX best thing to do here? max might be a best guess */,
				IPPROTO_TCP,
				0					/* chksum*/, /* XXX broken checksum */
				w->shost,
				w->dhost,
				NULL					/* ip options */,
				0					/* ipopt len */,
				NULL					/* payload */,
				0					/* payload size */
	);


	/****************************************************************
	 *			BUILD TCP HEADER			*
	 ****************************************************************/
	makepkt_build_tcp(	w->sport,
				w->dport,
				0,					/* XXX broken checksum */
				w->mseq,
				w->tseq,
				w->flags,
				w->window_size,
				0,					/* urgent ptr */
				s->ss->posttcpoptions,
				s->ss->posttcpoptions_len,
				dptr,
				dlen
	);


	makepkt_getbuf(&buf_size, &pbuf);
	if (pbuf != NULL && buf_size) {
		ssize_t ips=0;

		ips=ip_send(sl.s_u.ipsock, pbuf, buf_size);

		if (ips < 0 || (size_t)ips != buf_size) {
			terminate("ip send fails somehow");
		}
	}
	else {
		terminate("ip buffer NULL");
	}

	sl.packets_sent++;

	return;
}

static void open_link(int mode, struct sockaddr_storage *target, struct sockaddr_storage *targetmask) {

	DBG(M_SND, "open link at `%s'", mode == SOCK_LL ? "link layer" : "network layer");

	if (sl.sockmode != mode) {
		switch (sl.sockmode) {
			case SOCK_LL:
				if (sl.s_u.llsock != NULL) {
					eth_close(sl.s_u.llsock);
					sl.s_u.llsock=NULL;
				}
				break;

			case SOCK_IP:
				if (sl.s_u.ipsock != NULL) {
					ip_close(sl.s_u.ipsock);
					sl.s_u.ipsock=NULL;
				}
				break;

		}
	}

	sl.sockmode=mode;

	switch (mode) {
		case SOCK_IP:
			if (sl.s_u.ipsock == NULL) {
				sl.s_u.ipsock=ip_open();
				if (sl.s_u.ipsock == NULL) {
					terminate("dnet ip_open fails");
				}
			}
			break;

		case SOCK_LL:
			if (sl.s_u.llsock == NULL) {
				sl.s_u.llsock=eth_open(s->interface_str);
				if (sl.s_u.llsock == NULL) {
					terminate("dnet eth_open `%s' fails", s->interface_str);
				}
			}
			break;

		default:
			terminate("unknown link mode `%d', exiting", mode);
	}

	return;
}
