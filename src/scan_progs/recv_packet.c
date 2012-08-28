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

#include <pcap.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>
#include <packageinfo.h>

#include <unilib/terminate.h>
#include <unilib/xipc.h>
#include <unilib/arch.h>
#include <unilib/xmalloc.h>
#include <unilib/xpoll.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>
#include <unilib/pcaputil.h>
#include <unilib/modules.h>
#include <unilib/drone.h>
#include <unilib/socktrans.h>
#include <scan_progs/recv_packet.h>
#include <scan_progs/workunits.h>
#include <scan_progs/portfunc.h>
#include <scan_progs/packet_parse.h>
#include <scan_progs/entry.h>

#define UDP_PFILTER "udp"
#define UDP_EFILTER "or icmp"

/*
#define TCP_PFILTER "tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"
#define TCP_EFILTER "or icmp or (tcp[tcpflags] & (tcp-ack|tcp-rst) == (tcp-ack|tcp-rst))"
*/
#define TCP_PFILTER "tcp"
#define TCP_EFILTER "or icmp"

#define ARP_PFILTER "arp"

#define FRAG_MASK 0x1fff

static int lc_s;
static char *get_pcapfilterstr(void);
static void drain_pqueue(void);
static void extract_pcapfilter(const uint8_t *, size_t);

pcap_dumper_t *pdump;
static pcap_t *pdev;
static int pcap_fd;


void *r_queue=NULL, *p_queue=NULL;

void recv_packet(void) {
	char errbuf[PCAP_ERRBUF_SIZE], *pfilter=NULL;
	struct bpf_program filter;
	bpf_u_int32 net, mask;
	int ac_s=0, ret=0, worktodo=1;
	uint8_t msg_type=0, status=0, *ptr=NULL;
	size_t msg_len=0;
	xpoll_t spdf[2];
	union {
		recv_workunit_t *r;
		uint8_t *cr;
		uint32_t *magic;
	} wk_u;
	union {
		listener_info_t *l;
		uint8_t *ptr;
	} l_u;
	union {
		drone_version_t *v;
		uint8_t *ptr;
	} d_u;
	drone_version_t dv;
	struct pcap_stat pcs;

	r_queue=fifo_init();

	close_output_modules();
	close_report_modules();
	close_payload_modules();

	DBG(M_IPC, "creating server socket");

	memset(s->ss, 0, sizeof(scan_settings_t));

	memset(&dv, 0, sizeof(dv));
	d_u.v=&dv;
	dv.magic=DRONE_MAGIC;
	dv.maj=DRONE_MAJ;
	dv.min=DRONE_MIN;
	recv_stats_t recv_stats;

	/* heh */
	if ((ac_s=socktrans_bind(s->ipcuri)) < 0) {
		terminate("cant create listener socket");
	}

	DBG(M_IPC, "waiting for main to connect");

	parent_sync();

	lc_s=socktrans_accept(ac_s, DEF_SOCK_TIMEOUT);
	if (lc_s < 0) {
		terminate("main didnt connect, exiting");
	}

	DBG(M_IPC, "got connection");

	if (get_singlemessage(lc_s, &msg_type, &status, &ptr, &msg_len) != 1) {
		terminate("unexpected sequence of messages from parent waiting for ident request, exiting");
	}

	if (msg_type != MSG_IDENT || status != MSG_STATUS_OK) {
		ERR("got an unknown message type `%s' or bad status %d from parent, exiting", strmsgtype(msg_type), status);
	}

	if (send_message(lc_s, MSG_IDENTLISTENER, MSG_STATUS_OK, d_u.ptr, sizeof(drone_version_t)) < 0) {
		terminate("cant send back msgident to parent");
	}

	if (get_singlemessage(lc_s, &msg_type, &status, &ptr, &msg_len) != 1) {
		terminate("cant read ident ack message from parent, exiting");
	}
	if (msg_type != MSG_ACK || status != MSG_STATUS_OK) {
		ERR("got an unknown message type `%s' or bad status %d from parent, exiting", strmsgtype(msg_type), status);
	}

	DBG(M_IPC, "sending ready message to parent");

	l_u.l=(listener_info_t *)xmalloc(sizeof(listener_info_t));

	memcpy(&l_u.l->myaddr, &s->vi[0]->myaddr, sizeof(struct sockaddr_storage));
	memcpy(&l_u.l->mymask, &s->vi[0]->mymask, sizeof(struct sockaddr_storage));
	memcpy(l_u.l->hwaddr, s->vi[0]->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
	l_u.l->mtu=s->vi[0]->mtu;

	assert(s->interface_str != NULL);

	if (pcap_lookupnet(s->interface_str, &net, &mask, errbuf) < 0) {
		ERR("pcap_lookupnet fails, ignoring: %s", errbuf);
	}

	if (s->pcap_readfile == NULL) {
		pdev=pcap_open_live(s->interface_str, /* XXX haha */ s->vi[0]->mtu + 64, (GET_PROMISC() ? 1 : 0), 0, errbuf);
		if (pdev == NULL) {
			ERR("pcap open live: %s", errbuf);

			DBG(M_IPC, "sending ready error message to parent");
			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				terminate("cant send message ready error");
			}
			terminate("informed parent, exiting");
		}
	}
	else {
		pdev=pcap_open_offline(s->pcap_readfile, errbuf);
		if (pdev == NULL) {
			ERR("pcap open offline: %s", errbuf);

			DBG(M_IPC, "sending ready error message to parent");
			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				terminate("cant send message ready error");
			}
			terminate("informed parent, exiting");
		}
	}

	ret=util_getheadersize(pdev, errbuf);
	if (ret < 0 || ret > 0xffff) {
		ERR("error getting link header size: %s", errbuf);

		DBG(M_IPC, "sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			terminate("cant send message ready error");
		}
		terminate("informed parent, exiting");
	}
	s->ss->header_len=(uint16_t)ret;

	if (s->pcap_dumpfile != NULL) {
		VRB(0, "opening `%s' for pcap log", s->pcap_dumpfile);
		pdump=pcap_dump_open(pdev, s->pcap_dumpfile);
		if (pdump == NULL) {
			ERR("cant log to pcap file `%s'", pcap_geterr(pdev));

			DBG(M_IPC, "sending ready error message to parent");
			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				terminate("cant send message ready error");
			}
			terminate("informed parent, exiting");
		}
	}
	else {
		DBG(M_CLD, "not logging to pcap file");
	}

	if (util_preparepcap(pdev, errbuf) < 0) {
		ERR("cant setup pcap filedesc to immediate mode: %s", errbuf);

		DBG(M_IPC, "sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			terminate("cant send message ready error");
		}
		terminate("informed parent, exiting");
	}

	/* pcap_fd will be -1 for a pcap file */
	pcap_fd=pcap_get_selectable_fd(pdev);

	if (pcap_fd < 0 && s->pcap_readfile == NULL) {
		ERR("cant get selectable fd from pcap device, exiting");

		DBG(M_IPC, "sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			terminate("sant send message ready error");
		}
		terminate("informed parent, exiting");
	}

#ifdef PCAP_D_IN
	if (pcap_setdirection(pdev, PCAP_D_IN) < 0) {
		ERR("cant set pcap direction to in, exiting");

		DBG(M_IPC, "sending ready error message to parent");
		if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
			terminate("sant send message ready error");
		}
		terminate("informed parent, exiting");
	}
#endif

	DBG(M_CLD, "listener dropping privs");

	if (drop_privs() < 0) {
		terminate("cant drop privs");
	}

	if (send_message(lc_s, MSG_READY, MSG_STATUS_OK, l_u.ptr, sizeof(listener_info_t)) < 0) {
		terminate("cant send message ready");
	}

	xfree(l_u.l);

	/* XXX */
	s->ss->syn_key=0;

	do {
		if (get_singlemessage(lc_s, &msg_type, &status, &wk_u.cr, &msg_len) != 1) {
			terminate("unexpected sequence of messages from parent looking for a workunit");
		}

		if (status != MSG_STATUS_OK) {
			terminate("bad message status %u", status);
		}

		if (msg_type == MSG_QUIT) {
			worktodo=0;
			break;
		}
		else if (msg_type == MSG_WORKUNIT) {
			;
		}
		else {
			terminate("unexpected message, expecting workunit or quit message");
		}

		if (msg_len < sizeof(uint32_t)) {
			terminate("bad message, too short [" STFMT "]", msg_len);
		}

		if (msg_len < sizeof(recv_workunit_t)) {
			terminate("short workunit");
		}

		worktodo=1;

		DBG(M_WRK, "workunit `%s'", strworkunit(wk_u.cr, msg_len));

		s->ss->recv_timeout=wk_u.r->recv_timeout;
		s->ss->ret_layers=wk_u.r->ret_layers;
		s->recv_opts=wk_u.r->recv_opts;
		s->ss->window_size=wk_u.r->window_size;

		s->ss->syn_key=wk_u.r->syn_key;

		if (wk_u.r->pcap_len) {
			if ((msg_len - sizeof(recv_workunit_t)) == wk_u.r->pcap_len) {
				extract_pcapfilter(wk_u.cr + sizeof(recv_workunit_t), wk_u.r->pcap_len);
			}
			else {
				terminate("pcap option length illegal");
			}
		}

		switch (*wk_u.magic) {
			case UDP_RECV_MAGIC:
				s->ss->mode=MODE_UDPSCAN;
				break;

			case TCP_RECV_MAGIC:
				s->ss->mode=MODE_TCPSCAN;
				break;

			case ARP_RECV_MAGIC:
				s->ss->mode=MODE_ARPSCAN;
				break;

			default:
				terminate("unknown recv workunit type");
				break;
		}

		DBG(M_IPC, "from ipc, got workunit: %s", strworkunit((const void *)wk_u.cr, msg_len));

		if (s->ss->mode == MODE_ARPSCAN) {
			if (s->ss->header_len != 14) {

				DBG(M_IPC, "sending msg error");
				if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
					terminate("cant send message ready");
				}
				terminate("wrong linktype for arp scan");
			}
		}

		if (s->ss->ret_layers > 0) {
			DBG(M_CLD, "setting up packet queue");
			p_queue=fifo_init();
		}

		pfilter=get_pcapfilterstr();

		VRB(1, "using pcap filter: `%s'", pfilter);

		memset(&filter, 0, sizeof(filter));
		if (pcap_compile(pdev, &filter, pfilter, 0, net) < 0) {
			ERR("error compiling filter: %s",  pcap_geterr(pdev));

			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				ERR("cant send message ready error");
			}
			terminate("cant compile pcap filter");
		}

		if (pcap_setfilter(pdev, &filter) < 0) {
			ERR("error setting compiled filter: %s", pcap_geterr(pdev));

			if (send_message(lc_s, MSG_READY, MSG_STATUS_ERROR, NULL, 0) < 0) {
				ERR("cant send message ready error");
			}
			terminate("cant set compiled pcap filter");
		}

		pcap_freecode(&filter);

		if (s->ss->ret_layers > 0) {
			DBG(M_IPC, "returning whole packet via ipc");
		}

		DBG(M_IPC, "sending ready message to parent");

		if (pcap_setnonblock(pdev, 1, errbuf) < 0) {
			terminate("cant set pcap non-blocking mode");
		}

		if (send_message(lc_s, MSG_READY, MSG_STATUS_OK, NULL, 0) < 0) {
			terminate("cant send message ready");
		}

		while (1) {
			spdf[0].fd=lc_s;
			spdf[1].fd=pcap_fd;

			/* if pdev is a socket  ( ! -1 ) */
			if (xpoll(&spdf[0], 2, -1) < 0) {
				ERR("xpoll fails: %s", strerror(errno));
			}

			if (spdf[1].rw & XPOLL_READABLE) {
				pcap_dispatch(pdev, 1, parse_packet, NULL);
			}

			/* no packets, better drain the queue */
			drain_pqueue();

			if (spdf[0].rw & XPOLL_READABLE) {
				if (get_singlemessage(lc_s, &msg_type, &status, &ptr, &msg_len) != 1) {
					ERR("unexpected sequence of messages from parent in main read loop, exiting");
					worktodo=0;
					break;
				}

				if (msg_type == MSG_TERMINATE) {
					DBG(M_IPC, "parent wants me to stop listening, breaking");
					break;
				}
				else if (msg_type == MSG_QUIT) {
					DBG(M_IPC, "Parent wants me to quit, breaking");
					worktodo=0;
					break;
				}
				else {
					ERR("got strange message `%s' from parent, exiting", strmsgtype(msg_type));
					worktodo=0;
					break;
				}
			}
		}

		memset(&recv_stats, 0, sizeof(recv_stats));

		if (pcap_stats(pdev, &pcs) != -1) {

			recv_stats.packets_recv=pcs.ps_recv;
			recv_stats.packets_dropped=pcs.ps_drop;
			recv_stats.packets_dropped=pcs.ps_ifdrop;
		}

		if (send_message(lc_s, MSG_WORKDONE, MSG_STATUS_OK, (void *)&recv_stats, sizeof(recv_stats)) < 0) {
			terminate("cant send workdone message to parent, exiting");
		}

	} while (worktodo);

	pcap_close(pdev);
	if (s->pcap_dumpfile) {
		pcap_dump_close(pdump);
	}


	DBG(M_CLD, "listener exiting");

	shutdown(lc_s, SHUT_RDWR);
	close(lc_s);
 
	uexit(0);
}

static char *get_pcapfilterstr(void) {
	static char base_filter[128], addr_filter[128], pfilter[512];
	uint32_t foct=0;

	CLEAR(base_filter); CLEAR(addr_filter); CLEAR(pfilter);

	switch (s->ss->mode) {
		case MODE_UDPSCAN:
			if (GET_WATCHERRORS()) {
				snprintf(base_filter, sizeof(base_filter) -1, "%s %s", UDP_PFILTER, UDP_EFILTER);
			}
			else {
				snprintf(base_filter, sizeof(base_filter) -1, "%s", UDP_PFILTER);
			}
			break;

		case MODE_TCPSCAN:
			if (GET_WATCHERRORS()) {
				snprintf(base_filter, sizeof(base_filter) -1, "%s %s", TCP_PFILTER, TCP_EFILTER);
			}
			else {
				snprintf(base_filter, sizeof(base_filter) -1, "%s", TCP_PFILTER);
			}
			break;

		case MODE_ARPSCAN:
			snprintf(base_filter, sizeof(base_filter) -1, "%s", ARP_PFILTER);
			break;

		default:
			terminate("unknown mode");
			break;
	}

	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
#if 0
		foct=(htonl(s->vi[0]->myaddr.sin_addr.s_addr) >> 24);
		if (foct == 0x7f) {
			snprintf(addr_filter, sizeof(addr_filter) -1, "dst %s", s->vi[0]->myaddr_s);
		}
#else 
# warning FIXTHIS isloopback check
#endif
//		else {
			snprintf(addr_filter, sizeof(addr_filter) -1, "dst %s and ! src %s", s->vi[0]->myaddr_s, s->vi[0]->myaddr_s);
//		}
	}

	if (s->ss->mode == MODE_TCPSCAN || s->ss->mode == MODE_UDPSCAN) {
		/* XXX multicast */
		if (s->extra_pcapfilter != NULL && strlen(s->extra_pcapfilter)) {
			snprintf(pfilter, sizeof(pfilter) -1, "%s and (%s and %s)", addr_filter, base_filter, s->extra_pcapfilter);
		}
		else {
			if (s->pcap_readfile == NULL) {
				snprintf(pfilter, sizeof(pfilter) -1, "%s and (%s)", addr_filter, base_filter);
			}
			else {
				/* the pcap tracefile could have someone elses address in it.... */
				snprintf(pfilter, sizeof(pfilter) -1, "%s", base_filter);
			}
		}
	}
	else {
		snprintf(pfilter, sizeof(pfilter) -1, "%s", base_filter);
	}

	return pfilter;
}

static void drain_pqueue() {
	union {
		void *ptr;
		uint8_t *cr;
		uint32_t *r_magic;
	} r_u;
	size_t r_size=0;

	while ((r_u.ptr=fifo_pop(r_queue)) != NULL) {
		if (*r_u.r_magic == IP_REPORT_MAGIC) {
			r_size=sizeof(ip_report_t);
		}
		else if (*r_u.r_magic == ARP_REPORT_MAGIC) {
			r_size=sizeof(arp_report_t);
		}
		else {
			PANIC("report size/type unknown [%08x magic]", *r_u.r_magic);
		}

		if (s->ss->ret_layers > 0) {
			union {
				uint16_t *length;
				void *data;
				uint8_t *inc;
			} packet_u;
			union {
				void *data;
				uint8_t *inc;
			} nr_u;
			uint16_t pk_len=0;

			packet_u.data=fifo_pop(p_queue);
			if (packet_u.data == NULL) {
				PANIC("packet queue empty, mismatch with report queue");
			}
			DBG(M_CLD, "packet length is %u", *packet_u.length);
			pk_len=*packet_u.length;

			/* this should be impossible */
			if (pk_len > (uint16_t)s->vi[0]->mtu) {
				PANIC("impossible packet length in queue");
			}

			nr_u.data=xmalloc(r_size + pk_len + sizeof(pk_len));

			memcpy(nr_u.data, (const void *)r_u.ptr, r_size);
			memcpy(nr_u.inc + r_size, (const void *)packet_u.data, pk_len + sizeof(pk_len));

			if (send_message(lc_s, MSG_OUTPUT, MSG_STATUS_OK, nr_u.inc, r_size + pk_len + sizeof(pk_len)) < 0) {
				terminate("cant send message output");
			}

			xfree(nr_u.data);
			xfree(packet_u.data);
		}
		else {
			if (send_message(lc_s, MSG_OUTPUT, MSG_STATUS_OK, r_u.cr, r_size) < 0) {
				terminate("cant send message output");
			}
		}
		xfree(r_u.ptr);
	} /* while we can ipc a packet */

	return;
}

static void extract_pcapfilter(const uint8_t *str, size_t len) {
	if (s->extra_pcapfilter != NULL) { /* IM A DUAL TIMER IC */
		xfree(s->extra_pcapfilter);
	}

	s->extra_pcapfilter=(char *)xmalloc(len + 1);
	memcpy(s->extra_pcapfilter, str, len);
	s->extra_pcapfilter[len]='\0';
}
