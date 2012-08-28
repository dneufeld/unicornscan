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
#include <settings.h>
#include <scan_progs/scan_export.h>

#include <unilib/xmalloc.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>
#include <unilib/pktutil.h>

#include <scan_progs/packets.h>
#include <scan_progs/chksum.h>
#include <scan_progs/tcphash.h>

#include <pcap.h>

#include <scan_progs/packet_parse.h>

static void report_init(int /* type */, const struct timeval * /* pcap recv time */);
static void packet_init(const uint8_t * /* packet */, size_t /* pk_len */);
static void report_push(void);

static void  decode_arp (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_ip  (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_tcp (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_udp (const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_icmp(const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);
static void  decode_junk(const uint8_t * /* packet */, size_t /* pk_len */, int /* pk_layer */);

static int r_type=0;
static union {
	arp_report_t a;
	ip_report_t i;
} r_u;

extern void *r_queue, *p_queue;

static const uint8_t *trailgarbage=NULL, *p_ptr=NULL;
static size_t trailgarbage_len=0, p_len=0;
static ip_pseudo_t ipph;

static void packet_init(const uint8_t *packet, size_t pk_len) {
	p_ptr=packet;
	p_len=pk_len;
	return;
}

static void report_init(int type, const struct timeval *pcap_time) {

	r_type=type;
	switch (type) {
		case REPORT_TYPE_IP:
			memset(&r_u.i, 0, sizeof(ip_report_t));

			r_u.i.magic=IP_REPORT_MAGIC;
			r_u.i.od_q=NULL; /* this is not used here */
			if (pcap_time) {
				r_u.i.recv_time.tv_sec=pcap_time->tv_sec;
				r_u.i.recv_time.tv_usec=pcap_time->tv_usec;
			}
			break;

		case REPORT_TYPE_ARP:
			memset(&r_u.a, 0, sizeof(arp_report_t));

			r_u.a.magic=ARP_REPORT_MAGIC;
			r_u.a.od_q=NULL; /* this is not used here */
			if (pcap_time) {
				r_u.a.recv_time.tv_sec=pcap_time->tv_sec;
				r_u.a.recv_time.tv_usec=pcap_time->tv_usec;
			}
			break;

		default:
			PANIC("unknown report type requested");
			break;
	}
	return;
}

static void report_push(void) {
	union {
		arp_report_t *a;
		ip_report_t *i;
		void *ptr;
	} pr_u;

	DBG(M_RPT, "in report_push r_type %d", r_type);

	switch (r_type) {
		case REPORT_TYPE_ARP:

			pr_u.ptr=xmalloc(sizeof(arp_report_t));
			memcpy(pr_u.ptr, (const void *)&r_u.a, sizeof(arp_report_t));
			pr_u.a->doff=0;

			if (s->ss->ret_layers > 0) {
				union {
					uint16_t *len;
					uint8_t *inc;
					void *ptr;
				} pk_u;

				if (p_len < 1) {
					PANIC("saved packet size is incorrect");
				}

				pk_u.ptr=xmalloc(p_len + sizeof(uint16_t));
				*pk_u.len=p_len;
				memcpy(pk_u.inc + sizeof(uint16_t), p_ptr, p_len);
				fifo_push(p_queue, pk_u.ptr);
				DBG(M_RPT, "pushed packet into p_queue");
				pr_u.a->doff=p_len;
			}

			fifo_push(r_queue, pr_u.ptr);
			DBG(M_RPT, "pushed report into r_queue");
			break;

		case REPORT_TYPE_IP:
			pr_u.ptr=xmalloc(sizeof(ip_report_t));
			memcpy(pr_u.ptr, (const void *)&r_u.i, sizeof(ip_report_t));
			pr_u.i->doff=0;

			if (s->ss->ret_layers > 0) {
				union {
					uint16_t *len;
					uint8_t *inc;
					void *ptr;
				} pk_u;

				if (p_len < 1) {
					PANIC("saved packet size is incorrect");
				}

				pk_u.ptr=xmalloc(p_len + sizeof(uint16_t));
				*pk_u.len=p_len;
				memcpy(pk_u.inc + sizeof(uint16_t), p_ptr, p_len);
				fifo_push(p_queue, pk_u.ptr);
				DBG(M_RPT, "pushed packet into p_queue");
				pr_u.i->doff=p_len;
			}

			fifo_push(r_queue, pr_u.ptr);

			DBG(M_RPT, "pushed report into r_queue");
			break;

		default:
			PANIC("unknown report type %d", r_type);
			break;
	}
}

void parse_packet(uint8_t *notused, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	size_t pk_len=0;
	int pk_layer=0;
	extern pcap_dumper_t *pdump;

	if (packet == NULL || phdr == NULL) {
		ERR("%s is null", packet == NULL ? "packet" : "pcap header");
		return;
	}

	/* when you forget to put this here, it makes for really dull pcap log files */
	if (s->pcap_dumpfile) {
		pcap_dump((uint8_t *)pdump, phdr, packet);
	}

	pk_len=phdr->caplen;

	if (pk_len <= s->ss->header_len) {
		ERR("this packet is too short " STFMT ", header length is %u", pk_len, s->ss->header_len);
		return;
	}

	if (ISDBG(M_PKT) || GET_SNIFF()) {
		INF("got packet with length %u (cap %u) with header length at %u", phdr->len, phdr->caplen, s->ss->header_len);
	}

	pk_len -= s->ss->header_len;
	packet += s->ss->header_len;
	pk_layer++;

	switch (s->ss->mode) {
		case MODE_ARPSCAN:
			report_init(REPORT_TYPE_ARP, &phdr->ts);
			packet_init(packet, pk_len);
			decode_arp(packet, pk_len, pk_layer);	/* the pcap filter should be arp only */
			break;

		case MODE_TCPSCAN:
		case MODE_UDPSCAN:
		case MODE_ICMPSCAN:
		case MODE_IPSCAN:
			report_init(REPORT_TYPE_IP, &phdr->ts);
			packet_init(packet, pk_len);
			decode_ip(packet, pk_len, pk_layer);	/* the pcap filter should be ip only */
			break;

	}

	return;
}

static void decode_arp (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myetherarphdr *a;
		const uint8_t *d;
	} a_u;
	uint16_t hwtype=0, opcode=0;

	a_u.d=packet;
	r_u.a.flags=0;

	if (pk_len < sizeof(struct myetherarphdr)) {
		ERR("short arp packet");
		return;
	}

	hwtype=ntohs(a_u.a->hw_type);
	opcode=ntohs(a_u.a->opcode);

	if (a_u.a->protosize != 4 || a_u.a->hwsize != 6) {
		DBG(M_PKT, "arp packet isnt 6:4, giving up");
		return;
	}

	if (opcode != ARPOP_REPLY) {
		return;
	}

	if (memcmp(s->vi[0]->hwaddr, a_u.a->smac, 6) == 0) {
		return; /* we sent this */
	}

	if (ISDBG(M_PKT) || GET_SNIFF()) {
		char srcip[32], srcmac[32];
		struct in_addr ia;

		ia.s_addr=a_u.a->sip;
		sprintf(srcip, "%s", inet_ntoa(ia));
		ia.s_addr=a_u.a->dip;
		sprintf(srcmac, "%s", decode_6mac(a_u.a->smac));

		INF("ARP : hw_type `%s' protocol `%s' hwsize %d protosize %d opcode `%s'",
		str_hwtype(hwtype), str_hwproto(a_u.a->protocol), a_u.a->hwsize, a_u.a->protosize, str_opcode(opcode));
		INF("ARP : SRC HW %s SRC IP -> %s DST HW %s DST IP %s",
		srcmac, srcip, decode_6mac(a_u.a->dmac), inet_ntoa(ia));
	}

	pk_len -= sizeof(struct myetherarphdr);

	memcpy(r_u.a.hwaddr, a_u.a->smac, THE_ONLY_SUPPORTED_HWADDR_LEN);
	memcpy(&r_u.a.ipaddr, &a_u.a->sip, sizeof(r_u.a.ipaddr));

	report_push();

	if (pk_len) {
		/* frame padding ;] */
		pk_layer++;
		packet += sizeof(struct myetherarphdr);
		decode_junk(packet, pk_len, pk_layer);
	}

	return;
}

static void decode_ip  (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myiphdr *i;
		const uint8_t *d;
	} i_u;
	uint16_t fragoff=0, totlen=0, ipid=0, chksum=0, c_chksum=0;
	uint32_t saddr=0, daddr=0;
	size_t opt_len=0;
	int bad_cksum=0;

	i_u.d=packet;
	r_u.i.flags=0;

	if (pk_len < sizeof(struct myiphdr)) {
		ERR("short ip packet");
		return;
	}

	if (i_u.i->ihl < 5) {
		ERR("ihl is less than 5, this packet is likely confused/damaged");
		return;
	}

	ipid=ntohs(i_u.i->id);
	fragoff=ntohs(i_u.i->frag_off);
	totlen=ntohs(i_u.i->tot_len);
	chksum=ntohs(i_u.i->check);
	/* XXX everything expects addresses in network order */
	saddr=i_u.i->saddr;
	daddr=i_u.i->daddr;

	/* precalculated ip-pseudo header for transport layer checksumming */
	ipph.saddr=saddr;
	ipph.daddr=daddr;
	ipph.zero=0;
	ipph.proto=i_u.i->protocol;
	ipph.len=0;

	opt_len=(i_u.i->ihl - (sizeof(struct myiphdr) / 4)) * 4;

	if (fragoff & IP_OFFMASK) {
		ERR("likely bad: (is DF set? perhaps we need it) ignoring fragmented packet");
		return;
	}

	if (totlen > pk_len && pk_layer == 1) {
		/* this packet has an incorrect ip packet length, stop processing */
		ERR("likely bad: packet has incorrect ip length, skipping it [ip total length claims %u and we have " STFMT, totlen, pk_len);
		return;
	}
	else if (pk_layer == 3 && totlen > pk_len) {
		totlen=pk_len;
	}

	if (pk_len > totlen) {
		/*
		 * there is trailing junk past the end of the ip packet, save a pointer to it,
		 * and its length, then update pk_len
		 */
		DBG(M_PKT, "packet has trailing junk, saving a pointer to it and its length " STFMT, pk_len - totlen);
		trailgarbage=packet + totlen;
		trailgarbage_len=pk_len - totlen;
		pk_len=totlen;
	}

	if ((opt_len + sizeof(struct myiphdr)) > pk_len) {
		DBG(M_PKT, "IP options seem to overlap the packet size, truncating and assuming no ip options");
		opt_len=0; /* must be a trick, assume no options then, in case this is a damaged ip header is under a icmp reply */
	}

	if ((c_chksum=do_ipchksum(packet, opt_len + sizeof(struct myiphdr))) != 0) {
		DBG(M_PKT, "bad cksum, ipchksum returned %u", c_chksum);
		bad_cksum=1;
	}

	if (ISDBG(M_PKT) || GET_SNIFF()) {
		char frag_flags[32];
		char src_addr[32], dst_addr[32];
		struct in_addr ia;

		ia.s_addr=saddr;
		sprintf(src_addr, "%s", inet_ntoa(ia));

		ia.s_addr=daddr;
		sprintf(dst_addr, "%s", inet_ntoa(ia));

		CLEAR(frag_flags);
		if (fragoff & IP_DF) {
			strcat(frag_flags, "DF ");
		}
		if (fragoff & IP_MF) {
			strcat(frag_flags, "MF ");
		}
		if (fragoff & IP_RF) {
			strcat(frag_flags, "RF ");
		}

		INF("IP  : ihl %u (opt len " STFMT ") size " STFMT " version %u tos 0x%02x tot_len %u ipid %u frag_off %04x %s",
		i_u.i->ihl, opt_len, pk_len, i_u.i->version, i_u.i->tos, totlen, ipid, fragoff & IP_OFFMASK, frag_flags);
		INF("IP  : ttl %u protocol `%s' chksum 0x%04x%s IP SRC %s IP DST %s",
		i_u.i->ttl, str_ipproto(i_u.i->protocol), chksum, (bad_cksum == 1 ? " [bad cksum]" : " [cksum ok]"), src_addr, dst_addr);
	}

	if (pk_layer == 1) {
		r_u.i.proto=i_u.i->protocol;
		r_u.i.host_addr=saddr;
		r_u.i.trace_addr=saddr;
		r_u.i.send_addr=daddr;
		r_u.i.ttl=i_u.i->ttl;
		if (bad_cksum) {
			r_u.i.flags |= REPORT_BADNETWORK_CKSUM;
		}
	}
	else if (pk_layer == 3) { /* this is a ip header within an icmp header normally */
		/*
		 * this was the _original host_ we sent to according
		 * to the icmp error reflection
		 */
		r_u.i.host_addr=daddr;
	}
	else {
		ERR("decode IP at unknown layer %d", pk_layer);
		return;
	}

	if (opt_len > 0) {
		decode_ipopts(packet + sizeof(struct myiphdr), opt_len);
	}

	pk_len -= sizeof(struct myiphdr) + opt_len;
	packet += sizeof(struct myiphdr) + opt_len;

	if (pk_len) {
		switch (i_u.i->protocol) {
			case IPPROTO_TCP:
				decode_tcp(packet, pk_len, ++pk_layer);
				break;

			case IPPROTO_UDP:
				decode_udp(packet, pk_len, ++pk_layer);
				break;

			case IPPROTO_ICMP:
				decode_icmp(packet, pk_len, ++pk_layer);
				break;

			default:
				ERR("filter is broken?");
				break;
		}
	}

	return;
}

static void decode_tcp (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct mytcphdr *t;
		const uint8_t *d;
	} t_u;
	uint16_t sport=0, dport=0;
	uint32_t seq=0, ackseq=0;
	uint8_t doff=0, res1=0;
	uint16_t window=0, chksum=0, c_chksum=0, urgptr=0;
	size_t data_len=0, tcpopt_len=0;
	int bad_cksum=0;
	union {
		const ip_pseudo_t *ipph_ptr;
		const uint8_t *ptr;
	} ipph_u;
	struct chksumv c[2];

	t_u.d=packet;

	if (pk_layer == 4) { /* this is inside an icmp error reflection, check that */
		if (r_u.i.proto != IPPROTO_ICMP) {
			ERR("FIXME in TCP not inside an ICMP error?");
			return;
		}
		/*
		 * ok so why the special treatment? well the packet may be incomplete, so its ok if we dont have
		 * a full udp header, we really are only looking for the source and dest ports, we _need_ those
		 * everything else is optional at this point
		 */
		if (pk_len < 4) {
			ERR("TCP header too incomplete to get source and dest ports, halting processing");
			return;
		}
		if (pk_len >= 4 && pk_len < sizeof(struct mytcphdr)) {
			/*
			 * this is reversed from a response, the host never responded so flip src/dest ports
			 */
			r_u.i.sport=ntohs(t_u.t->dest);
			r_u.i.dport=ntohs(t_u.t->source);

			return;
		}
	}

	if (pk_len < sizeof(struct mytcphdr)) {
		ERR("short tcp header");
		return;
	}

	sport=ntohs(t_u.t->source);
	dport=ntohs(t_u.t->dest);
	seq=ntohl(t_u.t->seq);
	ackseq=ntohl(t_u.t->ack_seq);
	doff=t_u.t->doff; res1=t_u.t->res1;
	window=ntohs(t_u.t->window);
	chksum=ntohs(t_u.t->check);
	urgptr=ntohs(t_u.t->urg_ptr);

	if (pk_layer == 2) {
		uint32_t eackseq=0, high=0;

		TCPHASHTRACK(eackseq, r_u.i.host_addr, sport, dport, s->ss->syn_key);

		if (GET_LDOCONNECT()) {
			DBG(M_PKT, "window size is %u or whatever", s->ss->window_size);
			high=eackseq + s->ss->window_size;
		}
		else {
			high=eackseq + 2; /* should always be +1, but lets just accept someone who didnt inc th seq */
		}

		if (SEQ_WITHIN(ackseq, eackseq, high)) {
			DBG(M_PKT, "packet within my %08x-%08x window, with %08x expecting %08x", eackseq, high, ackseq, eackseq);
		}
		else if (! GET_SNIFF() && ! GET_IGNORESEQ() && ! (GET_IGNORERSEQ() && t_u.t->rst)) {
			DBG(M_PKT, "not my packet ackseq %08x expecting somewhere around %08x-%08x", ackseq, eackseq, high);
			return;
		}
	} /* layer 3 seq checking */

	if (doff && ((size_t)(doff * 4) > pk_len)) {
		ERR("datalength exceeds capture length, truncating to zero (doff %u bytes pk_len " STFMT ")", doff * 4, pk_len);
		doff=0;
	}

	if (doff && (size_t )(doff * 4) < sizeof(struct mytcphdr)) {
		ERR("doff is too small, increasing to min size and hoping for no tcpoptions");
		doff=sizeof(struct mytcphdr) / 4;
	}

	if (doff) {
		tcpopt_len=((doff * 4) -  sizeof(struct mytcphdr));
		data_len=pk_len - (doff * 4);
	}
	else {
		tcpopt_len=pk_len - sizeof(struct mytcphdr);
		data_len=0;
	}

	ipph_u.ipph_ptr=&ipph;
	/* its not natural to use _this_ size... */
	ipph.len=ntohs(pk_len);

	c[0].len=sizeof(ipph);
	c[0].ptr=ipph_u.ptr;

	c[1].len=pk_len;
	c[1].ptr=packet;

	c_chksum=do_ipchksumv((const struct chksumv *)&c[0], 2);
	if (c_chksum != 0) {
		DBG(M_PKT, "bad tcp checksum, ipchksumv returned 0x%04x", c_chksum);
		bad_cksum=1;
	}

	if (ISDBG(M_PKT) || GET_SNIFF()) {
		char tcpflags[16];

		memset(tcpflags, '-', sizeof(tcpflags));
		tcpflags[8]='\0';
		if (t_u.t->fin) tcpflags[0]='F';
		if (t_u.t->syn) tcpflags[1]='S';
		if (t_u.t->rst) tcpflags[2]='R';
		if (t_u.t->psh) tcpflags[3]='P';
		if (t_u.t->ack) tcpflags[4]='A';
		if (t_u.t->urg) tcpflags[5]='U';
		if (t_u.t->ece) tcpflags[6]='E';
		if (t_u.t->cwr) tcpflags[7]='C';

		INF("TCP : size " STFMT " sport %u dport %u seq 0x%08x ack_seq 0x%08x window %u",
		pk_len, sport, dport, seq, ackseq, window);
		INF("TCP : doff %u res1 %u flags `%s' chksum 0x%04x%s urgptr 0x%04x",
		doff, res1, tcpflags, chksum, (bad_cksum != 0 ? " [bad cksum]" : " [cksum ok]"), urgptr);
		INF("TCP : options length " STFMT " data length " STFMT, tcpopt_len, data_len);
	}

	packet += sizeof(struct mytcphdr);
	pk_len -= sizeof(struct mytcphdr);

	if (tcpopt_len && (ISDBG(M_PKT) || GET_SNIFF())) {
		decode_tcpopts(packet, tcpopt_len);
	}

	if (data_len && (ISDBG(M_PKT) || GET_SNIFF())) {
		INF("TCP : dumping packet data");
		hexdump(packet + tcpopt_len, data_len);
	}

	if (pk_layer == 2) {
		r_u.i.sport=sport;
		r_u.i.dport=dport;
		r_u.i.type=0;

		r_u.i.tseq=seq;
		r_u.i.mseq=ackseq;

		r_u.i.window_size=window;

		if (t_u.t->fin) r_u.i.type |= TH_FIN;
		if (t_u.t->syn) r_u.i.type |= TH_SYN;
		if (t_u.t->rst) r_u.i.type |= TH_RST;
		if (t_u.t->psh) r_u.i.type |= TH_PSH;
		if (t_u.t->ack) r_u.i.type |= TH_ACK;
		if (t_u.t->urg) r_u.i.type |= TH_URG;
		if (t_u.t->ece) r_u.i.type |= TH_ECE;
		if (t_u.t->cwr) r_u.i.type |= TH_CWR;

		r_u.i.subtype=0;

		if (bad_cksum) {
			r_u.i.flags |= REPORT_BADTRANSPORT_CKSUM;
		}

		if (GET_WATCHERRORS() || GET_LDOCONNECT()) {
			report_push();
		}
		else if (t_u.t->syn /* close enough */) {
			report_push();
		}
	}
	else if (pk_layer == 4) {
		r_u.i.sport=dport;
		r_u.i.dport=sport;
		r_u.i.mseq=ackseq;
		r_u.i.tseq=seq;
		r_u.i.window_size=0;
	}
	else {
		ERR("fixme");
		return;
	}

	return;
}

static void decode_udp (const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myudphdr *u;
		const uint8_t *d;
	} u_u;
	uint16_t sport=0, dport=0, len=0, chksum=0, c_chksum=0;
	int bad_cksum=0;
	union {
		const ip_pseudo_t *ipph_ptr;
		const uint8_t *ptr;
	} ipph_u;
	struct chksumv c[2];

	u_u.d=packet;

	if (pk_layer == 4) { /* this is inside an icmp error reflection, check that */
		if (r_u.i.proto != IPPROTO_ICMP) {
			ERR("FIXME in UDP not inside a ICMP error?");
			return;
		}
		/* see TCP comment above about special treatment */
		if (pk_len < 4) {
			ERR("UDP header too short to get source and dest ports");
			return;
		}
		if (pk_len >= 4 && pk_len < sizeof(struct myudphdr)) {
			/* this is reversed from a response, the host never responded so flip src/dest ports */
			r_u.i.sport=ntohs(u_u.u->dest);
			r_u.i.dport=ntohs(u_u.u->source);
			r_u.i.tseq=0;
			r_u.i.mseq=0;

			return;
		}
	}

	if (pk_len < sizeof(struct myudphdr)) {
		ERR("short udp header");
		return;
	}
	sport=ntohs(u_u.u->source);
	dport=ntohs(u_u.u->dest);
	len=ntohs(u_u.u->len);
	chksum=ntohs(u_u.u->check);

	ipph_u.ipph_ptr=&ipph;
	ipph.len=ntohs(pk_len);

	c[0].len=sizeof(ipph);
	c[0].ptr=ipph_u.ptr;

	c[1].len=pk_len;
	c[1].ptr=packet;

	c_chksum=do_ipchksumv((const struct chksumv *)&c[0], 2);
	if (c_chksum != 0) {
		DBG(M_PKT, "bad udp checksum, ipchksumv returned 0x%x", c_chksum);
		bad_cksum=1;
	}

	if (ISDBG(M_PKT) || GET_SNIFF()) {
		INF("UDP : pklen " STFMT " sport %u dport %u len %u checksum %04x%s",
		pk_len, sport, dport, len, chksum, bad_cksum == 0 ? " [bad cksum]" : " [cksum ok]");
	}

	if (pk_layer == 2) {
		r_u.i.sport=sport;
		r_u.i.dport=dport;
		r_u.i.type=0;
		r_u.i.subtype=0;
		r_u.i.tseq=0;
		r_u.i.mseq=0;

		report_push();
        }
	else if (pk_layer == 4) {
		/* this is reversed from a response, the host never responded so flip src/dest ports */
		r_u.i.sport=dport;
		r_u.i.dport=sport;
		r_u.i.tseq=0;
		r_u.i.mseq=0;
	}
	else {
		ERR("FIXME at decode UDP at layer %d", pk_layer);
		return;
	}

	pk_len -= sizeof(struct myudphdr);
	packet += sizeof(struct myudphdr);

	if (pk_len && (ISDBG(M_PKT) || GET_SNIFF())) {
		INF("UDP : dumping UDP payload");
		hexdump(packet, pk_len);
	}

	return;
}

static void decode_icmp(const uint8_t *packet, size_t pk_len, int pk_layer) {
	union {
		const struct myicmphdr *i;
		const uint8_t *d;
	} ic_u; /* ;] */
	uint8_t type=0, code=0;
	uint16_t chksum=0;

	ic_u.d=packet;

	if (pk_len < 4) {
		ERR("short icmp header");
		return;
	}

	type=ic_u.i->type;
	code=ic_u.i->code;
	chksum=ntohs(ic_u.i->checksum);

	if (ISDBG(M_PKT) || GET_SNIFF()) {
		INF("ICMP: type %u code %u chksum %04x%s", type, code, chksum, "[?]");
	}

	if (type == 3 || type == 5 || type == 11) {
		/*
		 * dest unreachable, the packet that generated this error should be after the icmpheader
		 * redirect message, same as with unreachable
		 * time exceeded, same as with above
		 */

		if (pk_len > sizeof(struct myicmphdr)) { /* there _could_ be data there, try to process it */
			const uint8_t *newpacket=NULL;
			size_t newpk_len=0;

			newpacket=packet + sizeof(struct myicmphdr);
			newpk_len=pk_len - sizeof(struct myicmphdr);

			decode_ip(newpacket, newpk_len, (pk_layer + 1));
		}
	}
	else if (type == 0 || type == 8) {
		/* pings ignore */
		DBG(M_PKT, "Ignoring ping request or response");
	}

	if (pk_layer == 2) {
		r_u.i.type=type;
		r_u.i.subtype=code;

		report_push();
	}

	return;
}

static void decode_junk(const uint8_t *packet, size_t pk_len, int pk_layer) {
	if (ISDBG(M_PKT) || GET_SNIFF()) {
		INF("JUNK: dumping trailing junk at end of packet at layer %d length " STFMT, pk_layer, pk_len);
		hexdump(packet, pk_len);
	}
	return;
}

/*
 * misc functions
 */

void decode_ipopts(const uint8_t *data, size_t len) {
/*
(last updated 2001-06-29)

The Internet Protocol (IP) has provision for optional header fields
identified by an option type field.  Options 0 and 1 are exactly one
octet which is their type field.  All other options have their one
octet type field, followed by a one octet length field, followed by
length-2 octets of option data.  The option type field is sub-divided
into a one bit copied flag, a two bit class field, and a five bit
option number.  These taken together form an eight bit value for the
option type field.  IP options are commonly refered to by this value.


Copy Class Number Value Name				Reference
---- ----- ------ ----- ------------------------------- ---------
   0     0      0     0 EOOL   - End of Options List    [RFC791,JBP]
   0     0      1     1 NOP    - No Operation           [RFC791,JBP]
   1     0      2   130 SEC    - Security                  [RFC1108]
   1     0      3   131 LSR    - Loose Source Route     [RFC791,JBP]
   0     2      4    68 TS     - Time Stamp             [RFC791,JBP]
   1     0      5   133 E-SEC  - Extended Security         [RFC1108]
   1     0      6   134 CIPSO  - Commercial Security           [???]
   0     0      7     7 RR     - Record Route           [RFC791,JBP]
   1     0      8   136 SID    - Stream ID              [RFC791,JBP]
   1     0      9   137 SSR    - Strict Source Route    [RFC791,JBP]
   0     0     10    10 ZSU    - Experimental Measurement      [ZSu]
   0     0     11    11 MTUP   - MTU Probe                 [RFC1191]*
   0     0     12    12 MTUR   - MTU Reply                 [RFC1191]*
   1     2     13   205 FINN   - Experimental Flow Control    [Finn]
   1     0     14   142 VISA   - Expermental Access Control [Estrin]
   0     0     15    15 ENCODE - ???                      [VerSteeg]
   1     0     16   144 IMITD  - IMI Traffic Descriptor        [Lee]
   1     0     17   145 EIP    - Extended Internet Protocol[RFC1385]
   0     2     18    82 TR     - Traceroute		   [RFC1393]
   1     0     19   147 ADDEXT - Address Extension    [Ullmann IPv7]	
   1     0     20   148 RTRALT - Router Alert              [RFC2113]
   1     0     21   149 SDB    - Selective Directed Broadcast[Graff]
   1     0     22   150 NSAPA  - NSAP Addresses          [Carpenter]
   1	 0     23   151 DPS    - Dynamic Packet State        [Malis]
   1	 0     24   152 UMP    - Upstream Multicast Pkt. [Farinacci]
*/
	if (ISDBG(M_PKT) || GET_SNIFF()) {
		INF("IPOP: dumping ipoptions");
		hexdump(data, len);
	}
}

void decode_tcpopts(const uint8_t *data, size_t len) {
	const uint8_t *ptr=NULL;
	char optstr[128];
	size_t dataoff=0, optstr_off=0;
	char scratch[32];
	union {
		const uint8_t *ptr;
		const uint16_t *hw;
		const uint32_t *w;
	} w_u, w2_u;

#define OPTSTR_APPEND(x) \
		do { \
			optstr_off += snprintf(&optstr[optstr_off], sizeof(optstr) - (optstr_off + 1), "%s ", (x)); \
		} while(0)

#define OPTSTR_APPENDU(x) \
		do { \
			optstr_off += snprintf(&optstr[optstr_off], sizeof(optstr) - (optstr_off + 1), "? [0x%02x] ", (x)); \
		} while(0)

	memset(optstr, 0, sizeof(optstr));

	for (ptr=data, dataoff=0; dataoff < len; ) {
		switch ((uint8_t )*ptr) {
			case TCPOPT_EOL:
				OPTSTR_APPEND("E");
				DBG(M_PKT, "EOL, halt processing");
				goto done;

			case TCPOPT_NOP:
				OPTSTR_APPEND("N");
				dataoff++; ptr++;
				break;

			case TCPOPT_MAXSEG:
				memset(scratch, 0, sizeof(scratch));
				dataoff++;
				ptr++;
				if (*ptr != 4 || (dataoff + 2) > len) {
					ERR("tcpopt MAXSEG damaged");
					OPTSTR_APPEND("MSS (damaged)");
					goto done;
				}
				ptr++;
				dataoff++;
				w_u.ptr=ptr;
				snprintf(scratch, sizeof(scratch) -1, "MSS%u", ntohs(*w_u.hw));
				OPTSTR_APPEND(scratch);
				ptr += 2;
				dataoff += 2;
				break;

			case TCPOPT_SACK_PERMITTED:
				dataoff++; ptr++;
				if (*ptr != 2) {
					ERR("tcpopt SackOK damaged");
					OPTSTR_APPEND("SackOK (damaged)");
					goto done;
				}
				OPTSTR_APPEND("SackOK");
				dataoff++;
				ptr++;
				break;

			case TCPOPT_TIMESTAMP:
				dataoff++;
				ptr++;
				if (*ptr != 10 || (dataoff + 9) > len) {
					ERR("tcpopt TS damaged");
					OPTSTR_APPEND("TS (damaged)");
					goto done;
				}
				ptr++;
				dataoff++;
				w_u.ptr=ptr;
				w2_u.ptr=(ptr + 4);
				memset(scratch, 0, sizeof(scratch));
				snprintf(scratch, sizeof(scratch) -1, "TS %u:%u", *w_u.w, *w2_u.w);
				ptr += 8;
				dataoff += 8;
				r_u.i.t_tstamp=ntohl(*w_u.w);
				r_u.i.m_tstamp=ntohl(*w2_u.w);
				OPTSTR_APPEND(scratch);
				break;

			case TCPOPT_WINDOW:
				dataoff++;
				ptr++;
				if (*ptr != 3 || (dataoff + 1) > len) {
					ERR("tcpopt window damaged");
					OPTSTR_APPEND("WIN (damaged)");
					goto done;
				}
				ptr++;
				dataoff++;
				memset(scratch, 0, sizeof(scratch));
				snprintf(scratch, sizeof(scratch) -1, "WS %u", (uint8_t)*ptr);
				OPTSTR_APPEND(scratch);
				ptr++;
				dataoff++;
				break;

			default:
				OPTSTR_APPENDU(*ptr);
				goto done;
		}
	}

done:
	if (ISDBG(M_PKT) || GET_SNIFF()) {
		INF("TCPO: `%s'", optstr);
	}

	return;
}
