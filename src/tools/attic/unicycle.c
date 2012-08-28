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

#include <pcap.h>

#include <scan_progs/packets.h>
#include <scan_progs/scanopts.h>
#include <settings.h>
#include <scan_progs/workunits.h>
#include <scan_progs/scan_export.h>

#include <unilib/output.h>
#include <unilib/arch.h>
#include <unilib/xipc.h>
#include <unilib/pcaputil.h>
#include <unilib/xmalloc.h>
#include <unilib/xipc_private.h>
#include <unilib/pktutil.h>

#define FILTER "host 127.0.0.1 and (port 12321 or port 12322 or port 12323) and tcp"

int ident;
const char *ident_name_ptr;
settings_t *s=NULL;
static int header_len=0;
static int verbose=0;

void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);

static struct connection {
	char *name;
	int sport;
	int dport;
} conns[MAX_CONNS];

int main(int argc, char ** argv) {
	char errbuf[PCAP_ERRBUF_SIZE], pfilter[2048];
	pcap_t *pdev=NULL;
	bpf_u_int32 mask=0, net=0;
	struct bpf_program filter;

	ident=IDENT_ANY;
	ident_name_ptr=IDENT_ANY_NAME;

	memset(&conns, 0, sizeof(conns));

	s=(settings_t *)xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));
	s->vi=(interface_info_t **)xmalloc(sizeof(interface_info_t *));
	s->vi[0]=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	memset(s->vi, 0, sizeof(interface_info_t));
	s->ss=(scan_settings_t *)xmalloc(sizeof(scan_settings_t));
	memset(s->ss, 0, sizeof(scan_settings_t));
	s->verbose=3;

	s->_stdout=stdout;
	s->_stderr=stderr;

	if (argc == 2) {
		if (strcmp(argv[1], "-v") == 0) {
			verbose=1;
		}
		else {
			printf("%s: Sniff loopback device and decode ipc messages\n", argv[0]);
			exit(0);
		}
	}

	memset(errbuf, 0, sizeof(errbuf));

	snprintf(pfilter, sizeof(pfilter) -1, "%s", FILTER);

	pcap_lookupnet("lo", &net, &mask, errbuf);

	pdev=pcap_open_live("lo", 16436, 1, 0, errbuf);
	if (pdev == NULL) {
		ERR("error: %s", errbuf);
		exit(1);
	}

	if ((header_len=util_getheadersize(pdev, errbuf)) < 0) {
		ERR("error getting header length: %s", errbuf);
		exit(1);
	}

	pcap_compile(pdev, &filter, pfilter, 0, net);
	pcap_setfilter(pdev, &filter);

	if (util_preparepcap(pdev, errbuf) < 0) {
		ERR("error putting pcap fd into immediate mode: %s", errbuf);
		exit(1);
	}

	pcap_loop(pdev, 0, &process_packet, NULL);

	exit(0);
}

void process_packet(uint8_t *user, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	const struct myiphdr *ip_ptr=NULL;
	const struct mytcphdr *tcp_ptr=NULL;
	const uint8_t *data=NULL;
	size_t hdrlen=0;
	int j=0, j1=0;

	if (packet == NULL) return;

	hdrlen=(header_len + sizeof(struct myiphdr) + sizeof(struct mytcphdr));

	if (phdr->caplen < hdrlen) {
		ERR("Short packet at %d bytes", phdr->caplen);
		return;
	}

	ip_ptr=(const struct myiphdr *)(packet + header_len);
	tcp_ptr=(const struct mytcphdr *)(packet + header_len + sizeof(struct myiphdr));

	if (phdr->caplen > (header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff))) {
		data=(const uint8_t *)(packet + header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff));
	}
	else {
		data=NULL;
	}

	VRB(0, "caplen %d datalen %d "
		"sport %d dport %d doff %d"
		"seq %08x ackseq %08x "
		"window %u checksum %04x urg_ptr %d\n",
		phdr->caplen, (phdr->caplen - (header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff))),
		ntohs(tcp_ptr->source), ntohs(tcp_ptr->dest), tcp_ptr->doff,
		tcp_ptr->seq, tcp_ptr->ack_seq, tcp_ptr->window, tcp_ptr->check,
		tcp_ptr->urg_ptr);

	for (j=0; j < MAX_CONNS ; j++) {
		if (conns[j].sport == ntohs(tcp_ptr->source) && conns[j].dport == ntohs(tcp_ptr->dest)) {
			break;
		}
		if (conns[j].sport == 0) {
			conns[j].sport=ntohs(tcp_ptr->source);
			conns[j].dport=ntohs(tcp_ptr->dest);

			if (conns[j].sport > 7999 && conns[j].sport < 8006) {
				conns[j].name=xstrdup("Master To Drone");
			}
			else if (conns[j].sport > 12320 && conns[j].sport < 12324) {
				conns[j].name=xstrdup("Drone To Master");
			}
			else {
				conns[j].name=xstrdup("Unknown");
			}
			break;
		}
	}


	if (data) {
		union {
			const ipc_msghdr_t *msg;
			const uint8_t *ptr;
		} mm_u;
		union {
			const uint8_t *ptr;
			const void *vp;
			listener_info_t *l;
		} md_u;

		mm_u.ptr=data;

		if (mm_u.msg->header != 0xf0f1f2f3) {
			ERR("BAD IPC PACKET, magic header wrong");
			return;
		}

		if (mm_u.msg->type == MSG_IDENTLISTENER) {
			if (conns[j].name) xfree(conns[j].name);
			conns[j].name=xstrdup("LISTENER To Master");
			for (j1=0 ; j1 < MAX_CONNS ; j1++) {
				if (conns[j1].dport == conns[j].sport && conns[j1].sport == conns[j].dport) {
					if (conns[j1].name) xfree(conns[j1].name);
					conns[j1].name=xstrdup("Master to LISTENER");
				}
			}
		}
		else if (mm_u.msg->type == MSG_IDENTSENDER) {
			if (conns[j].name) xfree(conns[j].name);
			conns[j].name=xstrdup("SENDER To Master");
			for (j1=0 ; j1 < MAX_CONNS ; j1++) {
				if (conns[j1].dport == conns[j].sport && conns[j1].sport == conns[j].dport) {
					if (conns[j1].name) xfree(conns[j1].name);
					conns[j1].name=xstrdup("Master to SENDER");
				}
			}
		}

		MSG(M_INFO, "{%s}\tMessagetype %s status %d len %d", (conns[j].name == NULL ? "Unknown" : conns[j].name), strmsgtype(mm_u.msg->type), mm_u.msg->status, mm_u.msg->len);

		if (mm_u.msg->len > 0) {
			struct in_addr ia1;

			if (mm_u.msg->len != (phdr->caplen - (header_len + sizeof(struct myiphdr) + (4 * tcp_ptr->doff) + sizeof(ipc_msghdr_t)))) {
				MSG(M_ERR, "BAD IPC PACKET!");
				return;
			}
			md_u.ptr=data + sizeof(ipc_msghdr_t);

			switch (mm_u.msg->type) {
				case MSG_WORKUNIT:
					MSG(M_OUT, "WORKUNIT: `%s'", strworkunit(md_u.vp, (size_t )mm_u.msg->len));
					break;
				case MSG_READY:
					if (mm_u.msg->len == sizeof(listener_info_t)) {
						ia1.s_addr=md_u.l->myaddr;
						MSG(M_OUT, "Ready with IP %s HWADDR %s MTU %u", inet_ntoa(ia1), decode_6mac(md_u.l->hwaddr), md_u.l->mtu);
					}
					else {
						MSG(M_OUT, "Unknown ready infomation");
					}
				default:
					break;
			}
		}
	}
	return;
}
