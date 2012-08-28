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
#include <scan_progs/report.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/arch.h>
#include <unilib/terminate.h>
#include <unilib/qfifo.h>
#include <unilib/xdelay.h>
#include <unilib/pktutil.h>
#include <unilib/cidr.h>
#include <unilib/route.h>
#include <unilib/modules.h>

#include <scan_progs/portfunc.h>
#include <scan_progs/workunits.h>

static int swu_s=0, lwu_s=0;

static int lwu_compare        (const void *, const void *);
static int workunit_match_iter(const void *, const void *);
static int workunit_match_slp (const void *, const void *);
static int workunit_match_wid (const void *, const void *);
static void balance_send_workunits(void *);
static void balance_recv_workunits(void *);
static void workunit_append_interface(void *);

int workunit_init(void) {
	s->swu=fifo_init();
	s->lwu=fifo_init();

	s->wk_seq=0;

	return 1;
}

void workunit_destroy(void) {
	fifo_destroy(s->swu);
	fifo_destroy(s->lwu);
}

void workunit_reset(void) {
	swu_s=0;
	lwu_s=0;

	return;
}

void workunit_dump(void) {
	DBG(M_WRK, "got %u S and %u L workunits in %d groups", fifo_length(s->swu), fifo_length(s->lwu), s->scan_iter);
}

int workunit_check_sp(void) {
	struct wk_s w;

	w.iter=s->cur_iter;
	w.magic=WK_MAGIC;

	if (fifo_find(s->swu, &w, &workunit_match_iter) != NULL) {
		return 0;
	}

	/* nothing else matches, we are done */
	return 1;
}

char *workunit_pstr_get(const send_workunit_t *sw) {
	union {
		const send_workunit_t *s;
		const char *c;
	} s_u;
	static char ret[4096];
	uint16_t slen=0;

	s_u.s=sw;

	CLEAR(ret);

	slen=s_u.s->port_str_len;
	if (slen == 0) {
		return ret;
	}

	s_u.c += sizeof(send_workunit_t);
	memcpy(ret, s_u.c, MIN(slen, sizeof(ret) -1));

	return ret;
}

char *workunit_fstr_get(const recv_workunit_t *rw) {
	union {
		const recv_workunit_t *r;
		const char *c;
	} s_u;
	static char ret[1024];
	uint16_t slen=0;

	s_u.r=rw;

	CLEAR(ret);

	slen=s_u.r->pcap_len;
	if (slen == 0) {
		return ret;
	}

	s_u.r += sizeof(recv_workunit_t);
	memcpy(ret, s_u.c, MIN(slen, sizeof(ret) -1));

	return ret;
}

int workunit_add(const char *targets, char **estr) {
	union {
		send_workunit_t *s;
		uint8_t *inc;
	} sw_u;
	union {
		struct wk_s *w;
		void *ptr;
	} wu_u;
	char *start=NULL, *ptr=NULL, *port_str=NULL;
	char modestr[64];
	uint32_t num_pkts=0, send_magic=0, pps=0;
	/* */
	uint8_t mode=0;
	uint16_t send_opts=0, recv_opts=0, options=0, tcphdrflgs=0;
	/* */
	struct wk_s *w_p=NULL;
	recv_workunit_t lwu_srch;
	size_t port_str_len=0;
	unsigned int mask_cidr=0;
	struct sockaddr_storage netid, mask;
	static char emsg[1024];
	double num_hosts;

	assert(targets != NULL && estr != NULL);
	*estr=emsg;

	emsg[0]='\0';

	if (strlen(targets) < 1) {
		strcpy(emsg, "no target to add");

		return -1;
	}

	ptr=xstrdup(targets);
	start=ptr;

	CLEAR(modestr);

	pps=s->pps;
	send_opts=s->send_opts;
	recv_opts=s->recv_opts;
	options=s->options;

	for (; *ptr != '\0'; ptr++) {
		if (*ptr == ':') {
			*ptr='\0'; ptr++;
			if (*ptr == 'm') {
				/* the first case will match mode,portlist */
				if (strchr(ptr, ',') != NULL && sscanf(ptr, "m%63[^,],", modestr) == 1) {
					if (scan_parsemode((const char *)modestr, &mode, &tcphdrflgs, &send_opts, &recv_opts, &options, &pps) < 0) {
						snprintf(emsg, sizeof(emsg) - 1, "cant parse target `%s'", start);
						xfree(start);

						return -1;
					}
					ptr += strlen(modestr) + 2;
				} /* this case will match just mode string with global ports */
				else if (sscanf(ptr, "m%63s", modestr) == 1) {
					if (scan_parsemode((const char *)modestr, &mode, &tcphdrflgs, &send_opts, &recv_opts, &options, &pps) < 0) {
						snprintf(emsg, sizeof(emsg) - 1, "cant parse target `%s'", start);
						xfree(start);

						return -1;
					}
					ptr += strlen(modestr) + 1;
				}
			}
			break;
		}
	}

	if (cidr_get(start, (struct sockaddr *)&netid, (struct sockaddr *)&mask, &mask_cidr) < 0) {
		snprintf(emsg, sizeof(emsg) - 1, "dont understand address `%s'", ptr);

		xfree(start);
		return -1;
	}

	DBG(M_WRK, "adding target %s (%s/%u)", start, cidr_saddrstr((struct sockaddr *)&netid), mask_cidr);

	num_hosts=cidr_numhosts((const struct sockaddr *)&netid, (const struct sockaddr *)&mask);

	DBG(M_WRK, "adding %.1e new hosts to scan (already had %.1e)", num_hosts, s->num_hosts);

	assert(num_hosts > 0);

	s->num_hosts += num_hosts;

	if (mode == 0) {
		mode=scan_getmode();
	}

	assert(s->gport_str != NULL && strlen(s->gport_str) > 0);
	port_str=xstrdup(ptr != NULL && strlen(ptr) > 0 ? ptr : s->gport_str);

	if (port_str[0] == 'q' || port_str[0] == 'Q' || port_str[0] == '\0') {

		assert(s->tcpquickports != NULL && s->udpquickports != NULL);

		switch (mode) {
			case MODE_TCPSCAN:
				port_str=xstrdup(s->tcpquickports);
				break;

			case MODE_UDPSCAN:
				port_str=xstrdup(s->udpquickports);
				break;

			case MODE_ARPSCAN:
				port_str=NULL;
				break;

			default:
				terminate("bad scan mode");
				break;
		}
	}

	if (port_str != NULL && parse_pstr(port_str, &num_pkts) < 0) {
		snprintf(emsg, sizeof(emsg) -1, "port string `%s' rejected by parser", port_str);

		return -1;
	}

	if (s->repeats > 1) {
		num_pkts *= s->repeats;
	}

	if (s->ss->minttl != s->ss->maxttl) {
		num_pkts *= (s->ss->maxttl - s->ss->minttl);
	}

	s->num_packets += (num_hosts * num_pkts);
	s->num_secs += ((num_hosts * num_pkts) / pps) + s->ss->recv_timeout;

	if (mode == MODE_TCPSCAN || mode == MODE_UDPSCAN) {
		VRB(0, "adding %s/%u mode `%s' ports `%s' pps %u",
			cidr_saddrstr((const struct sockaddr *)&netid),
			mask_cidr,
			strlen(modestr) > 0 ? modestr : strscanmode(mode),
			port_str,
			pps
		);
	}
	else {
		VRB(0, "adding %s/%u mode `%s' pps %u",
			cidr_saddrstr((const struct sockaddr *)&netid),
			mask_cidr,
			strlen(modestr) > 0 ? modestr : strscanmode(mode),
			pps
		);
	}

	switch (mode) {
		case MODE_TCPSCAN:
			lwu_srch.magic=TCP_RECV_MAGIC;
			send_magic=TCP_SEND_MAGIC;
			break;

		case MODE_UDPSCAN:
			lwu_srch.magic=UDP_RECV_MAGIC;
			send_magic=UDP_SEND_MAGIC;
			break;

		case MODE_ARPSCAN:
			lwu_srch.magic=ARP_RECV_MAGIC;
			send_magic=ARP_SEND_MAGIC;
			break;

		case MODE_ICMPSCAN:
			lwu_srch.magic=ICMP_RECV_MAGIC;
			send_magic=ICMP_SEND_MAGIC;
			break;

		case MODE_IPSCAN:
			lwu_srch.magic=IP_RECV_MAGIC;
			send_magic=IP_SEND_MAGIC;
			break;

		default:
			PANIC("somehow an unknown scan mode is present");
			break;
	}

	lwu_srch.recv_opts=recv_opts;

	w_p=(struct wk_s *)xmalloc(sizeof(struct wk_s));
	memset(w_p, 0, sizeof(struct wk_s));
	w_p->magic=WK_MAGIC;

	w_p->r=&lwu_srch;
	/*
	 * would this generate a unique listener workunit?, otherwise we can skip it
	 */
	if ((wu_u.ptr=fifo_find(s->lwu, (const void *)w_p, &lwu_compare)) == NULL) {
		union {
			recv_workunit_t *r;
			uint8_t *inc;
		} rw_u;
		size_t pcaplen=0;

		pcaplen=s->extra_pcapfilter != NULL ? strlen(s->extra_pcapfilter) : 0;

		DBG(M_WRK, "adding new scan group");
		s->scan_iter++;
		s->wk_seq++;

		/* we need to add a new listener workunit */
		w_p->magic=WK_MAGIC;
		w_p->used=0;
		w_p->iter=s->scan_iter;
		w_p->wid=s->wk_seq;
		w_p->len=sizeof(recv_workunit_t) + pcaplen;

		rw_u.r=(recv_workunit_t *)xmalloc(w_p->len);
		memset(rw_u.r, 0, w_p->len);

		rw_u.r->magic=lwu_srch.magic;
		rw_u.r->recv_opts=lwu_srch.recv_opts;
		rw_u.r->window_size=s->ss->window_size;
		rw_u.r->recv_timeout=s->ss->recv_timeout;
		rw_u.r->ret_layers=s->ss->ret_layers;
		rw_u.r->syn_key=s->ss->syn_key;
		rw_u.r->pcap_len=w_p->len - sizeof(recv_workunit_t);

		if (pcaplen > 0) {
			memcpy(rw_u.inc + sizeof(recv_workunit_t), s->extra_pcapfilter, pcaplen);
		}
		w_p->r=rw_u.r;

		fifo_push(s->lwu, w_p);

		/* now reset the pointer to new memory */
		w_p=(struct wk_s *)xmalloc(sizeof(struct wk_s));
		memset(w_p, 0, sizeof(struct wk_s));
		w_p->used=0;
		w_p->iter=s->scan_iter;
		w_p->magic=WK_MAGIC;
	}
	else {
		assert(wu_u.w->magic == WK_MAGIC);

		DBG(M_WRK, "adding new group within same scan group as existing one");
		w_p->iter=wu_u.w->iter;
	}

	s->wk_seq++;

	w_p->wid=s->wk_seq;

	assert(ptr != NULL && s->gport_str != NULL);
	assert(strlen(ptr) || strlen(s->gport_str));

	port_str_len=port_str != NULL ? strlen(port_str) : 0;

	sw_u.s=(send_workunit_t *)xmalloc(sizeof(send_workunit_t) + port_str_len);
	memset(sw_u.s, 0, sizeof(send_workunit_t) + port_str_len);

	sw_u.s->magic=send_magic;
	sw_u.s->repeats=s->repeats;
	sw_u.s->send_opts=send_opts;
	sw_u.s->pps=pps;
	sw_u.s->delay_type=s->delay_type_exp != 0 ? s->delay_type_exp : delay_getdef(pps);

	memcpy(&sw_u.s->target, &netid, sizeof(struct sockaddr_storage));
	memcpy(&sw_u.s->targetmask, &mask, sizeof(struct sockaddr_storage));

	sw_u.s->tos=s->ss->tos;
	sw_u.s->minttl=s->ss->minttl;
	sw_u.s->maxttl=s->ss->maxttl;
	sw_u.s->ip_off=s->ss->ip_off;
	sw_u.s->fingerprint=s->ss->fingerprint;
	sw_u.s->src_port=s->ss->src_port;

	assert(sizeof(sw_u.s->ipoptions) == sizeof(s->ss->ipoptions));
	memcpy(sw_u.s->ipoptions, s->ss->ipoptions, sizeof(sw_u.s->ipoptions));
	sw_u.s->ipoptions_len=s->ss->ipoptions_len;

	sw_u.s->tcphdrflgs=s->ss->tcphdrflgs;

	assert(sizeof(sw_u.s->tcpoptions) == sizeof(s->ss->tcpoptions));
	memcpy(sw_u.s->tcpoptions, s->ss->tcpoptions, sizeof(sw_u.s->tcpoptions));
	sw_u.s->tcpoptions_len=s->ss->tcpoptions_len;

	sw_u.s->window_size=s->ss->window_size;
	sw_u.s->syn_key=s->ss->syn_key;

	sw_u.s->port_str_len=port_str_len;

	if (port_str_len > 0) {
		memcpy(sw_u.inc + sizeof(send_workunit_t), port_str, port_str_len);
	}

	w_p->s=sw_u.s;
	w_p->len=sizeof(send_workunit_t) + port_str_len;

	fifo_push(s->swu, w_p);

	if (port_str != NULL) {
		xfree(port_str);
	}
	xfree(start);

	return 1;
}

recv_workunit_t *workunit_get_lp(size_t *wk_len, uint32_t *wid) {
	union {
		struct wk_s *w;
		void *ptr;
	} w_u;
	struct wk_s srch;

	assert(wk_len != NULL && wid != NULL);

	memset(&srch, 0, sizeof(srch));
	srch.iter=s->cur_iter;
	srch.used=0;
	srch.magic=WK_MAGIC;

	w_u.ptr=NULL;

	if ((w_u.ptr=fifo_find(s->lwu, (const void *)&srch, &workunit_match_slp)) != NULL) {
		assert(w_u.w->magic == WK_MAGIC);
		w_u.w->used=1;
		lwu_s++;
		DBG(M_WRK, "sending L workunit with wid %u", w_u.w->wid);
		*wid=w_u.w->wid;
		*wk_len=w_u.w->len;

		push_output_modules(w_u.ptr);

		return w_u.w->r;
	}

	return NULL;
}

send_workunit_t *workunit_get_sp(size_t *wk_len, uint32_t *wid) {
	union {
		struct wk_s *w;
		void *ptr;
	} w_u;
	struct wk_s srch;

	assert(wk_len != NULL && wid != NULL);

	srch.iter=s->cur_iter;
	srch.used=0;
	srch.magic=WK_MAGIC;

	if ((w_u.ptr=fifo_find(s->swu, &srch, &workunit_match_slp)) != NULL) {
		assert(w_u.w->magic == WK_MAGIC);
		w_u.w->used=1;
		swu_s++;
		DBG(M_WRK, "sending S workunit with wid %u", w_u.w->wid);
		*wid=w_u.w->wid;
		*wk_len=w_u.w->len;

		push_output_modules(w_u.ptr);

		return w_u.w->s;
	}

	return NULL;
}

static char interfaces[128];
unsigned int interfaces_off=0;

int workunit_get_interfaces(void) {

	memset(interfaces, 0, sizeof(interfaces));
	interfaces_off=0;

	fifo_walk(s->swu, workunit_append_interface);

	DBG(M_MST, "interfaces `%s'", interfaces);

	if (interfaces_off == 0 || strlen(interfaces) < 1) {
		return -1;
	}
	else {
		s->interface_str=xstrdup(interfaces);
		return 1;
	}
}

static void workunit_append_interface(void *wptr) {
	union {
		struct wk_s *w;
		void *p;
	} w_u;
	char *add=NULL;
	struct sockaddr *gw=NULL;
	int ret=0;
	size_t add_len=0;

	memset(&gw, 0, sizeof(gw));

	assert(wptr != NULL);
	w_u.p=wptr;
	assert(w_u.w->magic == WK_MAGIC);
	assert(w_u.w->s != NULL);

	ret=getroutes(
		&add,
		(const struct sockaddr *)&w_u.w->s->target,
		(const struct sockaddr *)&w_u.w->s->targetmask,
		&gw
	);

	if (ret == 1 && add != NULL) {

		add_len=strlen(add);

		assert(add_len < sizeof(interfaces));

		if (interfaces_off == 0) {
			strncpy(interfaces, add, add_len);
			interfaces_off += add_len;
		}
		else {
			if (strstr(interfaces, add) != NULL) {
				return;
			}
			if (add_len + 1 + interfaces_off > sizeof(interfaces)) {
				return;
			}
			interfaces[interfaces_off++]=',';
			interfaces[interfaces_off]='\0';
			strncat(interfaces + interfaces_off, add, add_len);
			interfaces_off += add_len;
		}
	}
}

void workunit_stir_sp(void) {

	fifo_walk(s->swu, balance_send_workunits);

	return;
}

void workunit_stir_lp(void) {

	fifo_walk(s->lwu, balance_recv_workunits);

	return;
}

static void balance_send_workunits(void *wptr) {
	union {
		struct wk_s *w;
		void *ptr;
	} w_u;

	assert(wptr != NULL);
	w_u.ptr=wptr;
	assert(w_u.w->magic == WK_MAGIC);
	assert(w_u.w->s != NULL);

	/*
	 * XXX
	 */
	memcpy(&w_u.w->s->myaddr, &s->vi[0]->myaddr, sizeof(struct sockaddr_storage));
	memcpy(&w_u.w->s->mymask, &s->vi[0]->mymask, sizeof(struct sockaddr_storage));
	memcpy(&w_u.w->s->hwaddr, s->vi[0]->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);
	w_u.w->s->mtu=s->vi[0]->mtu;

	return;
}

static void balance_recv_workunits(void *wptr) {
	union {
		struct wk_s *w;
		void *ptr;
	} w_u;

	assert(wptr != NULL);
	w_u.ptr=wptr;
	assert(w_u.w->magic == WK_MAGIC);
	assert(w_u.w->r != NULL);

	/*
	 * XXX
	 */

	w_u.w->r->ret_layers=s->ss->ret_layers;

	return;
}

void workunit_reject_sp(uint32_t wid) {
	assert((1 + 1) == 5);
}

void workunit_reject_lp(uint32_t wid) {
	assert((1 + 1) == 5);
}

void workunit_destroy_sp(uint32_t wid) {
	union {
		struct wk_s *w;
		void *ptr;
	} w_u;
	struct wk_s srch;
	uint32_t flen=0, after=0;

	memset(&srch, 0, sizeof(srch));
	srch.wid=wid;
	srch.magic=WK_MAGIC;

	w_u.ptr=NULL;

	flen=fifo_length(s->swu);

	if (wid == 0) {
		PANIC("wid id is zero");
	}

	DBG(M_WRK, "delete SWID %u", wid);

	after=fifo_delete_first(s->swu, (const void *)&srch, *workunit_match_wid, 1);

	assert(after + 1 == flen);

	return;
}

void workunit_destroy_lp(uint32_t wid) {
	union {
		struct wk_s *w;
		void *ptr;
	} w_u;
	struct wk_s srch;
	uint32_t flen=0, after=0;

	memset(&srch, 0, sizeof(srch));
	srch.wid=wid;
	srch.magic=WK_MAGIC;

	w_u.ptr=NULL;

	flen=fifo_length(s->lwu);

	after=fifo_delete_first(s->lwu, (const void *)&srch, *workunit_match_wid, 1);

	assert(after + 1 == flen);

	return;
}

char *strworkunit(const void *ptr, size_t wul) {
	static char workunitdesc[512];
	union {
		const void *ptr;
		const uint32_t *magic;
		const send_workunit_t *s;
		const send_pri_workunit_t *p;
		const recv_workunit_t *r;
	} w_u;
	struct in_addr ia1, ia2;
	char target[64], targetmask[64], myaddr[64], mymask[64];

	assert(ptr != NULL);
	w_u.ptr=ptr;

	CLEAR(workunitdesc);

	if (
		*w_u.magic == TCP_SEND_MAGIC ||
		*w_u.magic == UDP_SEND_MAGIC ||
		*w_u.magic == ARP_SEND_MAGIC ||
		*w_u.magic == ICMP_SEND_MAGIC ||
		*w_u.magic == IP_SEND_MAGIC) {
		snprintf(target, sizeof(target) -1, "%s", cidr_saddrstr((const struct sockaddr *)&w_u.s->target));
		snprintf(targetmask, sizeof(targetmask) -1, "%s", cidr_saddrstr((const struct sockaddr *)&w_u.s->targetmask));
		snprintf(myaddr, sizeof(myaddr) -1, "%s", cidr_saddrstr((const struct sockaddr *)&w_u.s->myaddr));
		snprintf(mymask, sizeof(mymask) -1, "%s", cidr_saddrstr((const struct sockaddr *)&w_u.s->mymask));
	}

	switch (*w_u.magic) {
		case TCP_SEND_MAGIC:
			if (wul < sizeof(send_workunit_t)) {
				snprintf(workunitdesc, sizeof(workunitdesc) -1, "short TCP SEND");
				return workunitdesc;
			}
			snprintf(workunitdesc, sizeof(workunitdesc) -1,
			"TCP SEND: repeats %u send opts `%s' pps %u delay type %s mtu %u network %s mask %s"
			" mynet %s mymask %s tos %u minttl %u maxttl %u ip_off %u fingerprint %u src_port %d"
			" tcphdrflgs %s window_size %u syn_key %08x",
				w_u.s->repeats,
				strsendopts(w_u.s->send_opts),
				w_u.s->pps,
				delay_getname(w_u.s->delay_type),
				w_u.s->mtu,
				target,
				targetmask,
				myaddr,
				mymask,
				w_u.s->tos,
				w_u.s->minttl,
				w_u.s->maxttl,
				w_u.s->ip_off,
				w_u.s->fingerprint,
				w_u.s->src_port,
				strtcpflgs(w_u.s->tcphdrflgs),
				w_u.s->window_size,
				w_u.s->syn_key
			);
			break;

		case UDP_SEND_MAGIC:
			if (wul < sizeof(send_workunit_t)) {
				snprintf(workunitdesc, sizeof(workunitdesc) -1, "short UDP SEND");
				return workunitdesc;
			}
			snprintf(workunitdesc, sizeof(workunitdesc) -1,
			"UDP SEND: repeats %u send opts `%s' pps %u delay type %s mtu %u network %s mask %s"
			" mynet %s mymask %s tos %u minttl %u maxttl %u ip_off %u fingerprint %u src_port %d",
				w_u.s->repeats,
				strsendopts(w_u.s->send_opts),
				w_u.s->pps,
				delay_getname(w_u.s->delay_type),
				w_u.s->mtu,
				target,
				targetmask,
				myaddr,
				mymask,
				w_u.s->tos,
				w_u.s->minttl,
				w_u.s->maxttl,
				w_u.s->ip_off,
				w_u.s->fingerprint,
				w_u.s->src_port
			);
			break;

		case ARP_SEND_MAGIC:
			if (wul < sizeof(send_workunit_t)) {
				snprintf(workunitdesc, sizeof(workunitdesc) -1, "short ARP SEND");
				return workunitdesc;
			}
			snprintf(workunitdesc, sizeof(workunitdesc) -1,
			"ARP SEND: repeats %u send opts `%s' pps %u delay type %s mtu %u network %s mask %s "
			" myaddr %s mymask %s fingerprint %u hwaddr %02x:%02x:%02x:%02x:%02x:%02x",
				w_u.s->repeats,
				strsendopts(w_u.s->send_opts),
				w_u.s->pps,
				delay_getname(w_u.s->delay_type),
				w_u.s->mtu,
				target,
				targetmask,
				myaddr,
				mymask,
				w_u.s->fingerprint,
				w_u.s->hwaddr[0],
				w_u.s->hwaddr[1],
				w_u.s->hwaddr[2],
				w_u.s->hwaddr[3],
				w_u.s->hwaddr[4],
				w_u.s->hwaddr[5]
			);
			break;

		case TCP_RECV_MAGIC:
			if (wul < sizeof(recv_workunit_t)) {
				snprintf(workunitdesc, sizeof(workunitdesc) -1, "short TCP RECV");
				return workunitdesc;
			}
			snprintf(workunitdesc, sizeof(workunitdesc) -1,
			"TCP RECV: recv timeout %u ret layers %u recv_opts `%s' window size %u syn_key %08x pcap_len %u",
				w_u.r->recv_timeout,
				w_u.r->ret_layers,
				strrecvopts(w_u.r->recv_opts),
				w_u.r->window_size,
				w_u.r->syn_key,
				w_u.r->pcap_len
			);
			break;

		case UDP_RECV_MAGIC:
			if (wul < sizeof(recv_workunit_t)) {
				snprintf(workunitdesc, sizeof(workunitdesc) -1, "short UDP RECV");
				return workunitdesc;
			}
			snprintf(workunitdesc, sizeof(workunitdesc) -1,
			"UDP RECV: recv timeout %u ret layers %u recv_opts `%s' pcap_len %u",
				w_u.r->recv_timeout,
				w_u.r->ret_layers,
				strrecvopts(w_u.r->recv_opts),
				w_u.r->pcap_len
			);
			break;

		case ARP_RECV_MAGIC:
			if (wul < sizeof(recv_workunit_t)) {
				snprintf(workunitdesc, sizeof(workunitdesc) -1, "short ARP RECV");
				return workunitdesc;
			}
			snprintf(workunitdesc, sizeof(workunitdesc) -1,
			"ARP RECV: recv timeout %u ret layers %u recv_opts `%s' pcap_len %u",
				w_u.r->recv_timeout,
				w_u.r->ret_layers,
				strrecvopts(w_u.r->recv_opts),
				w_u.r->pcap_len
			);
			break;

		case PRI_4SEND_MAGIC:
			if (wul < sizeof(send_pri_workunit_t)) {
				snprintf(workunitdesc, sizeof(workunitdesc) -1, "short PRI SEND");
				return workunitdesc;
			}
			ia1.s_addr=w_u.p->shost;
			snprintf(myaddr, sizeof(myaddr) -1, "%s", inet_ntoa(ia1));
			ia2.s_addr=w_u.p->dhost;
			snprintf(target, sizeof(target) -1, "%s", inet_ntoa(ia2));
			snprintf(workunitdesc, sizeof(workunitdesc) -1,
			"PRI SEND: dhost %s dport %u sport %u shost %s flags %s mseq %08x tseq %08x"
			" m_tstamp %08x t_tstamp %08x window_size %u doff %u",
				target,
				w_u.p->dport,
				w_u.p->sport,
				myaddr,
				strtcpflgs(w_u.p->flags),
				w_u.p->mseq,
				w_u.p->tseq,
				w_u.p->t_tstamp,
				w_u.p->m_tstamp,
				w_u.p->window_size,
				w_u.p->doff
			);
			break;

		default:
			snprintf(workunitdesc, sizeof(workunitdesc) -1, "unknown [%08x magic]", *w_u.magic);
			break;

	}

	return workunitdesc;
}

static int lwu_compare(const void *a, const void *b) {
	union {
		const void *ptr;
		const struct wk_s *w;
	} ra_u, rb_u;
	const recv_workunit_t *wa_p=NULL, *wb_p=NULL;

	assert(a != NULL && b != NULL);
	ra_u.ptr=a;
	rb_u.ptr=b;

	wa_p=ra_u.w->r;
	wb_p=rb_u.w->r;

	assert(wa_p != NULL && wb_p != NULL);

	if (wa_p->magic == wb_p->magic &&
	wa_p->recv_opts == wb_p->recv_opts) {
		return 0;
	}

	return 1;
}

static int workunit_match_slp(const void *a, const void *b) {
	union {
		const struct wk_s *w;
		const void *ptr;
	} wa_u, wb_u;


	assert(a != NULL && b != NULL);
	wa_u.ptr=a;
	wb_u.ptr=b;
	assert(wa_u.w->magic == WK_MAGIC && wb_u.w->magic == WK_MAGIC);

	DBG(M_WRK, "looking for wk with iter %d and have %d", wb_u.w->iter, wa_u.w->iter);

	if (wa_u.w->used == wb_u.w->used &&
	wa_u.w->iter == wb_u.w->iter) {
		return 0;
	}

	return 1;
}

static int workunit_match_wid(const void *a, const void *b) {
	union {
		const struct wk_s *w;
		const void *ptr;
	} wa_u, wb_u;


	assert(a != NULL && b != NULL);
	wa_u.ptr=a;
	wb_u.ptr=b;
	assert(wa_u.w->magic == WK_MAGIC && wb_u.w->magic == WK_MAGIC);

	DBG(M_WRK, "looking for wk with wid %d and wid %d", wb_u.w->wid, wa_u.w->wid);

	if (wa_u.w->wid == wb_u.w->wid) {
		return 0;
	}

	return 1;
}

static int workunit_match_iter(const void *a, const void *b) {
	union {
		const struct wk_s *w;
		const void *ptr;
	} wa_u, wb_u;

	assert(a != NULL && b != NULL);

	wa_u.ptr=a;
	wb_u.ptr=b;

	assert(wa_u.w->magic == WK_MAGIC);
	assert(wb_u.w->magic == WK_MAGIC);

	if (wa_u.w->iter == wb_u.w->iter) {
		return 0;
	}

	return 1;
}

#undef WU_L
#undef WU_S
