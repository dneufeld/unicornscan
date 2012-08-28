/**********************************************************************
 * Copyright (C) 2004-2006 (Jack Louis) <jack@rapturesecurity.org>    *
 *                                                                    *
 * there should be an infomercial for this file                       *
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
#include <scan_progs/packet_slice.h>

static void slice_arp    (const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);
static void slice_eth    (const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);
static void slice_ip     (const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);
static void slice_tcp    (const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);
static void slice_udp    (const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);
static void slice_icmp   (const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);
static void slice_payload(const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);
static void slice_junk   (const uint8_t * /* packet */, size_t /* pk_len */, packetlayers_t *);

/* tag and slice layer on past the app layer */
static const uint8_t *trailgarbage_ptr=NULL;
static size_t trailgarbage_len=0;

static size_t _plz_sz=0 /* sizeof array */, _plz_off=0 /* active array index */;
static int pk_layer=0;

#define INCR_PKL() _plz_off++; \
	if (_plz_off > _plz_sz) { \
		ERR("packet has too many layers"); \
		return; \
	}; \
	++plz;

#define STEP_FORWARD(x) \
	if (pk_len < (x)) { \
		ERR("internal error slicing packet, want to advance " STFMT " but only have " STFMT, (x), pk_len); \
		return; \
	} \
	pk_len -= (x); \
	packet += (x);

size_t packet_slice(const uint8_t *packet, size_t pk_len, packetlayers_t *plz, size_t plz_sz, int pk_start) {

	if (plz == NULL || packet == NULL) return 0;
	if (plz_sz < 1) return 0;

	trailgarbage_ptr=NULL;
	trailgarbage_len=0;

	_plz_sz=plz_sz;
	_plz_off=0;

	pk_layer=0;
	/* clear out the memory passed to use cause otherwise it would contain stray pointers */
	memset(plz, 0, sizeof(packetlayers_t) * plz_sz);

	switch (pk_start) {
		case PKLTYPE_IP:
			slice_ip(packet, pk_len, plz);
			break;
		case PKLTYPE_ETH:
			slice_eth(packet, pk_len, plz);
			break;
		default:
			return 0;
	}

/*
	if (trailgarbage_len > 0 && trailgarbage_ptr != NULL) {
		slice_junk(trailgarbage_ptr, trailgarbage_len, plz);
		if (ISDBG(M_PKT)) {
			DBG(M_PKT, "dumping crap at %p length " STFMT, trailgarbage_ptr, trailgarbage_len);
			hexdump(trailgarbage_ptr, trailgarbage_len);
		}
	}
*/

	return _plz_off;
}

static void slice_eth(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	/* fun with ethernet and no indication of header length, film at 11:00 */
	union {
		const struct my6etherheader *e;
		const uint8_t *d;
	} i_u;

	assert(plz != NULL);
	assert(packet != NULL);

	i_u.d=packet;

	if (pk_len < sizeof(struct my6etherheader)) {
		DBG(M_PKT, "Short ethernet6 packet");
		return;
	}

	plz->ptr=packet;
	plz->type=PKLTYPE_ETH;
	plz->stat=0;
	plz->len=sizeof(struct my6etherheader);

	INCR_PKL();
	STEP_FORWARD(sizeof(struct my6etherheader));

	switch (ntohs(i_u.e->ether_type)) {
		case ETHERTYPE_IP:
			slice_ip(packet, pk_len, plz);
			break;
		case ETHERTYPE_ARP:
			slice_arp(packet, pk_len, plz);
			break;
		default:
			ERR("unsupp ether protocol %04x!", ntohs(i_u.e->ether_type));
			break;
	}

	return;
}

static void slice_arp(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	PANIC("N/I");
}

static void slice_ip(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	union {
		const struct myiphdr *i;
		const uint8_t *d;
	} i_u;
	size_t opt_len=0;
	uint16_t tot_len=0;

	assert(plz != NULL);
	assert(packet != NULL);

	i_u.d=packet;

	if (pk_len < sizeof(struct myiphdr)) {
		DBG(M_PKT, "Short IP header");
		return;
	}

	plz->ptr=packet;
	plz->type=PKLTYPE_IP;
	plz->stat=0;
	plz->len=sizeof(struct myiphdr);

	if (i_u.i->ihl < 5) {
		DBG(M_PKT, "ip header claims too short length, halting slice (this shouldnt normally happen)");
		plz->stat |= PKLSTAT_DMGED|PKLSTAT_LAST;
		return;
	}

	if (ntohs(i_u.i->frag_off) & IP_OFFMASK) {
		plz->stat |= PKLSTAT_UNSUP|PKLSTAT_LAST;
		return;
	}

	tot_len=ntohs(i_u.i->tot_len);

	if (tot_len > pk_len) {
		plz->stat |= PKLSTAT_DMGED;
		/* Truncate now */
		tot_len=pk_len;
	}
	else if (pk_len > tot_len) {
		trailgarbage_len=pk_len - tot_len;
		trailgarbage_ptr=packet +  tot_len;
		if (ISDBG(M_PKT)) {
			DBG(M_PKT, "trailgarbage at %p length " STFMT, trailgarbage_ptr, trailgarbage_len);
			hexdump(trailgarbage_ptr, trailgarbage_len);
		}
	}

	DBG(M_PKT, "IP Packet length total %u packet cap len " STFMT, ntohs(i_u.i->tot_len), pk_len);

	opt_len=(i_u.i->ihl - (sizeof(struct myiphdr) / 4)) * 4;

	if (opt_len + sizeof(struct myiphdr) > pk_len) {
		plz->stat |= PKLSTAT_DMGED;
		opt_len=0;
	}

	INCR_PKL();
	STEP_FORWARD(sizeof(struct myiphdr));

	if (opt_len) {
		plz->type=PKLTYPE_IPO;
		plz->ptr=packet;
		plz->len=opt_len;
		plz->stat=0;

		INCR_PKL();
		STEP_FORWARD(opt_len);
	}

	switch (i_u.i->protocol) {
		case IPPROTO_TCP:
			slice_tcp(packet, pk_len - trailgarbage_len, plz);
			break;
		case IPPROTO_UDP:
			slice_udp(packet, pk_len - trailgarbage_len, plz);
			break;
		case IPPROTO_ICMP:
			slice_icmp(packet, pk_len - trailgarbage_len, plz);
			break;
		default:
			DBG(M_PKT, "call for a refund! unknown IP proto %u", i_u.i->protocol);
			break;
	}

	return;
}

static void slice_tcp(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	union {
		const struct mytcphdr *t;
		const uint8_t *ptr;
	} p_u;
	uint8_t doff=0;
	size_t data_len=0, tcpopt_len=0;

	p_u.ptr=packet;

	if (pk_len < sizeof(struct mytcphdr)) {
		DBG(M_PKT, "short tcp header");
		return;
	}

	plz->type=PKLTYPE_TCP;
	plz->ptr=packet;
	plz->len=sizeof(struct mytcphdr);

	doff=p_u.t->doff;

	if (doff > 0 && ((size_t)(doff * 4) > pk_len)) {
		DBG(M_PKT, "datalength exceeds capture length, truncating to zero (doff %u bytes pk_len " STFMT ")", doff * 4, pk_len);
		plz->stat |= PKLSTAT_DMGED|PKLSTAT_TRUNC;
		doff=0;
	}

	if (doff > 0 && (size_t )(doff * 4) < sizeof(struct mytcphdr)) {
		DBG(M_PKT, "doff is too small, increasing to min size and hoping for no tcpoptions");
		plz->stat |= PKLSTAT_DMGED;
		doff=sizeof(struct mytcphdr) / 4;
	}

	if (doff > 0) {
		tcpopt_len=((doff * 4) -  sizeof(struct mytcphdr));
		data_len=pk_len - (doff * 4);
	}
	else {
		tcpopt_len=pk_len - sizeof(struct mytcphdr);
		data_len=0;
	}

	INCR_PKL();
	STEP_FORWARD(sizeof(struct mytcphdr));

	if (tcpopt_len) {
		plz->type=PKLTYPE_TCPOP;
		plz->ptr=packet;
		plz->len=tcpopt_len;
		plz->stat=0;

		INCR_PKL();
		STEP_FORWARD(tcpopt_len);
	}

	if (pk_len) {
		DBG(M_PKT, "data off %u and pk_len " STFMT, doff, pk_len);
		slice_payload(packet, pk_len, plz);
	}

	return;
}

static void slice_udp(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	union {
		const struct myudphdr *u;
		const uint8_t *ptr;
	} p_u;
	uint16_t len=0;

	assert(packet != NULL); assert(plz != NULL);

	if (pk_len < sizeof(struct myudphdr)) {
		DBG(M_PKT, "short udp header");
		return;
	}

	p_u.ptr=packet;

	len=ntohs(p_u.u->len);

	plz->type=PKLTYPE_UDP;
	plz->stat=0;
	plz->len=sizeof(struct myudphdr);
	plz->ptr=packet;
	if (len > pk_len) {
		plz->stat=PKLSTAT_DMGED;
		INCR_PKL();
		STEP_FORWARD(sizeof(struct myudphdr));
		slice_payload(packet, pk_len, plz);
	}
	else if (len < pk_len) {
		INCR_PKL();
		STEP_FORWARD(sizeof(struct myudphdr));
		slice_payload(packet, len, plz);
		slice_junk(packet, pk_len, plz);
	}
	else {
		INCR_PKL();
		STEP_FORWARD(sizeof(struct myudphdr));
		slice_payload(packet, pk_len, plz);
	}

	return;
}

static void slice_icmp(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	ERR("slice icmp");
	return;
}

static void slice_payload(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	assert(plz != NULL); assert(packet != NULL);

	if (pk_len) {
		plz->type=PKLTYPE_PAYLOAD;
		plz->ptr=packet;
		plz->len=pk_len;
		INCR_PKL();
		STEP_FORWARD(pk_len);
	}

	return;
}

static void slice_junk(const uint8_t *packet, size_t pk_len, packetlayers_t *plz) {
	assert(plz != NULL); assert(packet != NULL);

	if (pk_len) {
		plz->type=PKLTYPE_JUNK;
		plz->ptr=packet;
		plz->len=pk_len;
		INCR_PKL();
		STEP_FORWARD(pk_len);
	}

	return;
}

char *strpkstat(int pstat) {
	static char desc[128];
	unsigned int doff=0;
	int sret=0;

#define APPEND(x) \
	if (doff + 2 < sizeof(desc)) { \
		if (doff > 0) { \
			desc[doff++]=' '; \
		}  \
		sret=snprintf(desc + doff, sizeof(desc) - doff, "%s", (x)); \
		if (sret < 0) { \
			ERR("snprintf fails, weird"); \
		} \
		else { \
			assert(doff + sret < sizeof(desc)); \
			doff += sret; \
		} \
	} \

	if (pstat & PKLSTAT_DMGED) {
		APPEND("damaged");
	}

	if (pstat & PKLSTAT_TRUNC) {
		APPEND("truncated");
	}

	if (pstat & PKLSTAT_LAST) {
		APPEND("last layer");
	}

	if (pstat & PKLSTAT_UNSUP) {
		APPEND("unsupported");
	}

	if (pstat & ~(PKLSTAT_DMGED|PKLSTAT_TRUNC|PKLSTAT_LAST|PKLSTAT_UNSUP)) {
		APPEND("unknown");
	}

	return desc;
}

char *strpklayer(int pklyr) {
	static char desc[32];

	switch (pklyr) {
		case PKLTYPE_ETH:
			strcpy(desc, "Ethernet");
			break;

		case PKLTYPE_ARP:
			strcpy(desc, "ARP");
			break;

		case PKLTYPE_IP:
			strcpy(desc, "IP");
			break;

		case PKLTYPE_IPO:
			strcpy(desc, "IP Options");
			break;

		case PKLTYPE_UDP:
			strcpy(desc, "UDP");
			break;

		case PKLTYPE_TCP:
			strcpy(desc, "TCP");
			break;

		case PKLTYPE_TCPOP:
			strcpy(desc, "TCPOPS");
			break;

		case PKLTYPE_ICMP:
			strcpy(desc, "ICMP");
			break;

		case PKLTYPE_PAYLOAD:
			strcpy(desc, "payload");
			break;

		case PKLTYPE_JUNK:
			strcpy(desc, "junk");
			break;

		default:
			sprintf(desc, "unknown[%d]", pklyr);
			break;
	}

	return desc;
}
