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

#include <scan_progs/packets.h>
#include <scan_progs/report.h>
#include <scan_progs/portfunc.h>
#include <scan_progs/connect.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/modules.h>
#include <unilib/qfifo.h>
#include <unilib/rbtree.h>
#include <unilib/pktutil.h>
#include <unilib/standard_dns.h>

#include <scan_progs/master.h>

#ifdef HAVE_LIBGEOIP
#include <GeoIP.h>

static GeoIP *gi=NULL;

#endif

static void *report_t=NULL;
static int do_report_nodefunc(uint64_t, void *, void *);
static void clean_report_extra(void *);
static char *get_report_extra(ip_report_t *);
static char *fmtcat_ip4addr(int /* dodns */, uint32_t /* addr */);
static char *fmtcat(const char * /* format string */, const void * /* report item */);
static char *strresptype(const ip_report_t *);
static const char *ipproto_tostr(int /* proto */);

static uint64_t get_ipreport_key(uint32_t /* dhost */, uint16_t /* dport */, uint32_t /* shost */);
static uint64_t get_arpreport_key(uint32_t /* dhost */, uint8_t * /* 6 hwaddr */);

static void display_report(void *);

static int port_open  (uint8_t /* proto */, uint16_t /* type */, uint16_t /* subtype */);
static int port_closed(uint8_t /* proto */, uint16_t /* type */, uint16_t /* subtype */);

void report_init(void) {

	report_t=rbinit(123);

#ifdef HAVE_LIBGEOIP
	gi=GeoIP_open(CONF_DIR "/GeoIP.dat", GEOIP_MEMORY_CACHE);
	if (gi == NULL) {
		ERR("error opening geoip database `%s/%s': %s", CONF_DIR, "/GeoIP.dat", strerror(errno));
	}

#endif

	return;
}

void report_do(void) {

#ifdef HAVE_LIBGEOIP
#endif

	DBG(M_RPT, "formats are ip `%s' imip `%s' arp `%s' imarp `%s', you should see %u results",
		s->ip_report_fmt,
		s->ip_imreport_fmt,
		s->arp_report_fmt,
		s->arp_imreport_fmt,
		rbsize(report_t)
	);

	rbwalk(report_t, do_report_nodefunc, 1, NULL);

	return;
}

void report_destroy(void) {

	/* XXX
	 * rbdestroy(report_t);
	 */

	report_t=NULL;

#ifdef HAVE_LIBGEOIP
	if (gi != NULL) {
		GeoIP_delete(gi);
	}
#endif

	return;
}

int report_add(void *o, size_t o_len) {
	union {
		void *ptr;
		arp_report_t *a;
		ip_report_t *i;
		uint32_t *magic;
	} o_u; /* output union */
	union {
		void *ptr;
		arp_report_t *a;
		ip_report_t *i;
	} oc_u; /* output COPY union, used for inserting */
	struct in_addr ia;
	uint64_t rkey=0;
	void *dummy=NULL;
	char *line=NULL;

	o_u.ptr=o;

	if (report_t == NULL) {
		PANIC("cannot add to NULL report structure");
	}

	if (*o_u.magic == IP_REPORT_MAGIC) {

		ia.s_addr=o_u.i->host_addr;

		rkey=get_ipreport_key(o_u.i->host_addr, o_u.i->sport, o_u.i->send_addr);

		if (port_open(o_u.i->proto, o_u.i->type, o_u.i->subtype)) {

			if (rbfind(report_t, rkey, &dummy) != 1) {

				oc_u.ptr=xmalloc(o_len);
				memcpy(oc_u.ptr, o_u.ptr, o_len);
				rbinsert(report_t, rkey, oc_u.ptr);

				if (GET_IMMEDIATE()) {
					line=fmtcat(s->ip_imreport_fmt, o_u.i);
					if (line != NULL) {
						OUT("%s", line);
						xfree(line);
					}
				}
			}
			else if (GET_PROCDUPS()) {
				union {
					void *p;
					ip_report_t *r;
				} r_u;
				ip_report_t *walk=NULL;

				r_u.p=dummy;

				for (walk=r_u.r; walk->next != NULL; walk=walk->next) {
					;
				}
				walk->next=(ip_report_t *)xmalloc(o_len);
				memset(walk->next, 0, o_len);
				walk=walk->next;
				memcpy(walk, o_u.ptr, o_len);
				walk->next=NULL;		/* just to be sure */

				if (GET_IMMEDIATE()) {
					line=fmtcat(s->ip_imreport_fmt, o_u.i);
					if (line != NULL) {
						OUT("%s", line);
						xfree(line);
					}
				}
			}
			else {
				DBG(M_RPT, "ignoring dup port open on %s:%d", inet_ntoa(ia), o_u.i->sport);
			}
		}
		else if (GET_PROCERRORS()) {

			if (rbfind(report_t, rkey, &dummy) != 1) {

				oc_u.ptr=xmalloc(o_len);
				memcpy(oc_u.ptr, o_u.ptr, o_len);
				rbinsert(report_t, rkey, oc_u.ptr);

				if (GET_IMMEDIATE()) {
					line=fmtcat(s->ip_imreport_fmt, o_u.i);
					if (line != NULL) {
						OUT("%s", line);
						xfree(line);
					}
				}
			}
			else if (GET_PROCDUPS()) {
				union {
					void *p;
					ip_report_t *r;
				} r_u;
				ip_report_t *walk=NULL;

				r_u.p=dummy;

				for (walk=r_u.r; walk->next != NULL; walk=walk->next) {
					;
				}
				walk->next=(ip_report_t *)xmalloc(o_len);
				memset(walk->next, 0, o_len);
				walk=walk->next;
				memcpy(walk, o_u.ptr, o_len);
				walk->next=NULL;		/* just to be sure */

				if (GET_IMMEDIATE()) {
					line=fmtcat(s->ip_imreport_fmt, o_u.i);
					if (line != NULL) {
						OUT("%s", line);
						xfree(line);
					}
				}
			}
			else {
				DBG(M_RPT, "ignoring dup error on %s:%d", inet_ntoa(ia), o_u.i->sport);
			}
		}
	} /* IP report */
	else if (*o_u.magic == ARP_REPORT_MAGIC) {
		rkey=get_arpreport_key(o_u.a->ipaddr, o_u.a->hwaddr);

		if (rbfind(report_t, rkey, &dummy) != 1) {

			oc_u.ptr=xmalloc(o_len);
			memcpy(oc_u.ptr, o_u.ptr, o_len);
			rbinsert(report_t, rkey, oc_u.ptr);

			if (GET_IMMEDIATE()) {
				line=fmtcat(s->arp_imreport_fmt, o_u.a);
				if (line != NULL) {
					OUT("%s", line);
					xfree(line);
				}
			}
		}
		else if (GET_PROCDUPS()) {
			ERR("arp duplicates not yet implemented");
			SET_PROCDUPS(0);
		}
	}
	else {
		ERR("unknown report format %08x", *o_u.magic);
		return -1;
	}

	return 1;
}

static void display_report(void *p) {
	union {
		void *p;
		arp_report_t *a;
		ip_report_t *i;
		uint32_t *magic;
	} r_u;
	char *extra=NULL, *line=NULL, *fmt=NULL;

	if (p == NULL) {
		PANIC("NULL ip report");
	}

	r_u.p=p;

	if (*r_u.magic == IP_REPORT_MAGIC) {
		extra=get_report_extra(r_u.i);
		fmt=s->ip_report_fmt;
	}
	else if (*r_u.magic == ARP_REPORT_MAGIC) {
		fmt=s->arp_report_fmt;
	}
	else {
		ERR("unknown report format %08x", *r_u.magic);
		return;
	}

	line=fmtcat(fmt, p);
	if (line != NULL) {
		OUT("%s %s", line, extra != NULL ? extra : "");
		xfree(line);
	}

	return;
}

static int do_report_nodefunc(uint64_t rkey, void *ptr, void *cbdata) {
	union {
		void *ptr;
		ip_report_t *ir;
		arp_report_t *ar;
		uint32_t *magic;
	} r_u;

	assert(ptr != NULL);

	r_u.ptr=ptr;

	push_report_modules((const void *)r_u.ptr); /* ADD to it */

	switch (*r_u.magic) {
		case IP_REPORT_MAGIC:
			if (GET_DOCONNECT()) {
				connect_grabbanners(r_u.ir); /* XXX */
			}
			break;

		case ARP_REPORT_MAGIC:
			break;

		default:
			PANIC("Unknown report format %08x", *r_u.magic);
			break;
	}

	push_output_modules((const void *)r_u.ptr); /* display it somehow */

	if ( ! GET_REPORTQUIET()) {
		display_report(r_u.ptr);
	}

	/*
	 * now check for chained reports
	 * should generally only happen if proc dups is set (-c)
	 */
	if (*r_u.magic == IP_REPORT_MAGIC) {
		if (r_u.ir->next != NULL) {
			do_report_nodefunc(0, r_u.ir->next, NULL);
		}
	}

	clean_report_extra(r_u.ptr);
	xfree(r_u.ptr);

	return 1;
}

static void clean_report_extra(void *r) {
	union {
		ip_report_t *ir;
		arp_report_t *ar;
		void *ptr;
		uint32_t *magic;
	} r_u;
	union {
		void *ptr;
		output_data_t *d;
	} d_u;

	assert(r != NULL);

	r_u.ptr=r;

	if (*r_u.magic != IP_REPORT_MAGIC || r_u.ir->od_q == NULL) {
		return;
	}

	while ((d_u.ptr=fifo_pop(r_u.ir->od_q)) != NULL) {
		xfree(d_u.ptr);
	}

	fifo_destroy(r_u.ir->od_q);

	return;
}

/*
 * deal with a 32 bit network address, possibly looking up DNS depending on GET_DODNS and the format string
 * dodns means that the format string had a trailing n inside it (1 = yes)
 */
static char *fmtcat_ip4addr(int dodns, uint32_t addr) {
	struct sockaddr_in tsin;
	char *thost=NULL;
	struct in_addr ia;

	if (dodns == 1 && GET_DODNS()) {
		tsin.sin_family=AF_INET;
		tsin.sin_port=0;
		tsin.sin_addr.s_addr=addr;

		thost=stddns_getname(s->dns, (const struct sockaddr *)&tsin);
		if (thost != NULL) {
			return thost;
		}
	}

	/* if dodns == 1 and GET_DODNS == 0
	 * they have a format string asking for dns, but want to skip doing DNS
	 * well override the format string with the lacking `do dns' option
	 */

	ia.s_addr=addr;
	return inet_ntoa(ia);
}

static char *fmtcat(const char *fmt, const void *report) {
	int state=0;
	char *outline=NULL;
	const char *end=NULL;
	size_t outoff=0, cursz=0;
	union {
		const arp_report_t *a;
		const ip_report_t *i;
		const void *p;
		const uint32_t *magic;
	} r_u;

	if (fmt == NULL || strlen(fmt) < 1) {
		return NULL;
	}

	r_u.p=report;

	cursz=128;
	outline=xmalloc(cursz);

#define KEH(x) \
	if (outoff + 2 > cursz) { \
		assert((cursz * 2) > cursz); \
		cursz *= 2; \
		outline=realloc(outline, cursz); \
	} \
	outline[outoff++]=x

#define KEHSTR(x) \
	if ((outoff + 1 + strlen((x))) > cursz) { \
		size_t newlen=cursz + (2 * (strlen((x)) + 1)); \
		\
		assert(newlen > cursz); \
		outline=realloc(outline, newlen); \
		cursz=newlen; \
	} \
	memcpy(outline + outoff, (x), strlen((x))); \
	outoff += strlen((x))

	for (end=fmt + strlen(fmt); *fmt != '\0'; fmt++) {
		if (state == 0) {
			if (*fmt == '%') {
				state=1;
			}
			else if (*fmt == '\\') {
				state=2;
			}
			else {
				KEH(*fmt);
			}
		}
		else if (state == 1) {
			/*
			 * dodge as much work as possible ;], printf already does this
			 */
			uint32_t taddr=0;
			char ofmt[128], tmp[1024], *tptr=NULL;
			unsigned int noff=0;
			struct in_addr ia;
			int doname=0;

			ofmt[0]='%';
			ofmt[1]='\0';

			state=0;

			if (*fmt == '-' || *fmt == '0' || *fmt == ' ') {
				ofmt[1]=*fmt;
				ofmt[2]='\0';
				fmt++;
				if (fmt == end) {
					continue;
				}
			}

			/* dont support large lengths, 999 is big enough */
			for (noff=0; fmt < end && isdigit(*fmt) && noff < 3; noff++, fmt++) {
				;
			}

			if (noff > 0) {
				char buf[16];

				memcpy(buf, fmt - noff, noff);
				buf[noff]='\0';
				strncat(ofmt, buf, strlen(buf));
			}

			doname=0;

			switch (*fmt) {
				case '%':
					KEH(*fmt);
					break;

				case 'C': /* country */
					if (*r_u.magic == IP_REPORT_MAGIC) {
						ia.s_addr=r_u.i->host_addr;
					}
					else if (*r_u.magic == ARP_REPORT_MAGIC) {
						ia.s_addr=r_u.a->ipaddr;
					}
					else {
						break;
					}
					strcat(ofmt, "s");
#ifdef HAVE_LIBGEOIP
					tptr=GeoIP_country_code_by_addr(gi, inet_ntoa(ia));
					snprintf(tmp, sizeof(tmp) -1, ofmt, tptr != NULL ? tptr : "??");
					KEHSTR(tmp);
#else
					ERR("no GeoIP support compiled in!");
#endif

					break;

				case 'h': /* host address (followed by n means dns name if possible) */
					if (*(fmt + 1) == 'n') {
						doname=1;
						fmt++;
					}
					if (*r_u.magic == IP_REPORT_MAGIC) {
						taddr=r_u.i->host_addr;
					}
					else if (*r_u.magic == ARP_REPORT_MAGIC) {
						taddr=r_u.a->ipaddr;
					}
					else {
						break;
					}
					strcat(ofmt, "s");

					tptr=fmtcat_ip4addr(doname, taddr);
					if (tptr != NULL) {
						snprintf(tmp, sizeof(tmp) - 1, ofmt, tptr);
						KEHSTR(tmp);
					}
					break;

				case 'L': /* local port */
					if (*(fmt + 1) == 'n') {
						doname=1;
						fmt++;
					}
					if (*r_u.magic != IP_REPORT_MAGIC) {
						break;
					}

					if (doname == 1) {
						strcat(ofmt, "s");
						snprintf(tmp, sizeof(tmp) - 1, ofmt, getservname(r_u.i->dport));
					}
					else {
						strcat(ofmt, "hu");
						snprintf(tmp, sizeof(tmp) -1, ofmt, r_u.i->dport);
					}
					KEHSTR(tmp);
					break;

				case 'M': /* link address */
					if (*r_u.magic == ARP_REPORT_MAGIC) {
						char hwstr[64];

						snprintf(hwstr, sizeof(hwstr) -1, "%02x:%02x:%02x:%02x:%02x:%02x",
							r_u.a->hwaddr[0], r_u.a->hwaddr[1], r_u.a->hwaddr[2],
							r_u.a->hwaddr[3], r_u.a->hwaddr[4], r_u.a->hwaddr[5]
						);
						strcat(ofmt, "s");
						snprintf(tmp, sizeof(tmp) -1, ofmt, hwstr);
						KEHSTR(tmp);
					}
					break;

				case 'o': /* macaddr OUI name */
					if (*r_u.magic == ARP_REPORT_MAGIC) {
						const char *vend=NULL;

						vend=getouiname(r_u.a->hwaddr[0], r_u.a->hwaddr[1], r_u.a->hwaddr[2]);
						if (vend == NULL) {
							vend="unknown";
						}
						strcat(ofmt, "s");
						snprintf(tmp, sizeof(tmp) -1, ofmt, vend);
						KEHSTR(tmp);
					}
					break;

				case 'p': /* port */
					if (*(fmt + 1) == 'n') {
						doname=1;
						fmt++;
					}
					if (*r_u.magic != IP_REPORT_MAGIC) {
						break;
					}

					if (doname == 1) {
						strcat(ofmt, "s");
						snprintf(tmp, sizeof(tmp) - 1, ofmt, getservname(r_u.i->sport));
					}
					else {
						strcat(ofmt, "hu");
						snprintf(tmp, sizeof(tmp) -1, ofmt, r_u.i->sport);
					}

					KEHSTR(tmp);
					break;

				case 'r': /* response type */
					if (*r_u.magic == IP_REPORT_MAGIC) {
						strcat(ofmt, "s");
						snprintf(tmp, sizeof(tmp) -1, ofmt, strresptype(r_u.i));
						KEHSTR(tmp);
					}
					break;

				case 's': /* source address */
					if (*(fmt + 1) == 'n') {
						doname=1;
						fmt++;
					}
					if (*r_u.magic != IP_REPORT_MAGIC) {
						break;
					}
					strcat(ofmt, "s");

					tptr=fmtcat_ip4addr(doname, r_u.i->send_addr);
					if (tptr != NULL) {
						snprintf(tmp, sizeof(tmp) -1, ofmt, tptr);
						KEHSTR(tmp);
					}
					break;

				case 'S': /* remote sequence number */
					if (*r_u.magic == IP_REPORT_MAGIC && r_u.i->proto == IPPROTO_TCP) {
						strcat(ofmt, "x");
						snprintf(tmp, sizeof(tmp) -1, ofmt, r_u.i->tseq);
						KEHSTR(tmp);
					}
					break;

				case 't': /* ttl */
					if (*r_u.magic != IP_REPORT_MAGIC) {
						break;
					}
					strcat(ofmt, "hu");
					snprintf(tmp, sizeof(tmp) - 1, ofmt, r_u.i->ttl);
					KEHSTR(tmp);
					break;

				case 'T': /* trace address */
					if (*(fmt + 1) == 'n') {
						doname=1;
						fmt++;
					}
					if (*r_u.magic != IP_REPORT_MAGIC) {
						break;
					}

					if (r_u.i->trace_addr == r_u.i->host_addr) {
						break;
					}

					tptr=fmtcat_ip4addr(doname, r_u.i->trace_addr);
					if (tptr != NULL) {
						strcat(ofmt, "s");
						snprintf(tmp, sizeof(tmp) - 1, ofmt, tptr);
						KEHSTR(tmp);
					}
					break;

				case 'w': /* window size */
					if (*r_u.magic == IP_REPORT_MAGIC && r_u.i->proto == IPPROTO_TCP) {
						strcat(ofmt, "u");
						snprintf(tmp, sizeof(tmp) -1, ofmt, r_u.i->window_size);
						KEHSTR(tmp);
					}
					break;

				default:
					fprintf(stderr, "unknown format string character `%c'\n", *fmt);
					break;
			}
		} /* if state */
		else if (state == 2) {
			switch (*fmt) {
				case 'v':
					KEH('\v');
					break;

				case 't':
					KEH('\t');
					break;

				case 'n':
					KEH('\n');
					break;

				case 'a':
					KEH('\a');
					break;

				case 'b':
					KEH('\b');
					break;

				case 'f':
					KEH('\f');
					break;

				case 'r':
					KEH('\r');
					break;

				case '\\':
					KEH('\\');
					break;

				default:
					fprintf(stderr, "Unknown escape char %c, ignoring\n", *fmt);
			}
			state=0;
		}
	} /* for each character in format */

	outline[outoff]='\0';

	return outline;
}

static char *strresptype(const ip_report_t *ir) {
	static char pstate[128];

	if (GET_DOTRANS() && port_open(ir->proto, ir->type, ir->subtype)) {
		snprintf(pstate, sizeof(pstate) -1, "%s %s", ipproto_tostr(ir->proto), s->openstr);
	}
	else if (GET_DOTRANS() && port_closed(ir->proto, ir->type, ir->subtype)) {
		snprintf(pstate, sizeof(pstate) -1, "%s %s", ipproto_tostr(ir->proto), s->closedstr);
	}
	else {
		if (ir->proto == IPPROTO_ICMP) {
			sprintf(pstate, "ICMP:T%02uC%02u", ir->type, ir->subtype);
		}
		else if (ir->proto == IPPROTO_TCP) {
			sprintf(pstate, "TCP%s", strtcpflgs(ir->type));
		}
		else {
			sprintf(pstate, "IP:P%02uT%04xS%04x", ir->proto, ir->type, ir->subtype);
		}
	}

	return pstate;
}

static const char *ipproto_tostr(int proto) {

	switch (proto) {
		case IPPROTO_ICMP:
			return "ICMP";

		case IPPROTO_TCP:
			return "TCP";

		case IPPROTO_UDP:
			return "UDP";

		default:
			break;
	}

	return "Unknown";
}

static int port_open(uint8_t proto, uint16_t type, uint16_t subtype) {

	switch (proto) {
		case IPPROTO_TCP:
			if ((type & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
				return 1;
			}
			break;

		case IPPROTO_UDP:
			return 1;
			break; /* heh */

		default:
			break;
	}
	return 0;
}

static int port_closed(uint8_t proto, uint16_t type, uint16_t subtype) {

	switch (proto) {
		case IPPROTO_TCP:
			if ((type & (TH_ACK|TH_RST)) == (TH_ACK|TH_RST)) {
				return 1;
			}
			break;

		case IPPROTO_ICMP:
			if (type == 3 && subtype == 3) {
				return 1;
			}
			break;
		default:
			break;
	}
	return 0;
}

/* destructive XXX this function is lame */
static char *get_report_extra(ip_report_t *r) {
	static char out[512];
	size_t out_off=0;
	int sret=0;
	union {
		void *ptr;
		output_data_t *d;
	} d_u;

	assert(r != NULL);

	CLEAR(out);

	if (r->od_q == NULL) {
		PANIC("output data NULL on report");
	}

	while ((d_u.ptr=fifo_pop(r->od_q)) != NULL) {
		/* XXX yah */
		sret=snprintf(&out[out_off], (sizeof(out) - (out_off + 1)), "%s `%s' ", (d_u.d->type == OD_TYPE_OS ? "OS" : "Banner"), (d_u.d->type == OD_TYPE_OS ? d_u.d->t_u.os : d_u.d->t_u.banner));
		if (sret < 1) break;
		out_off += sret;
		if (out_off >= (sizeof(out) -1)) {
			ERR("report buffer is overflowing, breaking");
			break;
		}
	}

	if (strlen(out)) {
		return out;
	}

	return NULL;
}

static uint64_t get_ipreport_key(uint32_t dhost, uint16_t dport, uint32_t shost) {
	union {
		struct {
			uint16_t cshost;
			uint16_t dport;
			uint32_t dhost;
		} ip;
		uint64_t key;
	} p_u;

	p_u.ip.dhost=dhost;
	p_u.ip.dport=dport;
	p_u.ip.cshost=(uint16_t)(shost >> 16) ^ (shost & 0x0000FFFF); /* whatever */

	return p_u.key;
}

static uint64_t get_arpreport_key(uint32_t dhost, uint8_t *dmac) {
	union {
		struct {
			uint32_t dhost;
			uint8_t cmac[4];
		} arp;
		uint64_t key;
	} p_u;

	p_u.arp.cmac[0]=*(dmac)     ^ *(dmac + 1);
	p_u.arp.cmac[1]=*(dmac + 3) ^ *(dmac + 2);
	p_u.arp.cmac[2]=*(dmac + 4);
	p_u.arp.cmac[3]=*(dmac + 5);

	p_u.arp.dhost=dhost;

	return p_u.key;
}
