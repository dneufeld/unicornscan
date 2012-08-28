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
#include <getopt.h>

#include <pcap.h>

#include <ctype.h>

#include <scan_progs/packets.h>
#include <scan_progs/scanopts.h>
#include <settings.h>
#include <scan_progs/scan_export.h>

#include <unilib/output.h>
#include <unilib/arch.h>
#include <unilib/pcaputil.h>
#include <unilib/xmalloc.h>
#include <unilib/terminate.h>

#include <scan_progs/packet_slice.h>

#define MAX_WIDTH 80

int ident;
const char *ident_name_ptr;
settings_t *s=NULL;
static int headerlen=0;
static int verbose=0;
FILE *outfp=NULL;

static void usage(const char *) _NORETURN_;
void process_packet(uint8_t *, const struct pcap_pkthdr *, const uint8_t *);

#define OPTS	"i:o:hv"

int main(int argc, char ** argv) {
	char errbuf[PCAP_ERRBUF_SIZE], *pfilter=NULL, *readfile=NULL;
	pcap_t *pdev=NULL;
	bpf_u_int32 net=0;
	struct bpf_program filter;
	int ch=0;

	ident=IDENT_ANY;
	ident_name_ptr="Pcpl";

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

	while ((ch=getopt(argc, argv, OPTS)) != -1) {
		switch (ch) {
			case 'i':
				readfile=xstrdup(optarg);
				break;

			case 'o':
				outfp=fopen(optarg, "a+");
				if (outfp == NULL) {
					terminate("cant open output file `%s'", optarg);
				}
				break;

			case 'v':
				verbose++;
				break;

			case 'h':
			default:
				usage(argv[0]);
				break;
		}
	}

	if (outfp == NULL) {
		outfp=stdout;
	}

	if (readfile == NULL || strlen(readfile) < 1) usage(argv[0]);

	if (!(optind < argc)) {
		pfilter=xstrdup("tcp or udp");
	}
	else {
		for ( ; argv[optind] != NULL ; optind++) {
			if (pfilter == NULL) {
				pfilter=xstrdup(argv[optind]);
			}
			else {
				char *nnew=NULL, *nptr=NULL;
				size_t t=0;

				t=strlen(pfilter) + strlen(argv[optind]) + 2;
				nnew=(char *)xmalloc(t);
				memset(nnew, 0, t);

				nptr=nnew;
				memcpy(nptr, pfilter, strlen(pfilter));
				nptr += strlen(pfilter);
				*nptr=' ';
				nptr++;
				memcpy(nptr, argv[optind], strlen(argv[optind]));
				pfilter=nnew;
			}
		}
	}

	memset(errbuf, 0, sizeof(errbuf));

	pdev=pcap_open_offline(readfile, errbuf);
	if (pdev == NULL) {
		ERR("error: %s", errbuf);
		exit(1);
	}

	if (pcap_compile(pdev, &filter, pfilter, 0, net) < 0) {
		ERR("pcap filter is from mars: %s", pcap_geterr(pdev));
		exit(1);
	}

	if (pcap_setfilter(pdev, &filter) < 0) {
		ERR("pcap setfilter didnt work: %s", pcap_geterr(pdev));
		exit(1);
	}

	if ((headerlen=util_getheadersize(pdev, errbuf)) < 0) {
		ERR("cant get header length: %s", errbuf);
		exit(1);
	}

	xfree(pfilter);

	pcap_loop(pdev, 0, &process_packet, NULL);

	exit(0);
}

typedef struct newpl_t {
	const char *data;
	uint16_t dport;
	int32_t sport;
	uint8_t proto;
} newpl_t;

#define BUF_SIZE 128

void process_packet(uint8_t *user, const struct pcap_pkthdr *phdr, const uint8_t *packet) {
	size_t len=0, fab=0;
	int j=0;
	packetlayers_t plz[8];
	union {
		const struct myudphdr *u;
		const struct mytcphdr *t;
		const uint8_t *ptr;
	} p_u;
	char *proto=NULL, linebuf[BUF_SIZE];
	uint16_t dport=0;
	int sport=-1;
	const uint8_t *dataptr=NULL;
	size_t datalen=0, print=0, doff=0, loff=0;
	int sret=0, nl=0;

	if (packet == NULL) return;

	len=phdr->caplen;

	fab=packet_slice(packet, len, &plz[0], 8, PKLTYPE_ETH);

	VRB(0, "/*");

	for (j=0 ; j < 8 ; j++) {
		if (plz[j].type == 0) break;
		VRB(0, "--type %s stat %s ptr %p len " STFMT "--", strpklayer(plz[j].type), strpkstat(plz[j].stat), plz[j].ptr, plz[j].len);
		if (plz[j].type == PKLTYPE_UDP && dport == 0 && sport == -1) {
			assert(plz[j].len == sizeof(struct myudphdr));

			p_u.ptr=plz[j].ptr;

			dport=ntohs(p_u.u->dest);
			sport=ntohs(p_u.u->source);

			proto=xstrdup("udp");
		}
		else if (plz[j].type == PKLTYPE_TCP && dport == 0 && sport == -1) {
			assert(plz[j].len == sizeof(struct mytcphdr));

			p_u.ptr=plz[j].ptr;

			dport=ntohs(p_u.t->dest);
			sport=ntohs(p_u.t->source);

			proto=xstrdup("tcp");
		}
		else if (plz[j].type == PKLTYPE_PAYLOAD) {
			dataptr=plz[j].ptr;
			datalen=plz[j].len;
		}
		if (verbose) { if (plz[j].len) hexdump(plz[j].ptr, plz[j].len); }
	}
	VRB(0, "*/");

	for (doff=0, print=0 ; doff < datalen ; doff++) {
		if (isprint(dataptr[doff]) || isspace(dataptr[doff])) {
			print++;
		}
	}

	CLEAR(linebuf);
	if (datalen && dataptr != NULL && proto != NULL) {
		OUT("\t%s %u %d {", proto, dport, sport);
		if (print == datalen) {
			for (doff=0 ; doff < datalen ; doff++) {
				if (isprint(dataptr[doff]) && dataptr[doff] != '\"') {
					sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "%c", dataptr[doff]);
				}
				else {
					switch (dataptr[doff]) {
						case '\040': /* i'm damaged                     */
							sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), " ");
							break;
						case '\f':   /* you're damaged                  */
							sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "\\f");
							break;
						case '\n':   /* i'm your damage                 */
							sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "\\n");
							nl=1;
							break;
						case '\r':   /* |||||||         |||||||         */
							sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "\\r");
							break;
						case '\t':   /* ||||||| ||||||| ||||||| ||||||| */
							sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "\\t");
							break;
						case '\v':   /* ||||||| ||||||| ||||||| ||||||| */
							sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "\\v");
							break;
						case '\"':   /* ||||||| ||||||| ||||||| ||||||| */
							sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "\\\"");
							break;
						default:     /*         |||||||         ||||||| */
							ERR("ive only got this default case so i fit in with the others");
							exit(1);
					}
				}
				if (sret < 1) {
					ERR("ack, truncated buffer, exiting");
					break;
				}
				loff += (size_t) sret;
				if (loff + 1 == sizeof(linebuf)) {
					ERR("ack truncation!!!");
					break;
				}
				if (nl == 1) {
					OUT("\t\t\"%s\"", linebuf);
					CLEAR(linebuf); nl=0; loff=0;
				}
				if (loff >= MAX_WIDTH) {
					OUT("\t\t\"%s\"", linebuf);
					CLEAR(linebuf); loff=0;
				}
			} /* for each char */
		} /* end printable payload */
		else {
			int csf=0;
			char strings[BUF_SIZE];
			size_t soff=0;

			CLEAR(strings);
			for (doff=0 ; doff < datalen ; doff++) {
				sret=snprintf(&linebuf[loff], sizeof(linebuf) - (1 + loff), "\\x%02x", dataptr[doff]);
				csf++;

				assert((soff + 1) < sizeof(strings));

				if (isprint(dataptr[doff])) {
					strings[soff++]=dataptr[doff];
				}
				else {
					strings[soff++]='.';
				}

				if (sret < 1) {
					ERR("ack, truncated buffer, exiting");
					break;
				}
				loff += (size_t) sret;
				if (loff + 1 == sizeof(linebuf)) {
					ERR("Ack truncation!!!");
					break;
				}
				if ((csf % 16) == 0) {
					OUT("\t\t\"%s\"\t/* %s */", linebuf, strings);
					CLEAR(linebuf); loff=0; csf=0; CLEAR(strings); soff=0;
				}
			} /* for each non-printable char */
			if (loff) {
				OUT("\t\t\"%s\"\t/* %s */", linebuf, strings);
			}
		} /* end hex output */

		OUT("\t};");
	}

	if (proto != NULL) xfree(proto);

	return;
}

static void usage(const char *progname) {
	fprintf(stderr, "Usage: %s:\n"
		"\t-i\t*for pcap file to read\n"
		"\t-o\t for output file (append mode)\n"
		"\t-v\t verbose operation\n"
		"\t-h\t display help that you are reading\n"
		"[*] required argument\n"
		"pcap filter expression follows options, like %s -o new.conf -i file.pcap port 500 and udp\n",
		progname, progname
	);

	exit(0);
};
