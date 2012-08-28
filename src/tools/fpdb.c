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
#include <scan_progs/scan_export.h>
#include <settings.h>

#include <unilib/terminate.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/qfifo.h>
#include <unilib/prng.h>
#include <scan_progs/packet_parse.h>
#include <scan_progs/packets.h>
#include <scan_progs/packet_slice.h>


#include "p0f/p0fexport.h"

#include <libpq-fe.h>

#define ISSYNACK	1
#define ISRSTACK	2

static void startit(void);
static void dump_packet(void *, size_t );

settings_t *s=NULL;
const char *ident_name_ptr="Fpdb";

static PGconn *pgconn=NULL;
static PGresult *pgres=NULL;
static ExecStatusType pgret;

int ident=0;
void *r_queue=NULL, *p_queue=NULL;
pcap_dumper_t *pdump=NULL;

int main(int argc, char **argv) {
	char connstr[1024], host[128];
	char *packet=NULL, *iprptid=NULL;
	union {
		unsigned char *pdata;
		uint16_t *plen;
	} p_u;
	size_t pdata_len=0, pl_ret=0, j1=0;
	int j=0, rows=0, plen=0, pkt=0, pmode=0, layerfp=0, good=0;
	packetlayers_t pl[8];
	struct in_addr ia;

	startit();

	SET_SNIFF(1);

	set_fuzzy();
	set_ackmode();
	pmode=ISSYNACK;
	load_config();

	strcpy(connstr, "user=scan password=scanit! dbname=scan");

	pgconn=PQconnectdb(connstr);
	if (pgconn == NULL || PQstatus(pgconn) != CONNECTION_OK) {
		ERR("PostgreSQL connection fails: %s",
			pgconn == NULL ? "unknown" : PQerrorMessage(pgconn)
		);
		exit(1);
	}

	pgres=PQexec(pgconn, "select ipreport_id, packet from uni_ippackets;");
	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_TUPLES_OK) {
		ERR("PostgreSQL scan insert id returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		goto kthnx;
	}

	rows=PQntuples(pgres);

	if (rows == 0) {
		goto kthnx;
	}

	assert(rows > -1);

	for (j=0; j < rows; j++) {
		packet=PQgetvalue(pgres, j, 1);
		if (packet == NULL) {
			continue;
		}

		plen=PQgetlength(pgres, j, 1);
		if (plen < 1) {
			continue;
		}

		iprptid=PQgetvalue(pgres, j, 0);
		if (iprptid == NULL) {
			continue;
		}

		/*
		 * printf("row %d ipreport_id %s packet %s length %d\n", j, iprptid, packet, plen);
		 */

		p_u.pdata=PQunescapeBytea(packet, &pdata_len);

		if (p_u.pdata == NULL || pdata_len < sizeof(uint16_t)) {
			continue;
		}

		assert(*p_u.plen == pdata_len);

		p_u.plen++;

		/*
		 * hexdump(p_u.pdata, pdata_len - sizeof(uint16_t));
		 */

		memset(&pl[0], 0, sizeof(pl));

		pl_ret=packet_slice(p_u.pdata, pdata_len, &pl[0], sizeof(pl), PKLTYPE_IP);

		ia.s_addr=0;
		for (j1=0, good=0; j1 < pl_ret; j1++) {
			if (pl[j1].type == PKLTYPE_IP) {
				union {
					const struct myiphdr *i;
					const uint8_t *p;
				} i_u;

				i_u.p=pl[j1].ptr;
				assert(pl[j1].len >= sizeof(struct myiphdr));
				ia.s_addr=i_u.i->saddr;

				memset(host, 0, sizeof(host));
				strncpy(host, inet_ntoa(ia), sizeof(host) -1);
				good++;
			}
			else if (pl[j1].type == PKLTYPE_TCP) {
				union {
					const struct mytcphdr *t;
					const uint8_t *p;
				} t_u;

				t_u.p=pl[j1].ptr;
				assert(pl[j1].len >= sizeof(struct mytcphdr));

				if (t_u.t->syn && t_u.t->ack) {
					pkt=ISSYNACK;
				}
				else if (t_u.t->rst && t_u.t->ack) {
					pkt=ISRSTACK;
				}
				layerfp=(int )j1;
				good++;
			}
			printf("layer %s processed\n", strpklayer(pl[j1].type));
		}
		//if (good != 2) {
		//	dump_packet(p_u.pdata, pdata_len - sizeof(uint16_t));
		//}

		if (pkt == ISSYNACK) {
			char *resp=NULL;

			resp=p0f_parse(p_u.pdata, pdata_len - sizeof(uint16_t));

			if (resp != NULL) {
				printf("host %s SYN+ACK resp `%s' at layer %d ipreportid %s\n", host, resp, layerfp, iprptid);
			}
		}
		else if (pkt == ISRSTACK) {
			printf("rst+ack\n");
		}
/*
char *p0f_parse(const uint8_t* , uint16_t );
*/

		p_u.plen--;

		//PQfreemem(p_u.pdata);
	}

kthnx:
	//PQclear(pgres);
	//PQfinish(pgconn);

	exit(0);
}

static void startit(void) {
        ident=IDENT_ANY;
        ident_name_ptr=IDENT_ANY_NAME;

        s=xmalloc(sizeof(settings_t));
        memset(s, 0, sizeof(settings_t));
        s->vi=(interface_info_t **)xmalloc(sizeof(interface_info_t *));
        s->vi[0]=(interface_info_t *)xmalloc(sizeof(interface_info_t));
        prng_init();
        memset(s->vi[0], 0, sizeof(interface_info_t));
        s->ss=xmalloc(sizeof(scan_settings_t));
        s->_stdout=stdout;
        s->_stderr=stderr;
        bluescreen_register();
	s->debugmask=0x7fffffff;

        s->verbose=255;
        s->ss->mode=MODE_TCPSCAN;
        s->ss->header_len=8;

        s->forked=0;

        r_queue=fifo_init();
        p_queue=fifo_init();

	return;
}

static void dump_packet(void *pkt, size_t pkt_len) {
	struct pcap_pkthdr ph;
	uint8_t *dupp=NULL;

	dupp=xmalloc(pkt_len + 8);
	memset(dupp, 0, 8);
	memcpy(dupp + 8, pkt, pkt_len);
	//hexdump(dupp, pkt_len + 8);

	ph.caplen=pkt_len + 8;
	ph.len=pkt_len + 8;

	parse_packet(NULL, (const struct pcap_pkthdr *)&ph, dupp);

	return;
}
