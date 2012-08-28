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
#ifndef _WORKUNITS_H
# define _WORKUNITS_H

#define  TCP_SEND_MAGIC 0x1a1b1c1d
#define  UDP_SEND_MAGIC 0x2a2b2c2d
#define  ARP_SEND_MAGIC 0x3a3b3c3d
#define ICMP_SEND_MAGIC 0x4a4b4c4d
#define   IP_SEND_MAGIC	0x5a5b5c5d
#define PRI_4SEND_MAGIC 0x6a6b6c6d
#define PRI_6SEND_MAGIC 0x7a7b7c7d

#define  TCP_RECV_MAGIC 0xa1b1c1d1
#define  UDP_RECV_MAGIC 0xa2b2c2d2
#define  ARP_RECV_MAGIC 0xa3b3c4d3
#define ICMP_RECV_MAGIC 0xa4b4c4d4
#define   IP_RECV_MAGIC 0xa5b5c5d5

#define        WK_MAGIC	0xf4f3f1f2
#define  WKS_SEND_MAGIC 0x33cd1a1a
#define  WKS_RECV_MAGIC 0x32cc1919

#define WORKUNIT_STATUS_OUTSTANDING	0
#define WORKUNIT_STATUS_COMPLETE	1
#define WORKUNIT_STATUS_ERROR		-1

typedef struct _PACKED_ send_workunit_t {
	uint32_t magic;
	uint32_t repeats;
	uint16_t send_opts;
	uint32_t pps;
	uint8_t delay_type;
	struct sockaddr_storage myaddr;
	struct sockaddr_storage mymask;
	uint8_t hwaddr[THE_ONLY_SUPPORTED_HWADDR_LEN];
	uint16_t mtu;

	struct sockaddr_storage target;
	struct sockaddr_storage targetmask;
	uint8_t tos;
	uint8_t minttl;
	uint8_t maxttl;
	uint16_t ip_off;
	uint16_t fingerprint;
	int32_t src_port;
	uint8_t ipoptions[64];
	uint8_t ipoptions_len;

	uint16_t tcphdrflgs;
	uint8_t tcpoptions[64];
	uint8_t tcpoptions_len;
	uint16_t window_size;	/* without WS, hence the 16 wide version */
	uint32_t syn_key;

	uint16_t port_str_len;
} send_workunit_t;

typedef struct _PACKED_ recv_workunit_t {
	uint32_t magic;
	uint8_t recv_timeout;
	uint8_t ret_layers;
	uint16_t recv_opts;
	uint32_t window_size;

	uint32_t syn_key;
	uint16_t pcap_len;
} recv_workunit_t;

/* this is always relative to the currently running scan for protocol types (currently) */
typedef struct _PACKED_ send_ipv4_pri_workunit_t {
	uint32_t magic;
	uint32_t dhost;
	uint16_t dport;
	uint16_t sport;
	uint32_t shost;
	uint32_t flags;
	uint32_t mseq;
	uint32_t tseq;
	uint32_t t_tstamp;
	uint32_t m_tstamp;
	uint16_t window_size;
	uint16_t doff;
} send_pri_workunit_t;

struct wk_s {
	uint32_t magic;
	size_t len;
	send_workunit_t *s;
	recv_workunit_t *r;
	int iter;
	int used;
	uint32_t wid;
};

typedef struct workunit_stats_t {
	uint32_t magic;
	uint32_t wid;
	char *msg;
} workunit_stats_t;

int workunit_init(void);

char *strworkunit(const void *, size_t );

send_workunit_t *workunit_get_sp(size_t * /* wu len */, uint32_t * /* wid */);
recv_workunit_t *workunit_get_lp(size_t * /* wu len */, uint32_t * /* wid */);

void workunit_reset(void);
void workunit_dump(void);

int  workunit_add(const char *, char ** /* error message if < 0 */);

void workunit_reject_sp(uint32_t /* wid */);
void workunit_reject_lp(uint32_t /* wid */);

int  workunit_check_sp(void);

void workunit_destroy_sp(uint32_t );
void workunit_destroy_lp(uint32_t );

char *workunit_pstr_get(const send_workunit_t *);
char *workunit_fstr_get(const recv_workunit_t *);

void workunit_destroy(void);
int  workunit_get_interfaces(void);

void workunit_stir_sp(void);
void workunit_stir_lp(void);

#endif
