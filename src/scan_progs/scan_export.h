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
#ifndef _SCAN_EXPORTS_H
# define _SCAN_EXPORTS_H

#ifndef TH_FIN
# define TH_FIN			1
#endif
#ifndef TH_SYN
# define TH_SYN			2
#endif
#ifndef TH_RST
# define TH_RST			4
#endif
#ifndef TH_PUSH
# define TH_PUSH		8
#endif
#ifndef TH_PSH
# define TH_PSH			8
#endif
#ifndef TH_ACK
# define TH_ACK			16
#endif
#ifndef TH_URG
# define TH_URG			32
#endif
#ifndef TH_ECE
# define TH_ECE			64
#endif
#ifndef TH_CWR
# define TH_CWR			128
#endif

#define MODE_TCPSCAN			1
#define MODE_UDPSCAN			2
#define MODE_ARPSCAN			4
#define MODE_ICMPSCAN			8
#define MODE_IPSCAN			16

#define REPORT_BADNETWORK_CKSUM		1
#define REPORT_BADTRANSPORT_CKSUM	2

#define OD_TYPE_OS			1
#define OD_TYPE_BANNER			2

#define REPORT_TYPE_IP			1
#define REPORT_TYPE_ARP			2

#define IP_REPORT_MAGIC			0xd2d19ff2
#define ARP_REPORT_MAGIC		0xd9d82aca

typedef struct output_data_t {
	uint8_t type;
	union {
		char *os;
		char *banner;
	} t_u;
} output_data_t;

typedef struct _PACKED_ ip_report_t {
	uint32_t magic;			/* extra checking						*/
	uint16_t sport;			/* from our senders `local' port				*/
	uint16_t dport;			/* the `target' machines listening port (or not listening)	*/
	uint8_t proto;			/* what ip protocol it was that we got back			*/
	uint16_t type;			/* for icmp this is type, for tcp it is the header flags	*
					 * on the packet, udp doesnt use this				*/
	uint16_t subtype;		/* for icmp this is the code, for tcp and udp it is not used	*/
	uint32_t send_addr;		/* who started this conversation anyhow				*/
	uint32_t host_addr;		/* our target machine						*/
	uint32_t trace_addr;		/* if we sent to the target where did the packet come back from?*/
	uint8_t ttl;			/* the raw ttl on the packet from the wire (not that we sent)	*/
	struct timeval recv_time; 	/* the secs and usecs that we pulled the packet off the wire at	*/
	void *od_q;			/* list of arbitrary data linked to this "packet" used in	*
					 * output mode (output_data_t list)				*/
	uint16_t flags;			/* had bad network or transport crc				*/
	/* XXX this is too tcp specific for ip reporting */
	uint32_t mseq;			/* tcp only							*/
	uint32_t tseq;			/* tcp only							*/
	uint16_t window_size;		/* tcp only							*/
	uint32_t t_tstamp;
	uint32_t m_tstamp;

	struct ip_report_t *next;	/* if keys can collide, well store chains here			*/

	uint16_t doff;			/*
					 * is there a packet following this report structure?
					 * if so how many bytes is it
					 */
} ip_report_t;

typedef struct _PACKED_ arp_report_t {
	uint32_t magic;			/* extra checking						*/
	uint8_t hwaddr[6];
	uint32_t ipaddr;
	struct timeval recv_time;
	void *od_q;
	uint16_t flags;
	uint16_t doff;
} arp_report_t;

#ifndef SCANSETTINGS
#define SCANSETTINGS void
#endif

void scan_setprivdefaults(void);

/*
 * returns 1, or -1 for error
 */
int scan_parsemode(
			const char *	/* input string		*/,
			uint8_t *	/* output mode		*/,
			uint16_t *	/* output flags		*/,
			uint16_t *	/* output sendflags	*/,
			uint16_t *	/* output recvflags	*/,
			uint16_t *	/* output masterflags	*/,
			uint32_t *	/* output pps		*/
		);

int scan_setoptmode(const char *);
int scan_setsrcaddr(const char *);
int scan_settcpflags(int );
int scan_setretlayers(int );
int scan_setttl(const char * );
int scan_settos(int );
int scan_setbroken(const char *);
int scan_setfingerprint(int );
int scan_setsrcp(int);
int scan_setrecvtimeout(int );
int scan_getrecvtimeout(void);
int scan_getmode(void);

int decode_tcpflags(const char *);

void send_mode(void);
void recv_mode(void);
void init_mode(void);

int init_payloads(void);

int add_payload(
		uint16_t /* proto */,
		uint16_t /* port */,
		int32_t /* local port */,
		const uint8_t * /* payload */,
		uint32_t /* payload_size */,
		int (* /* create payload */)(uint8_t **, uint32_t *, void *),
		uint16_t /* payload group */
	);

int add_default_payload(
		uint16_t /* proto */,
		int32_t /* local port */,
		const uint8_t * /* payload */,
		uint32_t /* payload_size */,
		int (* /* create payload */)(uint8_t **, uint32_t *, void *),
		uint16_t /* payload group */
	);

int get_payload(
		uint16_t /*index*/,
		uint16_t /* proto */,
		uint16_t /*port*/,
		uint8_t ** /*data*/,
		uint32_t * /*payload_s*/,
		int32_t * /*local_port*/,
		int (** /*create payload */)(uint8_t **, uint32_t *, void *),
		uint16_t /* payload_group */
	);

char *strscanmode(int /* s->ss->mode */);

#endif
