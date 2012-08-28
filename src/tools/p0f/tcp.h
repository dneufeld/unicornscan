/*

   p0f - portable TCP/IP headers
   -----------------------------

   Well.

   Copyright (C) 2003 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_TCP_H
#define _HAVE_TCP_H

#define	TCPOPT_EOL		0	/* End of options */
#define	TCPOPT_NOP		1	/* Nothing */
#define	TCPOPT_MAXSEG		2	/* MSS */
#define TCPOPT_WSCALE   	3	/* Window scaling */
#define TCPOPT_SACKOK   	4	/* Selective ACK permitted */
#define TCPOPT_TIMESTAMP        8	/* Stamp out timestamping! */

#define IP_DF   0x4000	/* dont fragment flag */
#define IP_MF   0x2000	/* more fragments flag */

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
/* Stupid ECN flags: */
#define TH_ECE  0x40
#define TH_CWR  0x80

struct ip_header {
  uint8_t  ihl,	/* IHL */
       tos;	/* type of service */
  uint16_t tot_len,	/* total length */
       id,	/* identification */
       off;	/* fragment offset + DF/MF */
  uint8_t  ttl,	/* time to live */
       proto; 	/* protocol */
  uint16_t cksum;	/* checksum */
  uint32_t saddr,   /* source */
       daddr;   /* destination */
};


struct tcp_header {
  uint16_t sport,	/* source port */
       dport;	/* destination port */
  uint32_t seq,	/* sequence number */
       ack;	/* ack number */
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t  _x2:4,	/* unused */
       doff:4;	/* data offset */
#else /* BYTE_ORDER == BIG_ENDIAN */
  uint8_t  doff:4,  /* data offset */
       _x2:4;	/* unused */
#endif			 
  uint8_t  flags;	/* flags, d'oh */
  uint16_t win;	/* wss */
  uint16_t cksum;	/* checksum */
  uint16_t urg;	/* urgent pointer */
};

#endif /* ! _HAVE_TCP_H */
