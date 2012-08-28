/*

   p0f - fingerprint entry
   -----------------------

   No servicable parts inside.

   Copyright (C) 2003 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#ifndef _HAVE_FPENTRY_H
#define _HAVE_FPENTRY_H

#include "p0f-config.h"

#define MOD_NONE	0
#define MOD_CONST	1
#define MOD_MSS		2
#define MOD_MTU		3

#define QUIRK_PAST      0x00000001 /* P */
#define QUIRK_ZEROID	0x00000002 /* Z */
#define QUIRK_IPOPT	0x00000004 /* I */
#define QUIRK_URG	0x00000008 /* U */ 
#define QUIRK_X2	0x00000010 /* X */ 
#define QUIRK_ACK	0x00000020 /* A */ 
#define QUIRK_T2	0x00000040 /* T */
#define QUIRK_FLAGS	0x00000080 /* F */
#define QUIRK_DATA	0x00000100 /* D */
#define QUIRK_BROKEN	0x00000200 /* ! */
#define QUIRK_RSTACK	0x00000400 /* K */
#define QUIRK_SEQEQ	0x00000800 /* Q */
#define QUIRK_SEQ0      0x00001000 /* 0 */

struct fp_entry {
  uint8_t* os;		/* OS genre */
  uint8_t* desc;		/* OS description */
  uint8_t  no_detail;	/* Disable guesstimates */
  uint8_t  generic;		/* Generic hit */
  uint8_t  userland;	/* Userland stack */
  uint16_t wsize;		/* window size */
  uint8_t  wsize_mod;	/* MOD_* for wsize */
  uint8_t  ttl,df;		/* TTL and don't fragment bit */
  uint8_t  zero_stamp;	/* timestamp option but zero value? */
  uint16_t size;		/* packet size */
  uint8_t  optcnt;		/* option count */
  uint8_t  opt[MAXOPT];	/* TCPOPT_* */
  uint16_t wsc,mss;		/* value for WSCALE and MSS options */
  uint8_t  wsc_mod,mss_mod;	/* modulo for WSCALE and MSS (NONE or CONST) */
  uint32_t quirks;		/* packet quirks and bugs */
  uint32_t line;		/* config file line */
  struct fp_entry* next;
};

#ifdef IGNORE_ZEROID
#  undef QUIRK_ZEROID
#  define QUIRK_ZEROID	0
#endif /* IGNORE_ZEROID */

#endif /* ! _HAVE_FPENTRY_H */
