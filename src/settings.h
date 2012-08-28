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
#ifndef _SETTINGS_H
# define _SETTINGS_H

#define FORK_LOCAL_LISTENER	1
#define FORK_LOCAL_SENDER	2

#define	XDEBUG_SIGNAL	SIGUSR2

#ifndef SCANSETTINGS
 /* this is the public interface then */
# define SCANSETTINGS void
#endif

/* XXX shouldnt be here at ALL, move this stuff out into scan_modules */
#include <unilib/drone.h>
#include <pcap.h>

#define IDENT_ANY	0
#define IDENT_ANY_NAME		"Test"
#define IDENT_MASTER	1
#define IDENT_MASTER_NAME	"Main"
#define IDENT_SEND	2
#define IDENT_SEND_NAME		"Send"
#define IDENT_RECV	3
#define IDENT_RECV_NAME		"Recv"

extern int ident;
extern const char *ident_name_ptr;

union sock_u {
	struct sockaddr *s;
	struct sockaddr_storage *ss;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_ll *sl;
	struct f_s *fs;
};

union csock_u {
	const struct sockaddr *s;
	const struct sockaddr_storage *ss;
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_ll *sl;
	const struct f_s *fs;
};

/*
 * INTERFACE INFORMATION
 */
typedef struct interface_info_t {
	uint16_t mtu;
	uint8_t hwaddr[THE_ONLY_SUPPORTED_HWADDR_LEN];
	char hwaddr_s[32];
	struct sockaddr_storage myaddr;
	struct sockaddr_storage mymask;
	char myaddr_s[64];
} interface_info_t;

/*
 * MODULE PARAMETERS TYPE
 */
typedef struct keyval_t {
	char *key;
	char *value;
	struct keyval_t *next;
} keyval_t;

/*
 * MODULE PARAMETERS
 */
typedef struct mod_params_t {
	char *name;
	keyval_t *kv;
	struct mod_params_t *next;
} mod_params_t;

typedef struct payload_struct {
	uint16_t proto;							/* 2 */
	uint16_t port;							/* 2 */
	int32_t local_port;						/* 2 */
	uint8_t *payload;						/* 4 */
	uint32_t payload_size;						/* 4 */
	int (*create_payload)(uint8_t **, uint32_t *, void *);		/* 4 */
	uint16_t payload_group;						/* 2 */
	struct payload_struct *next;					/* 4 */
	struct payload_struct *over;					/* 4 */
} payload_t;

typedef struct payload_lh_t {
	payload_t *top;
	payload_t *bottom;
	payload_t *def;
} payload_lh_t;

/*
 * MAIN CONFIGURATION
 */
typedef struct settings_s {
	double num_hosts;
	double num_packets;
	uint32_t num_secs;

	char *gport_str;
	char *tcpquickports;
	char *udpquickports;

	char *ip_report_fmt;
	char *ip_imreport_fmt;
	char *arp_report_fmt;
	char *arp_imreport_fmt;
	char *openstr;
	char *closedstr;

	void *swu; /* fifo target list  */
	void *lwu; /* ditto for sniffer */

	uint32_t wk_seq;

	int senders;
	int listeners;

	int scan_iter; /* how many distinct scan iterations do we need for the pcap filters? */
	int cur_iter;

	uint32_t repeats;

	SCANSETTINGS *ss;

	struct {
		int stream_segments_sent;
		int stream_reassembly_abort_badpkt;
		int stream_remote_abort;
		int stream_closed_alien_pkt;
		int stream_out_of_window_pkt;
		int stream_trunc_past_window;
		int stream_out_of_order_segment;
		int stream_connections_est;
		int stream_triggers_sent;
		int stream_dynamic_triggers_sent;
		int stream_completely_alien_packet;
	} stats;

	char *profile;
	char *user;
	char *interface_str;
	interface_info_t **vi;
	int vi_size;
	int conn_delay;
	int ipv4_lookup;
	int ipv6_lookup;

	char *pcap_dumpfile;
	char *pcap_readfile;
	char *extra_pcapfilter;

	uint16_t master_tickrate;

	/* if this is a forked process, read when terminating */
	int forked;

	uint16_t options;
	uint16_t send_opts;
	uint16_t recv_opts;

	uint32_t verbose;
	uint32_t debugmask;
	char *debugmaskstr;
	uint32_t pps;

	time_t s_time;
	time_t e_time;
	time_t est_e_time;

	uint16_t payload_group;

	char *ipcuri; /* for forked processes only */
	char *idle_hosts;
	char *drone_str;
	char *listen_addr;
	drone_head_t *dlh;

	uint8_t delay_type_exp;

	void *children;

	uint8_t forklocal;
	uint8_t covertness;

	char *mod_dir;
	char *module_enable;
	mod_params_t *mod_params;
	void *report_mod_jit;

	void *pri_work;

	FILE *_stdout;
	FILE *_stderr;

	payload_lh_t *plh;

	void *argv_ext;
	void *dns;
} settings_t;

#ifndef MODULE
extern settings_t *s;
#endif

/*
 * sender thread constants
 */
#define S_SHUFFLE_PORTS		1
#define S_SRC_OVERRIDE		2
#define S_DEFAULT_PAYLOAD	4
#define S_BROKEN_TRANS		8
#define S_BROKEN_NET		16
#define S_SENDER_INTR		32	/* we can interrupt the sender with new work (high priority)		*/

#define GET_SHUFFLE()		(s->send_opts & S_SHUFFLE_PORTS)
#define GET_OVERRIDE()		(s->send_opts & S_SRC_OVERRIDE)
#define GET_DEFAULT()		(s->send_opts & S_DEFAULT_PAYLOAD)
#define GET_BROKENTRANS()	(s->send_opts & S_BROKEN_TRANS)
#define GET_BROKENNET()		(s->send_opts & S_BROKEN_NET)
#define GET_SENDERINTR()	(s->send_opts & S_SENDER_INTR)

#define SET_SHUFFLE(x)		((x) ? (s->send_opts |= S_SHUFFLE_PORTS)   : (s->send_opts &= ~(S_SHUFFLE_PORTS)))
#define SET_OVERRIDE(x)		((x) ? (s->send_opts |= S_SRC_OVERRIDE)    : (s->send_opts &= ~(S_SRC_OVERRIDE)))
#define SET_DEFAULT(x)		((x) ? (s->send_opts |= S_DEFAULT_PAYLOAD) : (s->send_opts &= ~(S_DEFAULT_PAYLOAD)))
#define SET_BROKENTRANS(x)	((x) ? (s->send_opts |= S_BROKEN_TRANS)    : (s->send_opts &= ~(S_BROKEN_TRANS)))
#define SET_BROKENNET(x)	((x) ? (s->send_opts |= S_BROKEN_NET)      : (s->send_opts &= ~(S_BROKEN_NET)))
#define SET_SENDERINTR(x)	((x) ? (s->send_opts |= S_SENDER_INTR)     : (s->send_opts &= ~(S_SENDER_INTR)))

/*
 * master thread constants
 */
#define M_PROC_ERRORS		1	/* icmp + tcp resets							*/
#define M_IMMEDIATE		2	/* display as we get it in an informal format				*/
#define M_LISTEN_DRONE		4
#define M_SEND_DRONE		8
#define M_OUTPUT_DRONE		16
#define M_DO_CONNECT		32
#define M_REPORT_QUIET		64	/* no default scan output at all, just put it into the output modules	*/
#define M_IGN_ROOT		128
#define M_DO_DNS		256	/* in reporting, do reverse dns lookups (at least)			*/
#define M_DO_TRANS		512	/* translate open/closed						*/
#define M_PROC_DUPS		1024	/* chain duplicate report structures					*/

#define GET_PROCERRORS()	(s->options & M_PROC_ERRORS)
#define GET_IMMEDIATE()		(s->options & M_IMMEDIATE)
#define GET_LISTENDRONE()	(s->options & M_LISTEN_DRONE)
#define GET_SENDDRONE()		(s->options & M_SEND_DRONE)
#define GET_OUTPUTDRONE()	(s->options & M_OUTPUT_DRONE)
#define GET_DOCONNECT()		(s->options & M_DO_CONNECT)
#define GET_REPORTQUIET()	(s->options & M_REPORT_QUIET)
#define GET_IGNROOT()		(s->options & M_IGN_ROOT)
#define GET_DODNS()		(s->options & M_DO_DNS)
#define GET_DOTRANS()		(s->options & M_DO_TRANS)
#define GET_PROCDUPS()		(s->options & M_PROC_DUPS)

#define SET_PROCERRORS(x)	((x) ? (s->options |= M_PROC_ERRORS)  : (s->options &= ~(M_PROC_ERRORS)))
#define SET_IMMEDIATE(x)	((x) ? (s->options |= M_IMMEDIATE)    : (s->options &= ~(M_IMMEDIATE)))
#define SET_LISTENDRONE(x)	((x) ? (s->options |= M_LISTEN_DRONE) : (s->options &= ~(M_LISTEN_DRONE)))
#define SET_SENDDRONE(x)	((x) ? (s->options |= M_SEND_DRONE)   : (s->options &= ~(M_SEND_DRONE)))
#define SET_OUTPUTDRONE(x)	((x) ? (s->options |= M_OUTPUT_DRONE) : (s->options &= ~(M_OUTPUT_DRONE)))
#define SET_DOCONNECT(x)	((x) ? (s->options |= M_DO_CONNECT)   : (s->options &= ~(M_DO_CONNECT)))
#define SET_REPORTQUIET(x)	((x) ? (s->options |= M_REPORT_QUIET) : (s->options &= ~(M_REPORT_QUIET)))
#define SET_IGNROOT(x)		((x) ? (s->options |= M_IGN_ROOT)     : (s->options &= ~(M_IGN_ROOT)))
#define SET_DODNS(x)		((x) ? (s->options |= M_DO_DNS)       : (s->options &= ~(M_DO_DNS)))
#define SET_DOTRANS(x)		((x) ? (s->options |= M_DO_TRANS)     : (s->options &= ~(M_DO_TRANS)))
#define SET_PROCDUPS(x)		((x) ? (s->options |= M_PROC_DUPS)    : (s->options &= ~(M_PROC_DUPS)))

/*
 * recv thread constants
 */
#define L_WATCH_ERRORS		1	/* add icmp to the pcap filter, etc					*/
#define L_USE_PROMISC		2	/* mostly for -s stuff XXX check for aliases				*/
#define L_DO_CONNECT		4	/* do connection stuff							*/
#define L_IGNORE_RSEQ		8	/* ignore reset seq's, report anyhow (if watch errors is set anyhow)	*/
#define L_IGNORE_SEQ		16	/* ignore ALL seq's...							*/
#define L_SNIFF			32	/* display packet parsing information					*/

#define GET_WATCHERRORS()	(s->recv_opts & L_WATCH_ERRORS)
#define GET_PROMISC()		(s->recv_opts & L_USE_PROMISC)
#define GET_LDOCONNECT()	(s->recv_opts & L_DO_CONNECT)
#define GET_IGNORERSEQ()	(s->recv_opts & L_IGNORE_RSEQ)
#define GET_IGNORESEQ()		(s->recv_opts & L_IGNORE_SEQ)
#define GET_SNIFF()		(s->recv_opts & L_SNIFF)

#define SET_WATCHERRORS(x)	((x) ? (s->recv_opts |= L_WATCH_ERRORS) : (s->recv_opts &= ~(L_WATCH_ERRORS)))
#define SET_PROMISC(x)		((x) ? (s->recv_opts |= L_USE_PROMISC)  : (s->recv_opts &= ~(L_USE_PROMISC)))
#define SET_LDOCONNECT(x)	((x) ? (s->recv_opts |= L_DO_CONNECT)   : (s->recv_opts &= ~(L_DO_CONNECT)))
#define SET_IGNORERSEQ(x)	((x) ? (s->recv_opts |= L_IGNORE_RSEQ)  : (s->recv_opts &= ~(L_IGNORE_RSEQ)))
#define SET_IGNORESEQ(x)	((x) ? (s->recv_opts |= L_IGNORE_SEQ)   : (s->recv_opts &= ~(L_IGNORE_SEQ)))
#define SET_SNIFF(x)		((x) ? (s->recv_opts |= L_SNIFF)        : (s->recv_opts &= ~(L_SNIFF)))

char *stroptions (uint16_t );
char *strrecvopts(uint16_t );
char *strsendopts(uint16_t );
#endif
