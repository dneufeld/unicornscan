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
#ifndef _OUTPUT_H
# define _OUTPUT_H

#define M_INFO	0
#define M_OUT	1
#define M_ERR	2
#define M_VERB	3
#define M_DBG	4

void _display(int, const char *, int, const char *, ...) _PRINTF45_;

#define M_WRK	1	/* workunit		*/
#define M_WRKSTR	"workunit"
#define M_RTE	2	/* route/arp		*/
#define M_RTESTR	"route"
#define M_DRN	4	/* drones		*/
#define M_DRNSTR	"drone"
#define M_MOD	8	/* modules		*/
#define M_MODSTR	"module"
#define M_SCK	16	/* socket		*/
#define M_SCKSTR	"socket"
#define M_DNS	32	/* dns stuff		*/
#define M_DNSSTR	"dns"
#define M_IPC	64	/* ...			*/
#define M_IPCSTR	"ipc"
#define M_PIO	128	/* poll inout		*/
#define M_PIOSTR	"poll"
#define M_SND	256	/* send packet		*/
#define M_SNDSTR	"send"
#define M_CON	512	/* tcp conns		*/
#define M_CONSTR	"conn"
#define M_CLD	1024	/* forked child		*/
#define M_CLDSTR	"child"
#define M_PRT	2048	/* port stuff		*/
#define M_PRTSTR	"port"
#define M_MST	4096	/* master control	*/
#define M_MSTSTR	"master"
#define M_RPT	8192	/* reporting code	*/
#define M_RPTSTR	"report"
#define M_PKT	16384	/* packet parsing	*/
#define M_PKTSTR	"packet"
#define M_CNF	32768	/* configuration	*/
#define M_CNFSTR	"conf"
#define M_PYL	65536	/* payloads		*/
#define M_PYLSTR	"payload"
#define M_INT	131072	/* interface stuff	*/
#define M_INTSTR	"interface"

#define M_ALL 0x7fffffff

#define ISDBG(facility) \
	((s->debugmask & (facility)) == facility)

#define INF(fmt, args...) \
	_display(M_INFO, __FILE__, __LINE__, fmt, ## args)

#define OUT(fmt, args...) \
	_display(M_OUT, __FILE__, __LINE__, fmt, ## args)

#define DBG(facility, fmt, args...) \
	if ((s->debugmask & (facility)) == facility) { \
		_display(M_DBG, __FILE__, __LINE__, (fmt), ## args); \
	}

#define VRB(lvl, fmt, args...) \
	if (s->verbose > (lvl)) { \
		_display(M_VERB, __FILE__, __LINE__, (fmt), ## args); \
	}

#define ERR(fmt, args...) \
	_display(M_ERR, __FILE__, __LINE__, fmt, ## args)

void hexdump(const uint8_t *, size_t );

#endif
