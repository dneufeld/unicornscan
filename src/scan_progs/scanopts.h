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
#ifndef _SCAN_OPTS_H
# define _SCAN_OPTS_H

/* nothing other than the scan option code and scan_module code should touch this (perhaps modules too) */

typedef struct scan_settings_t {
	char *port_str;

	struct sockaddr_storage target;
	struct sockaddr_storage targetmask;

	/* OS fingerprint to emulate */
	uint16_t fingerprint;

	/* ip options */
	uint8_t tos;
	uint8_t minttl;
	uint8_t maxttl;
	uint16_t ip_off;

	uint32_t ip6flow;

	uint16_t mtu;

	uint8_t ipoptions[64];
	uint8_t ipoptions_len;

	/* tcp options */
	uint16_t tcphdrflgs;		/* TH_SYN etc				*/
	uint8_t tcpoptions[64];		/* options used during handshake	*/
	uint8_t tcpoptions_len;		/*					*/
	uint8_t posttcpoptions[64];	/* non-handshake options		*/
	uint8_t posttcpoptions_len;	/*					*/
	uint32_t window_size;		/*					*/
	uint32_t syn_key;		/* used to xor things against		*/

	uint8_t mode;			/* MODE_TCPSCAN, etc			*/
	uint8_t recv_timeout;		/* in secs to wait for responces	*/
	uint8_t ret_layers;		/* how many layers of packet to return	*/
	int header_type;		/* type of link layer in use		*/
	uint16_t header_len;		/* length of the `link layer' header	*/

	int32_t src_port;		/* -1 for random, otherwise uint16_t	*/
} scan_settings_t;

#ifdef SCANSETTINGS
# warning check headers!
# undef SCANSETTINGS
#endif

#define SCANSETTINGS scan_settings_t

#endif
