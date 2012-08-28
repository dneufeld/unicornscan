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

#include <settings.h>

#include <unilib/pktutil.h>

#include <scan_progs/packets.h>
#include <scan_progs/scan_export.h>

/*
 * type -> name mapping functions
 * all return pointers to static buffers, carefull
 */

char *decode_6mac(const uint8_t *mac) {
	static char str[32];

	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", *mac, *(mac + 1), *(mac + 2), *(mac + 3), *(mac + 4), *(mac + 5));

	return str;
}

char *str_opcode(uint16_t opcode) {
	static char name[32];

	memset(name, 0, sizeof(name));

	switch (opcode) {
		case ARPOP_REQUEST:
			strcat(name, "ARP Request"); break;
		case ARPOP_REPLY:
			strcat(name, "ARP Reply"); break;
		case ARPOP_RREQUEST:
			strcat(name, "RARP Request"); break;
		case ARPOP_RREPLY:
			strcat(name, "RARP Reply"); break;
		case ARPOP_INREQUEST:
			strcat(name, "InARP Request"); break;
		case ARPOP_INREPLY:
			strcat(name, "InARP Request"); break;
		case ARPOP_NAK:
			strcat(name, "ARM ARP NAK"); break;
		default:
			sprintf(name, "Unknown [%u]", opcode); break;
	}
	return name;
}

char *str_hwtype(uint16_t hw_type) {
	static char name[32];

	memset(name, 0, sizeof(name));

	switch (hw_type) {
		case ARPHRD_ETHER:
			strcat(name, "10/100 Ethernet"); break;
		case ARPHRD_NETROM:
			strcat(name, "NET/ROM pseudo"); break;
		case ARPHRD_EETHER:
			strcat(name, "Exp Ethernet"); break;
		case ARPHRD_AX25:
			strcat(name, "AX.25 Level 2"); break;
		case ARPHRD_PRONET:
			strcat(name, "PROnet token ring"); break;
		case ARPHRD_CHAOS:
			strcat(name, "ChaosNET"); break;
		case ARPHRD_IEEE802:
			strcat(name, "IEE 802.2 Ethernet"); break;
		case ARPHRD_ARCNET:
			strcat(name, "ARCnet"); break;
		case ARPHRD_APPLETLK:
			strcat(name, "APPLEtalk"); break;
		case ARPHRD_DLCI:
			strcat(name, "Frame Relay DLCI"); break;
		case ARPHRD_ATM:
			strcat(name, "ATM"); break;
		case ARPHRD_METRICOM:
			strcat(name, "Metricom STRIP"); break;
		default:
			sprintf(name, "NON-ARP? Unknown [%u]", hw_type); break;
	}
	return name;
}

char *str_hwproto(uint16_t proto) {
	static char name[32];

	memset(name, 0, sizeof(name));

	switch (proto) {
		case 8:
			strcat(name, "Ether Arp IP"); break;
		default:
			sprintf(name, "Unknown [%u]", proto); break;
	}

	return name;
}

char *str_ipproto(uint8_t proto) {
	static char name[32];

	memset(name, 0, sizeof(name));

	switch (proto) {
		case IPPROTO_TCP:
			strcat(name, "IP->TCP"); break;
		case IPPROTO_UDP:
			strcat(name, "IP->UDP"); break;
		case IPPROTO_ICMP:
			strcat(name, "IP->ICMP"); break;
		default:
			sprintf(name, "Unknown [%02x]", proto); break;
	}
	return name;
}

char *strtcpflgs(int flags) {
	static char tcphdrflags[16];

	memset(tcphdrflags, '-', 8);
	if (flags & TH_FIN) tcphdrflags[0]='F';
	if (flags & TH_SYN) tcphdrflags[1]='S';
	if (flags & TH_RST) tcphdrflags[2]='R';
	if (flags & TH_PSH) tcphdrflags[3]='P';
	if (flags & TH_ACK) tcphdrflags[4]='A';
	if (flags & TH_URG) tcphdrflags[5]='U';
	if (flags & TH_ECE) tcphdrflags[6]='E';
	if (flags & TH_CWR) tcphdrflags[7]='C';
	tcphdrflags[8]='\0';

	return tcphdrflags;
}
