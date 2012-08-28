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

#include <ctype.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>

#include <scan_progs/options.h>

#include <settings.h>
#include <unilib/xmalloc.h>
#include <unilib/xipc.h>
#include <unilib/output.h>
#include <unilib/modules.h>
#include <unilib/prng.h>
#include <unilib/cidr.h>
#include <scan_progs/portfunc.h>
#include <scan_progs/workunits.h>

int scan_getmode(void) {
	return s->ss->mode;
}

void scan_setprivdefaults() {

	s->ss=(SCANSETTINGS *)xmalloc(sizeof(SCANSETTINGS));

	memset(s->ss, 0, sizeof(SCANSETTINGS));

	/* default mode is tcp syn scan */
	s->ss->mode=MODE_TCPSCAN;
	s->ss->tcphdrflgs=TH_SYN; /* FSRPAUEC */
	s->ss->src_port=-1;
	s->ss->recv_timeout=DEF_SCANTIMEOUT; /* in config.h */
	s->ss->window_size=0x1000;

	s->ss->syn_key=prng_get32();

	return;
}

int scan_setsrcp(int port) {

	if (port < -1 || port > 0xffff) {
		ERR("source port `%d' out of range", port);
		return -1;
	}
	s->ss->src_port=(int32_t)port;

	return 1;
}

int scan_setretlayers(int layers) {

	if (layers < 0) {
		s->ss->ret_layers=0xff;
	}

	if (layers > 0xff) {
		ERR("too many layers");
		return -1;
	}

	s->ss->ret_layers=(uint8_t)layers;

	return 1;
}

int scan_setfingerprint(int fp) {

	if (fp < 0 || fp > 0xffff) {
		ERR("bad fingerprint value");
		return -1;
	}

	s->ss->fingerprint=(uint16_t)fp;

	return 1;
}

int scan_setttl(const char *ttl) {
	unsigned short int a=0, b=0;

	if (ttl == NULL) {
		return -1;
	}

	if (sscanf(ttl, "%hu-%hu", &a, &b) == 2) {
		if (a > 0xff || b > 0xff) {
			ERR("ttl out of range");
			return -1;
		}
		if (a > b) {
			unsigned short int t=0;

			t=a;
			a=b;
			b=t;
		}

		s->ss->minttl=(uint8_t)a;
		s->ss->maxttl=(uint8_t)b;
	}
	else if (sscanf(ttl, "%hu", &a) == 1) {
		if (a > 0xff) {
			ERR("ttl out of range");
			return -1;
		}
		s->ss->minttl=(uint8_t)a;
		s->ss->maxttl=(uint8_t)a;
	}
	else {
		ERR("bad ttl option `%s'", ttl);
		return -1;
	}

	return 1;
}

int scan_setsrcaddr(const char *addr) {
	unsigned int msk=0;

	if (addr == NULL || strlen(addr) < 1) {
		return -1;
	}

	if (cidr_get(addr, (struct sockaddr *)&s->vi[0]->myaddr, (struct sockaddr *)&s->vi[0]->mymask, &msk) < 0) {
		ERR("invalid source address `%s'", addr);
		return -1;
	}
	strncpy(s->vi[0]->myaddr_s, cidr_saddrstr((const struct sockaddr *)&s->vi[0]->myaddr), sizeof(s->vi[0]->myaddr_s) -1);

	DBG(M_CNF, "using explicit (user) source address `%s/%u'", s->vi[0]->myaddr_s, msk);

#if 0
	char *tok=NULL, *rent=NULL, *sdup=NULL;
	sdup=xstrdup(addr);

	for (tok=strtok_r(sdup, ",", &rent); tok != NULL; tok=strtok_r(NULL, ",", &rent)) {
	}
#endif

	SET_OVERRIDE(1);
	SET_PROMISC(1);

        return 1;
}

int scan_settos(int tos) {

	if (tos > 0xff || tos < 0) {
		ERR("tos out of range");
		return -1;
	}

	s->ss->tos=(uint8_t)tos;

	return 1;
}

int scan_setbroken(const char *instr) {

	if (instr == NULL || strlen(instr) < 1) {
		return -1;
	}

	if (instr[0] == 'N') {
		SET_BROKENNET(1);
	}
	else if (instr[0] == 'T') {
		SET_BROKENTRANS(1);
	}
	else {
		return -1;
	}

	if (instr[1] != '\0') {
		if (instr[1] == 'N') {
			SET_BROKENNET(1);
		}
		else if (instr[1] == 'T') {
			SET_BROKENTRANS(1);
		}
		else {
			return -1;
		}
	}

	return 1;
}

int scan_settcpflags(int flags) {

	if (flags < 0 || flags > 0xff) {
		ERR("TCP flags out of range");
		return -1;
	}

	s->ss->tcphdrflgs=flags;

	return 1;
}

int scan_setrecvtimeout(int seconds) {

	if (seconds < 0 || seconds > 0xff) {
		return -1;
	}

	s->ss->recv_timeout=seconds;

	return 1;
}

int scan_getrecvtimeout(void) {
	return s->ss->recv_timeout;
}

int scan_setoptmode(const char *str) {
	return scan_parsemode(str, &s->ss->mode, &s->ss->tcphdrflgs, &s->send_opts, &s->recv_opts, &s->options, &s->pps);
}

int scan_parsemode(const char *str, uint8_t *mode, uint16_t *flags, uint16_t *sf, uint16_t *lf, uint16_t *mf, uint32_t *pps) {
	int ret=0;
	const char *walk=NULL;

	assert(str != NULL);
	assert(mode != NULL); assert(flags != NULL); assert(sf != NULL);
	assert(lf != NULL); assert(mf != NULL); assert(pps != NULL);

	if (strlen(str) < 1) {
		return -1;
	}

	*pps=s->pps;

	walk=str;

	if (*walk == 'T') {

		*mode=MODE_TCPSCAN;

		walk++;
		/* check to see if the user specified TCP flags with TCP mode */
		if (strlen(walk) > 0) {
			ret=decode_tcpflags(walk);
			if (ret < 0) {
				ERR("bad tcp flags `%s'", str);
				return -1;
			}
			*flags=(uint16_t)ret;

			for (;*walk != '\0' && ! isdigit(*walk); walk++) {
				;
			}
		}
	}
	else if (*walk == 'U') {
		*mode=MODE_UDPSCAN;
		walk++;
	}
	else if (*walk == 'A') {
		*mode=MODE_ARPSCAN;
		walk++;
	}
	else if (*walk == 's' && *(walk + 1) == 'f') {
		*mode=MODE_TCPSCAN;
		/* XXX */
		*mf |= M_DO_CONNECT;
		*lf |= L_DO_CONNECT;
		*sf |= S_SENDER_INTR;
		/* XXX */
		if (scan_setretlayers(0xff) < 0) {
			ERR("unable to request packet transfer though IPC, exiting");
	                return -1;
		}
		walk += 2;

		/* check to see if the user specified TCP flags with TCP mode */
		if (strlen(walk) > 0) {
			ret=decode_tcpflags(walk);
			if (ret < 0) {
				ERR("bad tcp flags `%s'", str);
				return -1;
			}
			*flags=(uint16_t)ret;

			for (;*walk != '\0' && ! isdigit(*walk); walk++) {
				;
			}
		}
	}
	else {
		ERR("unknown scanning mode `%c'", str[1]);
		return -1;
	}

	if (*walk == '\0') {
		return 1;
	}

	if (sscanf(walk, "%u", pps) == 1) {
		return 1;
	}

	/* this isnt likely possible */
	ERR("bad pps `%s', using default %u", walk, s->pps);

	*pps=s->pps;

	return 1;
}

int decode_tcpflags(const char *str) {
	int ret=0;

	for (; *str != '\0' && (! isdigit(*str)); str++) {
		switch (*str) {
			case 'F':
				ret |= TH_FIN;
				break;
			case 'f':
				ret &= ~(TH_FIN);
				break;
			case 'S':
				ret |= TH_SYN;
				break;
			case 's':
				ret &= ~(TH_SYN);
				break;
			case 'R':
				ret |= TH_RST;
				break;
			case 'r':
				ret &= ~(TH_RST);
				break;
			case 'P':
				ret |= TH_PSH;
				break;
			case 'p':
				ret &= ~(TH_PSH);
				break;
			case 'A':
				ret |= TH_ACK;
				break;
			case 'a':
				ret &= ~(TH_ACK);
				break;
			case 'U':
				ret |= TH_URG;
				break;
			case 'u':
				ret &= ~(TH_URG);
				break;
			case 'E':
				ret |= TH_ECE;
				break;
			case 'e':
				ret &= ~(TH_ECE);
				break;
			case 'C':
				ret |= TH_CWR;
				break;
			case 'c':
				ret &= ~(TH_CWR);
				break;
			default:
				ERR("unknown TCP flag `%c' (FfSsRrPpAaUuEeCc are valid)", *str);
				return -1;
		} /* switch *str */
	} /* for strlen(str) */

	return ret;
}

char *strscanmode(int mode) {
	static char modestr[64];

	CLEAR(modestr);

	switch (mode) {
		case MODE_TCPSCAN:
			strcpy(modestr, "TCPscan");
			break;

		case MODE_UDPSCAN:
			strcpy(modestr, "UDPscan");
			break;

		case MODE_ARPSCAN:
			strcpy(modestr, "ARPscan");
			break;

		case MODE_ICMPSCAN:
			strcpy(modestr, "ICMPscan");
			break;

		case MODE_IPSCAN:
			strcpy(modestr, "IPscan");
			break;

		default:
			sprintf(modestr, "Unknown [%d]", mode);
			break;
	}

	return modestr;
}
