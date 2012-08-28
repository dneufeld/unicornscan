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
#include <settings.h>
#include <scan_progs/scan_export.h>
#include <scan_progs/portfunc.h>

#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/prng.h>
#include <unilib/rbtree.h>

static int32_t *ports=NULL;
static uint32_t num_ports=0;
static int32_t *user_index=0;

void reset_getnextport(void) {

	user_index=&ports[0];

	return;
}

int get_nextport(int32_t *in) {
	assert(user_index != NULL);

	if (*user_index == -1) {
		return -1;
	}
	else {
		*in=*user_index;
		user_index++;
	}

	return 1;
}

void shuffle_ports(void) {
	uint32_t ss=0, d=0, indx=0;
	int j=0;

	DBG(M_PRT, "shuffle ports at depth %u", num_ports);

	if (num_ports < 2) {
		return;
	}

	for (j=0; j < 2; j++) {
		for (indx=0; indx < num_ports; indx++) {

			ss=(prng_get32() % num_ports);
			d=(prng_get32() % num_ports);

			if (ss == d) {
				continue;
			}

			SWAP(ports[ss], ports[d]);
		}
	}

	if (ISDBG(M_PRT)) {

		DBG(M_PRT, "randomized ports follow");

		for (j=0; ports[j] != -1; j++) {
			DBG(M_PRT, "port in list %d", ports[j]);
		}
	}


	return;
}

int parse_pstr(const char *input, uint32_t *total_ports) {
	char *data=NULL, *dtok=NULL, *st1=NULL;
	unsigned int low=0, high=0, port_index=0;
	char *string=NULL;

	assert(input != NULL && strlen(input));

	if (input[0] == 'a' || input[0] == 'A') {
		string=xstrdup("0-65535");
	}
	else if (input[0] == 'p' || input[0] == 'P') {
		string=xstrdup("1-1024");
	}
	else {
		string=xstrdup(input);
	}

	/* GLOBAL */
	num_ports=0;

	data=xstrdup(string);

	for (dtok=strtok_r(data, ",", &st1); dtok != NULL; dtok=strtok_r(NULL, ",", &st1)) {
		if (sscanf(dtok, "%u-%u", &low, &high) == 2) {
			if (low > high) {
				SWAP(low, high);
			}
			if (low > 0xffff || high > 0xffff) {
				xfree(data);
				xfree(string);
				ERR("port out of range");

				return -1;
			}
			num_ports += ((high + 1) - low);
		}
		else if (sscanf(dtok, "%u", &low) == 1) {
			if (low > 0xffff) {
				xfree(data);
				xfree(string);
				ERR("port out of range");

				return -1;
			}
			num_ports++;
		}
		else {
			xfree(data);
			xfree(string);
			ERR("cannot parse port string `%s'", input);

			return -1;
		}
	}

	xfree(data);

	if (total_ports != NULL) {
		*total_ports=num_ports;
		xfree(string);

		return 1;
	}

	ports=(int32_t *)xmalloc((num_ports + 1) * sizeof(int32_t)); /* GLOBAL */
	port_index=0;

	data=xstrdup(string);

	for (dtok=strtok_r(data, ",", &st1); dtok != NULL; dtok=strtok_r(NULL, ",", &st1)) {
		if (sscanf(dtok, "%u-%u", &low, &high) == 2) {
			unsigned int indx=0;

			if (low > high) {
				SWAP(low, high);
			}

			if (low > 0xffff || high > 0xffff) {
				PANIC("heap corrupt?");
			}
			for (indx=low; indx < (high + 1); indx++) {
				ports[port_index++]=indx;
			}
		}
		else if (sscanf(dtok, "%u", &low) == 1) {

			if (low > 0xffff) {
				PANIC("heap corrupt?");
			}

			ports[port_index++]=low;

		}
		else {
			PANIC("heap corrupt?");
                }

	}

	ports[port_index]=-1;

	if (ISDBG(M_PRT)) {
		int j=0;

		for (j=0; ports[j] != -1; j++) {
			DBG(M_PRT, "port in list %d", ports[j]);
		}
	}

	xfree(data);
	xfree(string);

	user_index=&ports[0];

	return 1;
}

char *getservname(uint16_t port) {
	union {
		struct {
			uint32_t proto;
			uint32_t port;
		} s;
		uint64_t key;
	} key_u;
	char tmpstr[256];
	int sport=0;
	uint8_t proto=0;
	static FILE *uniservices=NULL;
	static char _name[64];
	static void *sncache=NULL;

	if (s->ss->mode == MODE_UDPSCAN) {
		proto=17;
	}
	else if (s->ss->mode == MODE_TCPSCAN) {
		proto=6;
	}
	else {
		DBG(M_PRT, "not tcp or udp, but `%d' this isnt going to work", s->ss->mode);
		strcpy(_name, "unknown");
		return &_name[0];
	}

	if (sncache == NULL) {
		sncache=rbinit(111);
	}
	else {
		union {
			char *str;
			void *p;
		} s_u;

		key_u.s.proto=proto;
		key_u.s.port=port;

		if (rbfind(sncache, key_u.key, &s_u.p) == 1) {
			assert(s_u.str != NULL);
			return s_u.str;
		}
	}

	if (uniservices == NULL) {
		DBG(M_PRT, "opening `%s' for port names", PORT_NUMBERS);

		uniservices=fopen(PORT_NUMBERS, "r");
		if (uniservices == NULL) {
			sprintf(_name, "error");

			return _name;
		}
	}
	else {
		rewind(uniservices);
	}

	while (fgets(tmpstr, sizeof(tmpstr) -1, uniservices) != NULL) {
		if (tmpstr[0] == '#') {
			continue;
		}

		switch (proto) {
			case 17:
				if (sscanf(tmpstr, "%63s %d/udp", _name, &sport) == 2) {
					if (port == sport) {
						goto cacheit;
					}
				}
				break;
			case 6:
				if (sscanf(tmpstr, "%63s %d/tcp", _name, &sport) == 2) {
					if (port == sport) {
						goto cacheit;
					}
				}
				break;

			default:
				DBG(M_PRT, "ignoring line `%s'", tmpstr);
				break;
		}
	}

	strcpy(_name, "unknown");

cacheit:

	DBG(M_PRT, "caching name %s for proto %u and port %u", _name, proto, port);

	if (rbinsert(sncache, key_u.key, xstrdup(_name)) != 1) {
		ERR("cant cache!");
		return _name;
	}

	return _name;
}

char *getouiname(uint8_t a, uint8_t b, uint8_t c) {
	char tmpstr[256];
	static FILE *ouiconf=NULL;
	static char oui_name[64];

	/* this is slow and bad, but its not critical so here it is */

	if (ouiconf == NULL) {
		DBG(M_PRT, "opening `%s' for oui names", OUI_CONF);
		ouiconf=fopen(OUI_CONF, "r");
		if (ouiconf == NULL) {
			strcpy(oui_name, "error");

			return oui_name;
		}
	}
	else {
		rewind(ouiconf);
	}

	while (fgets(tmpstr, sizeof(tmpstr) -1, ouiconf) != NULL) {
		unsigned int fa=0, fb=0, fc=0;
		if (tmpstr[0] == '#') {
			continue;
		}

		memset(oui_name, 0, sizeof(oui_name));

		sscanf(tmpstr, "%x-%x-%x:%63[^\n]", &fa, &fb, &fc, oui_name);
		if ((uint8_t)fa == a && (uint8_t)fb == b && (uint8_t)fc == c) {
			return oui_name;
		}
	}

	strcat(oui_name, "unknown");

	return oui_name;
}
