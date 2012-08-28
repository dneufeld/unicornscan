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
/* XXX include check code for hpet, rtc, or tsc in that order, using first 2 if found > tsc */
#include <config.h>

#include <settings.h>
#include <unilib/output.h>
#include <unilib/xdelay.h>

void (*r_start_tslot)(void)=NULL;
void (*r_end_tslot)(void)=NULL;

/* tsc.c */
void tsc_init_tslot(uint32_t );
void tsc_start_tslot(void);
void tsc_end_tslot(void);
int  tsc_supported(void);

/* gtod.c */
void gtod_init_tslot(uint32_t );
void gtod_start_tslot(void);
void gtod_end_tslot(void);

/* sleep.c */
void sleep_init_tslot(uint32_t );
void sleep_start_tslot(void);
void sleep_end_tslot(void);

char *delay_getopts(void) {
	static char str[64];

	sprintf(str, "%d:tsc %d:gtod %d:sleep", XDELAY_TSC, XDELAY_GTOD, XDELAY_SLEEP);
	return str;
}

int delay_gettype(const char *str) {
	assert(str != NULL); assert(strlen(str));

	if (strcmp(str, "tsc") == 0) {
		return XDELAY_TSC;
	}
	if (strcmp(str, "gtod") == 0) {
		return XDELAY_GTOD;
	}
	if (strcmp(str, "sleep") == 0) {
		return XDELAY_SLEEP;
	}
	return -1;
}

char *delay_getname(int type) {
	static char name[32];

	CLEAR(name);
	switch (type) {
		case XDELAY_TSC:
			strcpy(name, "tsc"); break;
		case XDELAY_GTOD:
			strcpy(name, "gtod"); break;
		case XDELAY_SLEEP:
			strcpy(name, "sleep"); break;
		default:
			strcpy(name, "unknown"); break;
	}

	return name;
}

int delay_getdef(uint32_t pps) {

	if (pps < 50) {
		return XDELAY_SLEEP;
	}
	else if (pps > 50 && pps < 300) {
		return XDELAY_GTOD;
	}

	if (tsc_supported()) {
		return XDELAY_TSC;
	}

	return XDELAY_GTOD;
}

void init_tslot(uint32_t pps, uint8_t delay_type) {
	switch (delay_type) {
		case XDELAY_TSC:
			if (tsc_supported()) {
				VRB(1, "using TSC delay");
				r_start_tslot=&tsc_start_tslot;
				r_end_tslot=&tsc_end_tslot;
				tsc_init_tslot(pps);
				break;
			}
			ERR("TSC delay is not supported, using gtod");
			/* fall-through */

		case XDELAY_GTOD:
			r_start_tslot=&gtod_start_tslot;
			r_end_tslot=&gtod_end_tslot;
			gtod_init_tslot(pps);
			VRB(1, "using gtod delay");
			break;

		case XDELAY_SLEEP:
			r_start_tslot=&sleep_start_tslot;
			r_end_tslot=&sleep_end_tslot;
			sleep_init_tslot(pps);
			VRB(1, "using sleep delay");
			break;

		default:
			ERR("unknown delay type %d, defaulting to gtod delay", delay_type);
			r_start_tslot=&gtod_start_tslot;
			r_end_tslot=&gtod_end_tslot;
			gtod_init_tslot(pps);
			break;

	}
	return;
}

void start_tslot(void) {
	r_start_tslot();
}

void end_tslot(void) {
	r_end_tslot();
}
