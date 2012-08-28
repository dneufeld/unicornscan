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
#include <unilib/xdelay.h>

static uint64_t tod_delay=0;
static uint64_t tod_s_time=0;

static uint64_t get_tod(void) {
	struct timeval tv;
	uint64_t tt=0;

	gettimeofday(&tv, NULL);

	tt=tv.tv_sec;
	/* some 64 bit platforms have massive tv_usecs, truncate them */
	tt=tt << (4 * 8);
	tt += (uint32_t)(tv.tv_usec & 0xffffffff);

	return tt;
}

void gtod_init_tslot(uint32_t pps) {
	uint64_t start=0, end=0, cps=0;
	struct timespec s_time, rem;

	rem.tv_sec=0; rem.tv_nsec=0;
	s_time.tv_sec=0; s_time.tv_nsec=100000001;

	start=get_tod();

	do {
		if (nanosleep((const struct timespec *)&s_time, &rem) != -1) break;
	} while (rem.tv_sec != 0 && rem.tv_nsec != 0);

	end=get_tod();

	cps=(end - start) * 10;

	tod_delay=(cps / pps);
}


void gtod_start_tslot(void) {
	tod_s_time=get_tod();
	return;
}

void gtod_end_tslot(void) {
	while (1) {
		if ((get_tod() - tod_s_time) >= tod_delay) {
			break;
		}
	}
	tod_s_time=0;
	return;
}
