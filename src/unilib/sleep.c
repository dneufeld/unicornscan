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

static struct timeval sleep_delay;
static struct timeval sleep_s_time;

static void get_sleep(struct timeval *tv) {
	gettimeofday(tv, NULL);
}

void sleep_init_tslot(uint32_t pps) {
	sleep_delay.tv_sec=0;
	sleep_delay.tv_usec=1000000 / pps;
}


void sleep_start_tslot(void) {
	get_sleep(&sleep_s_time);
	return;
}

void sleep_end_tslot(void) {
	struct timeval new_time;
	struct timespec s_time, rem;
	time_t secs_off=0;
	suseconds_t micro_off=0;

	get_sleep(&new_time);

	secs_off=new_time.tv_sec - sleep_s_time.tv_sec;
	micro_off=new_time.tv_usec - sleep_s_time.tv_usec;

	if (secs_off > sleep_delay.tv_sec) {
		/* WHOA this thing is SSLLOOWW */
		return;
	}

	if (secs_off == 0 && micro_off > sleep_delay.tv_usec) {
		struct timespec kludge, krem;
		/* well do something here to make sure we lag a little bit otherwise the pps can go really high */
		kludge.tv_sec=0;
		kludge.tv_nsec=1;
		nanosleep((const struct timespec *)&kludge, &krem);
		return;
	}

	rem.tv_sec=0; rem.tv_nsec=0;

	s_time.tv_sec=sleep_delay.tv_sec - secs_off;
	s_time.tv_nsec=(sleep_delay.tv_usec - micro_off) * 1000;

	do {
		if (nanosleep((const struct timespec *)&s_time, &rem) != -1) break;
	} while (rem.tv_sec != 0 && rem.tv_nsec != 0);

	return;
}
