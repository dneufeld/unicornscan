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

#if defined(__i386__) || defined(__x86_64__)

#define tsc_t uint64_t

int tsc_supported(void) {
	/* XXX check cpu at runtime */
	return 1;
}

inline tsc_t get_tsc(void) {
	tsc_t j;
	asm volatile (	"pause\n"
			"nop\n"
			"rdtsc" : "=A" (j));
	return j;
}

#elif defined(__powerpc__) || defined(__ppc__)

#define tsc_t uint64_t

int tsc_supported(void) {
	/* XXX check cpu at runtime */
	return 1;
}

	/*
	 * 64 bit idea taken from kernel/cycle.h from fftw-3.0.1
	 * by Matteo Frigo
	 */

inline tsc_t get_tsc(void) {
	uint32_t tbl, tbu0, tbu1;

	asm volatile("nop");

	do {
		asm volatile ("mftbu %0" : "=r" (tbu0));
		asm volatile ("mftb  %0" : "=r" (tbl) );
		asm volatile ("mftbu %0" : "=r" (tbu1));
	} while (tbu0 != tbu1);

	return (((tsc_t)tbu0) << 32) | tbl;
}

#elif defined(__sparc_v9__)

#define tsc_t uint32_t /* shrug */

int tsc_supported(void) {
	/* XXX check cpu at runtime */
	return 1;
}

inline tsc_t get_tsc(void) {
	tsc_t j;

	asm volatile (
		"nop\n"
		"rd %%tick, %0"
		: "=r" (j)
	);

	return j;
}

#elif defined(__hppa__) /* this should be set on linux */

#define tsc_t uint32_t

int tsc_supported(void) {
	/* XXX check cpu at runtime */
	return 1;
}

inline tsc_t get_tsc(void) {
	uint32_t j;

	/*
	 * cr16 is the system interval timer and should be readable from
	 * any privledge level
	 */

	asm volatile(
		"nop\n"
		"mfctl 16, %0" /* move from control register 16 */
		: "=r" (j)
	);

	return j;
}

#if 0
/* #elif defined(__mips__) */

#define tsc_t int

/* illegal instruction on my test box */

inline tsc_t get_tsc(void) {
	volatile tsc_t ret=0;

	/* read coprocessor register 9 (count/timer) */
	asm volatile (
		"mfc0   %0,     $9\n"
		"nop\n"
		: "=r" (ret)
	);

	return ret;
}

/* #endif */
#endif

#else

#define tsc_t uint32_t /* shrug */

int tsc_supported(void) {
	return 0;
}

inline tsc_t get_tsc(void) {
	PANIC("Your CPU is not supported by the `tsc' delay, use -d2 or -d3 or edit your config file to use gtod or sleep");
}

#endif

static tsc_t tsc_delay=0;
static tsc_t tsc_s_time=0;

void tsc_init_tslot(uint32_t pps) {
	tsc_t start=0, end=0, cps=0;
	struct timespec s_time, rem;

	rem.tv_sec=0; rem.tv_nsec=0;
	s_time.tv_sec=0; s_time.tv_nsec=100000001;

	start=get_tsc();

	do {
		if (nanosleep((const struct timespec *)&s_time, &rem) != -1) break;
	} while (rem.tv_sec != 0 && rem.tv_nsec != 0);

	end=get_tsc();

	cps=(end - start) * 10;

	tsc_delay=(cps / pps);
}


void tsc_start_tslot(void) {
	tsc_s_time=get_tsc();
	return;
}

void tsc_end_tslot(void) {
	while (1) {
		if ((get_tsc() - tsc_s_time) >= tsc_delay) {
			break;
		}
	}
	tsc_s_time=0;
	return;
}
