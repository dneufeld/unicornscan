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

#include <stdarg.h>
#if defined(WITH_BACKTRACE) && defined(DEBUG_SUPPORT)
#include <execinfo.h>
#endif
#include <errno.h>

void panic(const char *func, const char *file, int lineno, const char *msg, ...) {
	va_list ap;
	char pbuf[2048];
#if defined(WITH_BACKTRACE) && defined(DEBUG_SUPPORT)
	void *array[50];
	int size;
#endif

	va_start(ap, msg);
	vsnprintf(pbuf, sizeof(pbuf) -1, msg, ap);

	fprintf(s->_stderr, "%s PANIC IN %s [%s:%d]: %s\n", (ident_name_ptr == NULL ? "Unknown" : ident_name_ptr), func, file, lineno, pbuf);

#if defined(WITH_BACKTRACE) && defined(DEBUG_SUPPORT)
	size=backtrace(array, 50);
	fprintf(s->_stderr, "Obtained %d stack frames.\n", size);
	/* similar to backtrace_symbols but avoids malloc */
	backtrace_symbols_fd(array, size, fileno(s->_stderr));
#endif

	abort();
}

#ifdef DEBUG_SUPPORT

#define BSOD_START	"\x1b[44;37m"
#define BSOD_TITLE	"\x1b[47;34m"
#define BSOD_RESET	"\x1b[00m\x0a\x1b[m"

#define RBEM	"\x1b[41;37m\n\nhtaeD fo neercS deR eht si siht\n\n" BSOD_RESET

#define ERROR_MSG  \
BSOD_START "\n\n" \
  "             " BSOD_TITLE "UNICORNSCAN" BSOD_START "                  \n" \
  "A fatal exception %d:%d has occured at %p in %s (%d)\n" \
  "The current process will be killed.\n\n" \
  "    - Press CTRL+C to stop your scan. You will lose any unsaved\n" \
  "    information in unicornscan\n" \
  "\n\n" BSOD_RESET

/* XXX dont use printf ;] */
void bluescreen(int signo, siginfo_t *si, void *not_used) {
#ifdef WITH_BACKTRACE
	void *array[50];
	int size;
#endif

	if (si == NULL) goto really_bad_error;

	switch (si->si_signo) {
		case SIGILL:
		case SIGSEGV:
		case SIGBUS:
		case SIGFPE:
			if (si->si_addr == NULL) goto really_bad_error;

			fprintf(stderr, ERROR_MSG, si->si_signo, si->si_code, si->si_addr, (ident_name_ptr == NULL ? "Unknown" : ident_name_ptr), si->si_errno);
			break;
		default:
			goto really_bad_error;
	}

#ifdef WITH_BACKTRACE
	size=backtrace(array, 50);
	fprintf(stderr, "Obtained %d stack frames.\n", size);
	/* similar to backtrace_symbols but avoids malloc */
	backtrace_symbols_fd(array, size, 2);
#endif
	raise(SIGABRT);
	_exit(-1);

really_bad_error:

	write(2, RBEM, sizeof(RBEM));

	raise(SIGABRT);
	_exit(-1);
}

void bluescreen_register(void) {
	struct sigaction crash, abrt;

	memset(&crash, 0, sizeof(crash));
	memset(&abrt, 0, sizeof(abrt));

	sigemptyset(&crash.sa_mask);
	crash.sa_flags=SA_SIGINFO;
	crash.sa_sigaction=&bluescreen;

	if (sigaction(SIGSEGV, &crash, NULL) < 0) {
		PANIC("cant register SEGV handler: %s", strerror(errno));
	}
	if (sigaction(SIGILL, &crash, NULL) < 0) {
		PANIC("cant register ILL handler: %s", strerror(errno)); 
	}
	if (sigaction(SIGFPE, &crash, NULL) < 0) {
		PANIC("cant register FPE handler: %s", strerror(errno));
	}
	if (sigaction(SIGBUS, &crash, NULL) < 0) {
		PANIC("cant register BUS handler: %s", strerror(errno));
	}

	sigemptyset(&abrt.sa_mask);
	abrt.sa_handler=SIG_DFL;
	if (sigaction(SIGABRT, &abrt, NULL) < 0) {
		PANIC("cant register default ABRT handler: %s", strerror(errno));
	}

	return;
}

#endif
