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

#include <errno.h>
#include <signal.h>

#include <settings.h>

#include <unilib/output.h>
#include <usignals.h>

static int children_synced=0, children_dead=0;

static void signals_chldsync(int );
static void signals_chlddead(int );

void signals_setup(void) {
#ifdef DEBUG_SUPPORT
	bluescreen_register();
#endif
	return;
}

int signals_children(void) {
	struct sigaction chsa;

	if (s->forklocal) {
		DBG(M_CLD, "children will be forked, setting up signal handler for them");

		chsa.sa_handler=&signals_chlddead;
		sigemptyset(&chsa.sa_mask);
		chsa.sa_flags=SA_NOCLDSTOP;

		if (sigaction(SIGCHLD, &chsa, NULL) < 0) {
			ERR("cant register SIGCHLD handler");
			return -1;
		}

		chsa.sa_handler=&signals_chldsync;
		sigemptyset(&chsa.sa_mask);
		chsa.sa_flags=0;
#ifdef SA_RESTART
		chsa.sa_flags |= SA_RESTART;
#endif

		if (sigaction(UNI_SYNC_SIGNAL, &chsa, NULL) < 0) {
			ERR("cant register SYNC handler");
			return -1;
		}
	}

	return 1;
}

static void signals_chldsync(int signo) {

	if (signo == UNI_SYNC_SIGNAL) {
		++children_synced;
	}

	return;
}

static void signals_chlddead(int signo) {
        int status=0;

        if (signo == SIGCHLD) {
		if (wait(&status) > 0) {
			++children_dead;
		}
        }

	return;
}

int signals_synccount(void) {
	return children_synced;
}

int signals_deadcount(void) {
	return children_dead;
}
