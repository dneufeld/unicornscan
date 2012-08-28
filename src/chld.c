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

#include <unilib/terminate.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/arch.h>
#include <unilib/drone.h>
#include <unilib/modules.h>

#include <usignals.h>

#define MAX_CHILDREN 16

static int child_forked=0;

void chld_init(void) {

	child_forked=0;

	return;
}

void chld_reapall(void) {
	int cnt=0;

	while (child_forked != signals_deadcount()) {
		cnt++;
		usleep(10000);
		if (cnt > 100) {
			ERR("am i missing children?, oh well");
			break;
		}
	}

	return;
}

int chld_waitsync(void) {
	int j=0;

	for (j=0; j < 50; j++) {
		/* if a child dies before syncing this will get ugly */
		if (signals_synccount() >= child_forked) {
			return 0;
		}
		usleep(10000);
	}

	/* if we dont get the children now, well defer failure until we cant connect to them */

	return 1;
}

int chld_fork(void) {
	pid_t chld_listener=-1, chld_sender=-1;
	char verbose_level[32], sendername[32], listenername[32];

	sprintf(verbose_level, "%u", s->verbose);

	/* initialize senders */
	if ((s->forklocal & FORK_LOCAL_SENDER) == FORK_LOCAL_SENDER) {

		drone_add(DEF_SENDER);

		chld_sender=fork();
		if (chld_sender < 0) {
			ERR("cant fork sender: %s", strerror(errno));
			return -1;
		}
		else if (chld_sender == 0) {
			char *argz[8];
			char *envz[1];

			sprintf(sendername, "%s", SENDERNAME);
			argz[0]=sendername;
			argz[1]=s->profile;
			argz[2]=s->mod_dir;
			argz[3]=verbose_level;
			argz[4]=s->debugmaskstr;
			argz[5]=s->interface_str;
			argz[6]=xstrdup(DEF_SENDER);
			argz[7]=NULL;

			envz[0]='\0';

			DBG(M_CLD, "execve %s %s %s %s %s %s %s %s",
				SENDER_PATH, argz[0], argz[1], argz[2], argz[3], argz[4], argz[5], argz[6]
			);

			execve(SENDER_PATH, (char * const *)argz, (char * const *)envz);

			s->forked=1;
			terminate("execve `%s' fails", SENDER_PATH);
		}

		child_forked++;

		s->forklocal &= ~(FORK_LOCAL_SENDER);
	}
	else {
		DBG(M_CLD, "no local sender will be forked");
	}

	/* initialize listeners */
	if ((s->forklocal & FORK_LOCAL_LISTENER) == FORK_LOCAL_LISTENER) {

		drone_add(DEF_LISTENER);

		chld_listener=fork();
		if (chld_listener < 0) {
			ERR("cant fork listener: %s", strerror(errno));
			return -1;
		}
		else if (chld_listener == 0) {
			char *argz[11];
			char *envz[1];
			char mtu[8];

			snprintf(mtu, sizeof(mtu) -1, "%u", s->vi[0]->mtu);

			sprintf(listenername, "%s", LISTENERNAME);
			argz[0]=listenername;
			argz[1]=s->profile;
			argz[2]=s->mod_dir;
			argz[3]=verbose_level;
			argz[4]=s->debugmaskstr;
			argz[5]=s->interface_str;
			argz[6]=s->vi[0]->myaddr_s;
			argz[7]=s->vi[0]->hwaddr_s;
			argz[8]=(s->pcap_dumpfile == NULL ? xstrdup("none") : s->pcap_dumpfile);
			argz[9]=xstrdup(DEF_LISTENER);
			argz[10]=NULL;

			envz[0]='\0';

			DBG(M_CLD, "execve %s %s %s %s %s %s %s %s %s %s %s",
				LISTENER_PATH, argz[0], argz[1], argz[2], argz[3],
				argz[4], argz[5], argz[6], argz[7], argz[8], argz[9]
			);
			execve(LISTENER_PATH, argz, envz);

			s->forked=1;
			terminate("execve %s fails", LISTENER_PATH);
		}

		child_forked++;

		s->forklocal &= ~(FORK_LOCAL_LISTENER);
	}
	else {
		DBG(M_CLD, "no local listener will be forked");
	}

	return 1;
}
