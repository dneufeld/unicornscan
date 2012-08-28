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
#include <getconfig.h>

#include <unilib/terminate.h>
#include <unilib/xmalloc.h>
#include <unilib/prng.h>
#include <unilib/output.h>
#include <unilib/xipc.h>
#include <unilib/arch.h>
#include <unilib/standard_dns.h>

#include <unilib/drone.h>
#include <unilib/modules.h>

#include <scan_progs/scan_export.h>
#include <scan_progs/master.h>
#include <scan_progs/workunits.h>
#include <scan_progs/report.h>
#include <scan_progs/connect.h>

#include <usignals.h>
#include <drone_setup.h>
#include <chld.h>

settings_t *s=NULL;
int ident=0;
const char *ident_name_ptr=NULL;

int main(int argc, char **argv) {
	unsigned int num_secs=0, time_off=0;
	char time_est[128];

	ident=IDENT_MASTER;
	ident_name_ptr=IDENT_MASTER_NAME;

	s=(settings_t *)xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));

	signals_setup();

	s->_stdout=stdout;
	s->_stderr=stderr;

	prng_init();

	time(&s->s_time);

	scan_setprivdefaults();

	s->vi=(interface_info_t **)xmalloc(sizeof(interface_info_t *));
	s->vi[0]=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	memset(s->vi[0], 0, sizeof(interface_info_t));
	s->dns=stddns_init(NULL, STDDNS_FLG_ALL);

	if (workunit_init() < 0) {
		terminate("cant initialize workunits");
	}

	/* s->display=&display_builtin; */
	if (init_payloads() < 0) {
		terminate("cant initialize payloads");
	}

	getconfig_profile(argv[0]);

	if (getconfig_argv(argc, argv) < 0) {
		terminate("unable to get configuration");
	}

	/* now parse argv data for a target -> workunit list */
	do_targets();

	if (s->interface_str == NULL) {
		if (workunit_get_interfaces() < 0) {
			terminate("cant get interface(s) for target(s) from route table");
		}
	}
	assert(s->interface_str != NULL);

	VRB(0, "using interface(s) %s", s->interface_str);

	if (init_modules() < 0) {
		terminate("cant initialize module structures, quiting");
	}

	if (init_output_modules() < 0) {
		terminate("cant initialize output module structures, quiting");
	}

	if (init_report_modules() < 0) {
		terminate("cant initialize report module structures, quiting");
	}

	if (init_payload_modules(&add_payload) < 0) {
		terminate("cant initialize payload module structures, quiting");
	}

	time_est[0]='\0';
	time_off=0;

	num_secs=s->num_secs;

	if (num_secs > (60 * 60)) {
		unsigned long long int hours=0;
		int sret=0;

		hours=num_secs / (60 * 60);

		sret=snprintf(&time_est[time_off], sizeof(time_est) - (time_off + 1), "%llu Hours, ", hours);
		assert(sret > 0);
		time_off += sret;

		num_secs -= hours * (60 * 60);
	}
	if (num_secs > 60) {
		unsigned long long int minutes=0;
		int sret=0;

		minutes=num_secs / 60;

		sret=snprintf(&time_est[time_off], sizeof(time_est) - (time_off + 1), "%llu Minutes, ", minutes);
		assert(sret > 0);
		time_off += sret;

		num_secs -= minutes * 60;
	}

	snprintf(&time_est[time_off], sizeof(time_est) - (time_off + 1), "%u Seconds", num_secs);

	VRB(0, "scaning %.2e total hosts with %.2e total packets, should take a little longer than %s",
		s->num_hosts,
		s->num_packets,
		time_est
	);

	if (GET_OVERRIDE()) {
		/* the ip info is already filled in, so just complete the rest */
		if (strlen(s->vi[0]->hwaddr_s) == 0) {
			strcpy(s->vi[0]->hwaddr_s, "00:00:00:00:00:00");
		}

		/* complete the information we need like hwaddr, cause its impossible to specify that currently */
		VRB(1, "spoofing from `%s [%s]'", s->vi[0]->myaddr_s, s->vi[0]->hwaddr_s);
        }
	else {
		/* let the listener tell us then, the user didnt request a specific address */
		strcpy(s->vi[0]->myaddr_s, "0.0.0.0");
		strcpy(s->vi[0]->hwaddr_s, "00:00:00:00:00:00");
	}

	s->vi[0]->mtu=0; /* the listener will to tell us this */

	if (ipc_init() < 0) {
		terminate("cant initialize IPC, quiting");
	}

	if (drone_init() < 0) {
		terminate("cant initialize drone structure");
	}

	DBG(M_CLD, "main process id is %d", getpid());

	if (s->forklocal) {
		chld_init();

		/* setup signals for children to sync with */
		if (signals_children() < 0) {
			terminate("cant setup child signals");
		}

		/* initialize senders */
		if (chld_fork() < 0) {
			terminate("something went wrong while forking children");
		}

		while (chld_waitsync() > 0) {
			usleep(10000);
		}

		DBG(M_CLD, "children synced");
	}

	if (drone_setup() < 0) {
		terminate("cant setup drones, exiting");
	}

	/* XXX remove this and fix */
	if (s->senders == 0 && GET_SENDDRONE()) {
		/* XXX */
		terminate("no senders for scan, giving up and rudley disconnecting from other drones without warning");
	}

	if (s->listeners == 0 && GET_LISTENDRONE()) {
		/* XXX */
		terminate("no listeners for scan, giving up and rudley disconnecting from other drones without warning");
	}

	if (GET_SENDDRONE() || GET_LISTENDRONE()) {
		run_drone();
	}
	else {

		report_init();
		if (GET_DOCONNECT()) {
			connect_init();
		}

		for (s->cur_iter=1 ; s->cur_iter < (s->scan_iter + 1); s->cur_iter++) {
			VRB(1, "scan iteration %u out of %u", s->cur_iter, s->scan_iter);
			workunit_reset();
			run_scan();
		}

		report_do();
		report_destroy();

		if (GET_DOCONNECT()) {
			connect_destroy();
		}
	}

	terminate_alldrones();

	time(&s->e_time);

	DBG(M_MOD, "main shuting down output modules");

	fini_output_modules();
	fini_report_modules();

	workunit_destroy();

	chld_reapall();

	VRB(2, "main exiting");

	uexit(0);
}
