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

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif

#include <settings.h>

#include <scan_progs/send_packet.h>
#include <scan_progs/recv_packet.h>
#include <scan_progs/options.h>

#include <unilib/output.h>
#include <unilib/terminate.h>
#include <unilib/xmalloc.h>
#include <unilib/xipc.h>
#include <unilib/prng.h>
#include <unilib/intf.h>

#include <parse/parse.h>

#define PROCTYPE_SENDER		1
#define PROCTYPE_LISTENER	2

#if defined(BUILD_IDENT_SEND)
int ident=IDENT_SEND;
const char *ident_name_ptr=IDENT_SEND_NAME;
#elif defined(BUILD_IDENT_RECV)
int ident=IDENT_RECV;
const char *ident_name_ptr=IDENT_RECV_NAME;
#else
# error whoa
#endif
settings_t *s=NULL;
static pid_t ppid=0;

int main(int argc, char **argv) {
	void (*run_mode)(void)=NULL;
	int sret=0, j=0;
	size_t doff=0;
	char cmdline[256];
#ifdef WITH_SELINUX
	security_context_t c_con, p_con;
#endif

	s=(settings_t *)xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));
	s->vi=(interface_info_t **)xmalloc(sizeof(interface_info_t *));
	s->vi[0]=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	memset(s->vi[0], 0, sizeof(interface_info_t));

	ppid=getppid(); /* set this early */

	s->_stdout=stdout;
	s->_stderr=stderr;

#ifdef DEBUG_SUPPORT
	bluescreen_register();
#endif

	prng_init();
	scan_setdefaults();
	s->forked=1;

#if defined(BUILD_IDENT_SEND)
	run_mode=&send_packet;

	if (argc != 7) {
		terminate("arguments are incorrect for this program");
	}

	if (scan_setprofile(argv[1]) < 0) {
		terminate("cant setprofile");
	}
	if (scan_setmoddir(argv[2]) < 0) {
		terminate("cant set module directory");
	}
	if (scan_setverbose(atoi(argv[3])) < 0) {
		terminate("cant set verbose level");
	}
	if (scan_setdebug(argv[4]) < 0) {
		terminate("cant set debug level");
	}
	if (scan_setinterface(argv[5]) < 0) {
		terminate("cant set interface");
	}
	s->ipcuri=xstrdup(argv[6]);

#elif defined(BUILD_IDENT_RECV)
	run_mode=&recv_packet;

	if (argc != 10) {
		terminate("arguments are incorrect for this program");
	}

	if (scan_setprofile(argv[1]) < 0) {
		terminate("cant setprofile");
	}
	if (scan_setmoddir(argv[2]) < 0) {
		terminate("cant set module directory");
	}
	if (scan_setverbose(atoi(argv[3])) < 0) {
		terminate("cant set verbose level");
	}
	if (scan_setdebug(argv[4]) < 0) {
		terminate("cant set debug level");
	}
	if (scan_setinterface(argv[5]) < 0) {
		terminate("cant set interface");
	}

	DBG(M_INT, "got interface `%s' from parent", argv[5]);

	if (get_interface_info(s->interface_str, s->vi[0]) < 0) {
		terminate("cant get interface information");
	}

# warning FIXTHIS IPV4 ONLY
	if (strcmp(argv[6], "0.0.0.0") != 0) {
		struct in_addr ia;
		union {
			struct sockaddr_in *sin;
			struct sockaddr_storage *ss;
		} s_u;

		DBG(M_CLD, "ok so we are spoofing `%s' then", argv[6]);
		snprintf(s->vi[0]->myaddr_s, sizeof(s->vi[0]->myaddr_s) -1, "%s", argv[6]);
		if (inet_aton(s->vi[0]->myaddr_s, &ia) == 0) {
			terminate("invalid ip address");
		}
		s_u.ss=&s->vi[0]->myaddr;
		s_u.sin->sin_addr.s_addr=ia.s_addr;
		s_u.sin->sin_family=AF_INET;

		s_u.ss=&s->vi[0]->mymask;
		s_u.sin->sin_addr.s_addr=0xffffffff;
		s_u.sin->sin_family=AF_INET;

		SET_PROMISC(1);
	}

	if (strcmp(argv[7], "00:00:00:00:00:00") != 0) {
		unsigned int a,b,c,d,e,f;

		DBG(M_CLD, "ok so we are spoofing my mac then `%s'", argv[7]);
		if (sscanf(argv[7], "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) != 6) {
			terminate("invalid mac address");
		}
		if (a > 0xff || b > 0xff || c > 0xff || d > 0xff || e > 0xff || f > 0xff) {
			terminate("mac address out of range");
		}

		snprintf(s->vi[0]->hwaddr_s, sizeof(s->vi[0]->hwaddr_s) -1, "%s", argv[7]);

		s->vi[0]->hwaddr[0]=(uint8_t)a;
		s->vi[0]->hwaddr[1]=(uint8_t)b;
		s->vi[0]->hwaddr[2]=(uint8_t)c;
		s->vi[0]->hwaddr[3]=(uint8_t)d;
		s->vi[0]->hwaddr[4]=(uint8_t)e;
		s->vi[0]->hwaddr[5]=(uint8_t)f;

		SET_PROMISC(1);
	}

	if (strcmp(argv[8], "none") != 0) {
		if (scan_setsavefile(argv[8]) < 0) {
			terminate("can't use file `%s' as savefile", argv[8]);
		}
	}

	s->ipcuri=xstrdup(argv[9]);

#else
 #error BUILD_IDENT_SEND or BUILD_IDENT_RECV must be set
#endif

	for (j=0; j < argc; j++) {
		sret=snprintf(cmdline + doff, sizeof(cmdline) - (doff + 1), "%s ", argv[j]);
		if ((sret < 1) || (doff + 1 >= sizeof(cmdline))) {
			break;
		}
		doff += (size_t) sret;
	}

	DBG(M_CLD, "command line `%s', %s with pid of %d", cmdline, ident == IDENT_RECV ? "listener" : "sender", getpid());

#ifdef WITH_SELINUX
	/*
	 * obviously none of this is required, but if we are in selinux mode, lets just
	 * make sure that we are in a sane selinux env, in case the policy isnt added,
	 * it will make troubleshooting more obvious if we fail with an error regarding
	 * a broken selinux setup.
	 */
	if (getpidcon(getpid(), &c_con) < 0) {
		terminate("getpidcon fails");
	}

	if (getprevcon(&p_con) < 0) {
		terminate("getprevcon fails");
	}

	if (security_check_context(c_con) != 0) {
		terminate("my security context is invalid, exiting");
	}

/*
	if (ident == IDENT_RECV) {
		if (strstr(c_con, LISTENERNAME) != NULL) {
		}
	}
	else {
		if (strstr(c_con, SENDERNAME) != NULL) {
		}
	}
*/

	DBG(M_CLD, "current context `%s' prev context `%s'", c_con, p_con);

	if (!(security_getenforce())) {
		/*
		 * once again this is not something that should ever happen in a sane env, but well just check
		 * anyhow to prevent serious mistakes
		 */
		terminate("this program is not compiled to run without the protection of selinux, enforcing mode must be on, perhaps you should recompile without selinux support if you do not plan to use it");
	}

	if (setreuid(0, 0) == -1) {
		terminate("setreuid fails");
	}
#endif

	if (ipc_init() < 0) {
		terminate("cant initialize IPC, quiting");
	}

	run_mode(); /* shouldnt return */

	PANIC("if you are seeing this, something is really bad");
}

void parent_sync(void) {

	if (ppid == 1) {
		terminate("ack, parent died?");
	}

	if (kill(ppid, UNI_SYNC_SIGNAL) < 0) {
		terminate("can't sync with parent, exiting");
	}
}
