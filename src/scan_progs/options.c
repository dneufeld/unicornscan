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
#include <ctype.h>

#include <settings.h>

#include <unilib/xdelay.h>
#include <unilib/cidr.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/arch.h>
#include <unilib/xdelay.h>

#include <scan_progs/scan_export.h>
#include <scan_progs/options.h>

static keyval_t *kv_list=NULL;

int scan_setdefaults(void) {
	s->repeats=1;
	s->forklocal=FORK_LOCAL_LISTENER|FORK_LOCAL_SENDER;

	s->pps=250;

	s->master_tickrate=250;

	s->gport_str=xstrdup("q");

	s->tcpquickports=xstrdup("22");
	s->udpquickports=xstrdup("53");

	s->payload_group=1;

	/* translate syn+ack to open, rst+ack to closed, etc */
	SET_DOTRANS(1);

	/* the default is to have the ports shuffled */
	SET_SHUFFLE(1);

	/* the default is to have a default payload 16 A's or whatever */
	SET_DEFAULT(1);

	SET_WATCHERRORS(0);
	SET_PROCERRORS(0);
	SET_IGNORESEQ(0);
	SET_IGNORERSEQ(0);

	if (scan_setdebug("none") < 0) {
		ERR("cant set debug mask");
	}

	scan_setprivdefaults();

	s->conn_delay=4000;

	s->ip_report_fmt=xstrdup("%-8r\t%16P[%5p]\t\tFrom %h %T ttl %t");
	s->ip_imreport_fmt=xstrdup("%-8r %h:%p %T ttl %t");
	s->arp_report_fmt=xstrdup("%M (%o) is %h");
	s->arp_imreport_fmt=xstrdup("%h at %M");
	s->openstr=xstrdup("open");
	s->closedstr=xstrdup("closed");

	return 1;
}

int scan_settcpquick(const char *ports) {

	if (ports == NULL || strlen(ports) < 1) {
		return -1;
	}

	if (s->tcpquickports != NULL) {
		xfree(s->tcpquickports);
	}

	s->tcpquickports=xstrdup(ports);
	return 1;
}

int scan_setudpquick(const char *ports) {

	if (ports == NULL || strlen(ports) < 1) {
		return -1;
	}

	if (s->udpquickports != NULL) {
		xfree(s->udpquickports);
	}

	s->udpquickports=xstrdup(ports);

	return 1;
}

int scan_setopenclosed(const char *openstr, const char *closedstr) {
	if (openstr == NULL || closedstr == NULL || MIN(strlen(openstr), strlen(closedstr)) < 1) {
		return -1;
	}

	if (s->openstr != NULL) {
		xfree(s->openstr);
	}
	if (s->closedstr != NULL) {
		xfree(s->closedstr);
	}

	s->openstr=xstrdup(openstr);
	s->closedstr=xstrdup(closedstr);

	return 1;
}

int scan_setformat(const char *fmt) {
	size_t flen=0;

	if (fmt == NULL || strlen(fmt) < 1) {
		return -1;
	}

	flen=strlen(fmt);

	if      (flen > 3 && strncmp(fmt, "ip:"   , 3) == 0) {
		if (s->ip_report_fmt != NULL) {
			xfree(s->ip_report_fmt);
		}
		s->ip_report_fmt=xstrdup(fmt + 3);
	}
	else if (flen > 5 && strncmp(fmt, "imip:" , 5) == 0) {
		if (s->ip_imreport_fmt != NULL) {
			xfree(s->ip_imreport_fmt);
		}
		s->ip_imreport_fmt=xstrdup(fmt + 5);
	}
	else if (flen > 4 && strncmp(fmt, "arp:"  , 4) == 0) {
		if (s->arp_report_fmt != NULL) {
			xfree(s->arp_report_fmt);
		}
		s->arp_report_fmt=xstrdup(fmt + 4);
	}
	else if (flen > 6 && strncmp(fmt, "imarp:", 6) == 0) {
		if (s->arp_imreport_fmt != NULL) {
			xfree(s->arp_imreport_fmt);
		}
		s->arp_imreport_fmt=xstrdup(fmt + 6);
	}
	else {
		ERR("unknown format specification type, ip:,imip:,arp:,imarp: are known");
		return -1;
	}

	return 1;
}

int scan_setdronestring(const char *type) {

	if (type == NULL || strlen(type) < 1) {
		return -1;
	}

	if (type[0] == 'L' || type[0] == 'l') {
		if (type[1] != '\0') {
			s->listen_addr=xstrdup(&type[1]);
		}
		else {
			s->listen_addr=xstrdup(DEF_LISTEN_ADDR);
		}
		SET_LISTENDRONE(1);
		s->forklocal=FORK_LOCAL_LISTENER;

		return 1;
	}
	else if (type[0] == 'S' || type[0] == 's') {
		if (type[1] != '\0') {
			s->listen_addr=xstrdup(&type[1]);
		}
		else {
			s->listen_addr=xstrdup(DEF_LISTEN_ADDR);
		}
		SET_SENDDRONE(1);
		s->forklocal=FORK_LOCAL_SENDER;

		return 1;
	}
	else {
		s->drone_str=xstrdup(type);
		s->forklocal=0;
	}

	return 1;
}

int scan_setenablemodule(const char *modules) {

	if (modules == NULL || strlen(modules) < 1) {
		return -1;
	}

	if (s->module_enable != NULL) {
		xfree(s->module_enable);
	}

	s->module_enable=xstrdup(modules);

	return 1;
}

int scan_setgports(const char *ports) {

	if (ports == NULL || strlen(ports) < 1) {
		return -1;
	}

	if (s->gport_str != NULL) {
		xfree(s->gport_str);
	}

	s->gport_str=xstrdup(ports);

	return 1;
}

int scan_setidlehosts(const char *ihosts) {

	if (ihosts == NULL || strlen(ihosts) < 1) {
		return -1;
	}

	if (s->idle_hosts != NULL) {
		xfree(s->idle_hosts);
	}

	s->idle_hosts=xstrdup(ihosts);

	return 1;
}

int scan_setignoreseq(const char *type) {

	if (type == NULL || strlen(type) < 1) {
		return -1;
	}

	if (type[0] == 'A' || type[0] == 'a') {
		SET_IGNORESEQ(1);
	}
	else if (type[0] == 'R' || type[0] == 'r') {
		SET_IGNORERSEQ(1);
	}
	else if (type[0] == 'N' || type[0] == 'n') {
		SET_IGNORESEQ(0);
		SET_IGNORERSEQ(0);
		return 1;
	}
	else {
		ERR("unknown sequence ignorace type %c", type[0]);
		return -1;
	}

	return 1;
}

int scan_setinterface(const char *intf) {

	if (intf == NULL || strlen(intf) < 1) {
		return -1;
	}

	if (s->interface_str != NULL) {
		xfree(s->interface_str);
	}

	s->interface_str=xstrdup(intf);

	return 1;
}

int scan_setmoddir(const char *dir) {

	if (dir == NULL || strlen(dir) < 1) {
		return -1;
	}

	if (access(dir, R_OK|X_OK) < 0) {
		ERR("cant read module directory `%s': %s", dir, strerror(errno));
		return -1;
	}

	if (s->mod_dir != NULL) {
		xfree(s->mod_dir);
	}

	s->mod_dir=xstrdup(dir);

	return 1;
}

int scan_setpcapfilter(const char *filter) {

	if (filter == NULL || strlen(filter) < 1) {
		return -1;
	}

	if (s->extra_pcapfilter != NULL) {
		xfree(s->extra_pcapfilter);
	}
	s->extra_pcapfilter=xstrdup(filter);

	return 1;
}

int scan_setpps(const char *ppsstr) {
	int pps=0;

	if (ppsstr == NULL || strlen(ppsstr) < 1) {
		return -1;
	}

	if (sscanf(ppsstr, "%d", &pps) != 1) {
		ERR("bad pps format");
		return -1;
	}

	if (pps < 0) {
		ERR("negative pps not handled, nor is carpet made of palmtree shoes, but thats not important right now, whats important is that you use this option correctly.");
		return -1;
	}

	s->pps=pps;

	return 1;
}

int scan_setprofile(const char *profname) {

	if (profname == NULL || strlen(profname) < 1) {
		return -1;
	}

	if (s->profile != NULL) {
		xfree(s->profile);
	}

	s->profile=xstrdup(profname);
	return 1;
}

int scan_setreadfile(const char *file) {

	if (file == NULL || strlen(file) < 1) {
		return -1;
	}

	if (access(file, R_OK) < 0) {
		ERR("file `%s' cant be read: %s", file, strerror(errno));
		return -1;
	} 

	if (s->pcap_readfile != NULL) {
		xfree(s->pcap_readfile);
	}

	s->pcap_readfile=xstrdup(file);

	return 1;
}

int scan_setsavefile(const char *sfile) {
	char newfname[PATH_MAX], *opos=NULL;
	const char *cptr=NULL;
	size_t olen=0;
	time_t curtime;
	int sret=0, tfd=0;

	if (sfile == NULL || strlen(sfile) < 1) {
		return -1;
	}

	memset(newfname, 0, sizeof(newfname));

	for (cptr=sfile, opos=newfname; *cptr != '\0'; cptr++) {
		switch (*cptr) {
			case '%':
				if (*(cptr + 1) == '\0') {
					*(opos++)='%'; olen++;
					break;
				}
				cptr++;
				switch (*cptr) {
					case 'd':
						if ((olen + 11) >= sizeof(newfname)) {
							ERR("source filename too long");
							return -1;
						}
						time(&curtime);
						sret=snprintf(opos, (sizeof(newfname) - olen - 1), "%d", (int)curtime);
						olen += sret; opos += sret;
						break;

					case '%': /* this turns into a % then */
						*(opos++)='%'; olen++;
						break;

					default:
						ERR("unknown escape char `%c' in filename", *cptr);
						return -1;
				}
				break;

			default:
				if ((olen + 1) >= sizeof(newfname)) {
					ERR("source filename too long");
					return -1;
				}
				*(opos++)=*cptr; olen++;
				break;
		}
	}

	if (s->pcap_dumpfile != NULL) {
		xfree(s->pcap_dumpfile);
	}

	tfd=open(newfname, O_CREAT|O_WRONLY|O_EXCL, S_IRUSR|S_IWUSR);
	if (tfd < 0) {
		ERR("cant open file `%s': %s", newfname, strerror(errno));
		return -1;
	}

	unlink(newfname);

	s->pcap_dumpfile=xstrdup(newfname);

	return 1;
}

/* bool */

int scan_setcovertness(int level) {

	if (level < 0 || level > 0xff) {
		ERR("covertness value `%d' of of range", level);
		return -1;
	}

	s->covertness=(uint8_t)level;
	return 1;
}

int scan_setdefpayload(int def) {

	if (def) {
		SET_DEFAULT(1);
	}
	else {
		SET_DEFAULT(0);
	}

	return 1;
}

/* XXX */
int scan_setdelaytype(int type) {

	if (type > 0xff || type < 0) {
		ERR("delay type out of range");
		return -1;
	}

	s->delay_type_exp=(uint8_t)type;
	return 1;
}

int scan_setdodns(int dns) {

	if (dns) {
		SET_DODNS(1);
	}
	else {
		SET_DODNS(0);
	}

	return 1;
}

int scan_setidlescan(int idle) {

	if (idle) {
		ERR("not implemented");
		return -1;
	}
	else {
		//SET_IDLESCAN(0);
	}

	return 1;
}

int scan_setignroot(int root) {

	if (root) {
		SET_IGNROOT(1);
	}
	else {
		SET_IGNROOT(0);
	}

	return 1;
}

int scan_setimmediate(int imm) {

	if (imm) {
		SET_IMMEDIATE(1);
	}
	else {
		SET_IMMEDIATE(0);
	}

	return 1;
}

int scan_setlistendrone(int listd) {

	if (listd) {
		if (GET_SENDDRONE()) {
			ERR("send and listen drones are mutually exclusive");
			return -1;
		}
		SET_LISTENDRONE(1);
		s->forklocal=FORK_LOCAL_LISTENER;
	}
	else {
		SET_LISTENDRONE(0);
	}

	return 1;
}

int scan_setpayload_grp(int plg) {
	if (plg < 0 || plg > 0xffff) {
		ERR("payload group out of range");
		return -1;
	}
	s->payload_group=(uint16_t)plg;

	return 1;
}

int scan_setppsi(int value) {

	if (value < 1) {
		ERR("negative pps not handled currently, and if it was, you must ask yourself why!");
		return -1;
	}

	s->pps=value;

	return 1;
}

int scan_setprocdups(int proc) {
	if (proc) {
		SET_PROCDUPS(1);
	}
	else {
		SET_PROCDUPS(0);
	}

	return 1;
}

int scan_setprocerrors(int proc) {
	if (proc) {
		SET_PROCERRORS(1);
		SET_WATCHERRORS(1);
	}
	else {
		SET_PROCERRORS(0);
		SET_WATCHERRORS(0);
	}

	return 1;
}

int scan_setrepeats(int repeats) {

	if (repeats < 1) {
		ERR("scan repeats is less than one");
		return -1;
	}

	s->repeats=(uint32_t)repeats;

	return 1;
}

int scan_setreportquiet(int quiet) {

	SET_REPORTQUIET(quiet);

	return 1;
}

int scan_setsenddrone(int sendd) {

	if (sendd) {
		if (GET_LISTENDRONE()) {
			ERR("send and listen drones are mutually exclusive");
			return -1;
		}
		SET_SENDDRONE(1);
		s->forklocal=FORK_LOCAL_SENDER;
	}
	else {
		SET_SENDDRONE(0);
	}

	return 1;
}

int scan_setshuffle(int shuffle) {

	if (shuffle) {
		SET_SHUFFLE(1);
	}
	else {
		SET_SHUFFLE(0);
	}

	return 1;
}

int scan_setsniff(int sniff) {

	if (sniff) {
		SET_SNIFF(1);
	}
	else {
		SET_SNIFF(0);
	}

	return 1;
}

int scan_settrans(int trans) {

	if (trans) {
		SET_DOTRANS(1);
	}
	else {
		SET_DOTRANS(0);
	}

	return 1;
}

int scan_settryfrags(int frag) {

	if (frag) {
		ERR("frag scanning is not implemented in this release");
		return -1;
	}

	return 1;
}

int scan_setverbose(int verbl) {

	if (verbl < 0) {
		s->verbose=0;
		return 1;
	}

	if (verbl > 0xff) {
		s->verbose=255;
		return 1;
	}

	s->verbose=(uint8_t)verbl;

	return 1;
}

int scan_setdebug(const char *maskstr) {
	char *sdup=NULL, *tok=NULL, *rent=NULL;

	sdup=xstrdup(maskstr);

	s->debugmask=0;

	for (tok=strtok_r(sdup, ",", &rent); tok != NULL; tok=strtok_r(NULL, ",", &rent)) {
		if (strcasecmp(tok, "all") == 0) {
			s->debugmask=M_ALL;
			break;
		}
		else if (strcasecmp(tok, "none") == 0) {
			s->debugmask=0;
		}
		else if (strcasecmp(tok, M_WRKSTR) == 0) {
			s->debugmask |= M_WRK;
		}
		else if (strcasecmp(tok, M_RTESTR) == 0) {
			s->debugmask |= M_RTE;
		}
		else if (strcasecmp(tok, M_DRNSTR) == 0) {
			s->debugmask |= M_DRN;
		}
		else if (strcasecmp(tok, M_MODSTR) == 0) {
			s->debugmask |= M_MOD;
		}
		else if (strcasecmp(tok, M_SCKSTR) == 0) {
			s->debugmask |= M_SCK;
		}
		else if (strcasecmp(tok, M_DNSSTR) == 0) {
			s->debugmask |= M_DNS;
		}
		else if (strcasecmp(tok, M_IPCSTR) == 0) {
			s->debugmask |= M_IPC;
		}
		else if (strcasecmp(tok, M_PIOSTR) == 0) {
			s->debugmask |= M_PIO;
		}
		else if (strcasecmp(tok, M_SNDSTR) == 0) {
			s->debugmask |= M_SND;
		}
		else if (strcasecmp(tok, M_CONSTR) == 0) {
			s->debugmask |= M_CON;
		}
		else if (strcasecmp(tok, M_CLDSTR) == 0) {
			s->debugmask |= M_CLD;
		}
		else if (strcasecmp(tok, M_PRTSTR) == 0) {
			s->debugmask |= M_PRT;
		}
		else if (strcasecmp(tok, M_MSTSTR) == 0) {
			s->debugmask |= M_MST;
		}
		else if (strcasecmp(tok, M_RPTSTR) == 0) {
			s->debugmask |= M_RPT;
		}
		else if (strcasecmp(tok, M_PKTSTR) == 0) {
			s->debugmask |= M_PKT;
		}
		else if (strcasecmp(tok, M_CNFSTR) == 0) {
			s->debugmask |= M_CNF;
		}
		else if (strcasecmp(tok, M_PYLSTR) == 0) {
			s->debugmask |= M_PYL;
		}
		else if (strcasecmp(tok, M_INTSTR) == 0) {
			s->debugmask |= M_INT;
		}
		else {
			ERR("unknown debug facility `%s'", tok);
		}
	}

	if (s->debugmaskstr != NULL) {
		xfree(s->debugmaskstr);
	}

	s->debugmaskstr=xstrdup(maskstr);
	xfree(sdup);

	return 1;
}

int scan_setverboseinc(void) { /* kludge for getconfig.c */

	if (s->verbose > 0xfe) {
		ERR("stop that, stop saying that.");
		return -1;
	}

	++s->verbose;

	return 1;
}

char *scan_getgports(void) {
	return s->gport_str;
}

char *scan_optmap(const char *key, const char *value) {
	static char ebuf[64];
	char lkey[32], lval[32];
	int j=0, eflg=0;

	CLEAR(ebuf); CLEAR(lkey); CLEAR(lval);

	for (j=0; (size_t)j < MIN(strlen(key), sizeof(lkey) - 1); j++) {
		lkey[j]=tolower(key[j]);
	}

	for (j=0; (size_t)j < MIN(strlen(value), sizeof(lval) - 1); j++) {
		lval[j]=tolower(value[j]);
	}

	snprintf(ebuf, sizeof(ebuf) -1, "unknown error for `%s'=`%s'", key, value);

	if (strcmp(lkey, "delaytype") == 0) {
		int dt=0;

		if ((dt=delay_gettype(lval)) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "unknown delay type `%s'", lval); eflg=1;
		}
		if (scan_setdelaytype(dt) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "cant set delay type `%s'", lval); eflg=1;
		}
	}
	else if (strcmp(lkey, "ipttl") == 0) {
		if (scan_setttl(lval) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "cant set ttl value `%s'", lval); eflg=1;
		}
	}
	else if (strcmp(lkey, "brokencrc") == 0) {
		if (strstr(lval, "transport") != NULL && strstr(lval, "network") != NULL) {
			if (scan_setbroken("TN") < 0) {
				snprintf(ebuf, sizeof(ebuf) -1, "cant set broken transport crcs"); eflg=1;
			}
		}
		else if (strstr(lval, "network") != NULL) {
			if (scan_setbroken("N") < 0) {
				snprintf(ebuf, sizeof(ebuf) -1, "cant set broken network crcs"); eflg=1;
			}
		}
		else if (strstr(lval, "transport") != NULL) {
			if (scan_setbroken("T") < 0) {
				snprintf(ebuf, sizeof(ebuf) -1, "cant set broken transport/network crcs"); eflg=1;
			}
		}
		else {
			snprintf(ebuf, sizeof(ebuf) -1, "unknown value `%s' for brokencrc (network and transport are valid)", lval); eflg=1;
		}
	}
	else if (strcmp(lkey, "debug") == 0) {
		if (scan_setdebug(lval) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "cant set debug"); eflg=1;
		}
	}
	else if (strcmp(lkey, "format") == 0) {
		if (scan_setformat(value) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "cant set format"); eflg=1;
		}
	}
	else if (strcmp(lkey, "readfile") == 0) {
		if (scan_setreadfile(value) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "unable to set readfile `%s'", value); eflg=1;
		}
	}
	else if (strcmp(lkey, "ignoreseq") == 0) {
		if (scan_setignoreseq(lval) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "bad sequence ignorance option `%s'", value); eflg=1;
		}
	}
	else if (strcmp(lkey, "scanmode") == 0) {
		DBG(M_CNF, "scanmode is currently ignored when inside the configuration file");
	}
	else if (strcmp(lkey, "tcpquickports") == 0) {
		if (scan_settcpquick(value) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "cant set tcp quick ports"); eflg=1;
		}
	}
	else if (strcmp(lkey, "udpquickports") == 0) {
		if (scan_setudpquick(value) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "cant set udp quick ports"); eflg=1;
		}
	}
	else if (strcmp(lkey, "tcpflags") == 0) {
		int tcphdrflgs=0;

		tcphdrflgs=decode_tcpflags(value);
		if (tcphdrflgs < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "unable to decode tcp header flags `%s'", value); eflg=1;
		}
		if (scan_settcpflags(tcphdrflgs) < 0) {
			snprintf(ebuf, sizeof(ebuf) -1, "unable to set tcp header flags `%s'", value); eflg=1;
		}
	}
	else {
		snprintf(ebuf, sizeof(ebuf) -1, "unknown option `%s'", lkey); eflg=1;
	}

	if (eflg) return ebuf;
	return NULL;
}

char *scan_optmapi(const char *key, int value) {
	static char ebuf[64];
	char lkey[32];
	int j=0;

	CLEAR(ebuf); CLEAR(lkey);

	for (j=0; (size_t)j < MIN(strlen(key), sizeof(lkey) - 1); j++) {
		lkey[j]=tolower(key[j]);
	}

	if (strcmp(lkey, "pps") == 0) {
		if (scan_setppsi(value)) return NULL;
	}
	else if (strcmp(lkey, "procerrors") == 0) {
		if (scan_setprocerrors(value)) return NULL;
	}
	else if (strcmp(lkey, "immediate") == 0 || strcmp(lkey, "robert") == 0) {
		if (scan_setimmediate(value)) return NULL;
	}
	else if (strcmp(lkey, "defpayload") == 0 || strcmp(lkey, "defaultpayload") == 0) {
		if (scan_setdefpayload(value)) return NULL;
	}
	else if (strcmp(lkey, "ignoreroot") == 0) {
		if (scan_setignroot(value)) return NULL;
	}
	else if (strcmp(lkey, "dodns") == 0) {
		if (scan_setdodns(value)) return NULL;
	}
	else if (strcmp(lkey, "repeats") == 0) {
		if (scan_setrepeats(value)) return NULL;
	}
	else if (strcmp(lkey, "sourceport") == 0) {
		if (scan_setsrcp(value)) return NULL;
	}
	else if (strcmp(lkey, "iptos") == 0) {
		if (scan_settos(value)) return NULL;
	}
	else if (strcmp(lkey, "payload_group") == 0) {
		if (scan_setpayload_grp(value)) return NULL;
	}
	else if (strcmp(lkey, "fingerprint") == 0) {
		if (scan_setfingerprint(value)) return NULL;
	}
	else if (strcmp(lkey, "quiet") == 0) {
		if (scan_setreportquiet(value)) return NULL;
	}
	else if (strcmp(lkey, "verbose") == 0) {
		if (scan_setverbose(value)) return NULL;
	}
	else {
		snprintf(ebuf, sizeof(ebuf) -1, "bad parameter `%s' or value %d", lkey, value);
	}

	return ebuf;
}

void scan_modaddkeyval(const char *key, const char *value) {
	keyval_t *nkv=NULL;

	nkv=(keyval_t *)xmalloc(sizeof(keyval_t));
	nkv->key=xstrdup(key);
	nkv->value=xstrdup(value);
	nkv->next=NULL;

	if (kv_list != NULL) {
		keyval_t *walk=NULL, *sdsdf=NULL;

		for (walk=kv_list; walk != NULL; walk=walk->next) {
			sdsdf=walk;
		}

		sdsdf->next=nkv;
	}
	else {
		kv_list=nkv;
	}

	return;
}

void scan_collectkeyval(const char *modname) {
	mod_params_t *mp=NULL;

	mp=(mod_params_t *)xmalloc(sizeof(mod_params_t));
	mp->next=NULL;
	mp->name=xstrdup(modname);
	assert(kv_list != NULL);
	mp->kv=kv_list;
	kv_list=NULL;

	if (s->mod_params == NULL) {
		s->mod_params=mp;
	}
	else {
		mod_params_t *walk=NULL, *dfgdfg=NULL;

		for (walk=s->mod_params; walk != NULL; walk=walk->next) {
			dfgdfg=walk;
		}
		dfgdfg->next=mp;
	}

	return;
}
