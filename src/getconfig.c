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
#include <netdb.h>

#include <pcap.h>

#include <scan_progs/scan_export.h>
#include <scan_progs/options.h>
#include <scan_progs/workunits.h>
#include <settings.h>
#include <packageinfo.h>
#include <getconfig.h>
#include <parse/parse.h>

#include <unilib/drone.h>
#include <unilib/xmalloc.h>
#include <unilib/terminate.h>
#include <unilib/arch.h>
#include <unilib/cidr.h>
#include <unilib/output.h>
#include <unilib/xdelay.h>
#include <unilib/arch.h>
#include <unilib/qfifo.h>

#ifdef WITH_LONGOPTS
#include <getopt.h>
#endif


#include <compile.h>

/*
 * inputs: NONE
 * outputs: NONE
 * terminates the program with an error code with a description of the arguments
 * the program accepts, currently only used inside getconfig.c
 */
static void usage(void) _NORETURN_;

/*
 */
static void display_version(void) _NORETURN_;

/* XXX
 * this needs to be recoded
 */
void getconfig_profile(const char *progname) {
	const char *profname=NULL;

	if (progname == NULL) {
		PANIC("argv[0] is NULL?");
	}

	profname=strrchr(progname, '/');
	if (profname != NULL) {
		progname=profname + 1;
	}

	if ((profname=strrchr(progname, '.')) != NULL) {
		profname++;
		if (*profname != '\0') {
			s->profile=xstrdup(profname);
		}
		else {
			s->profile=xstrdup(DEF_PROFILE);
		}
	}
	else {
		s->profile=xstrdup(DEF_PROFILE);
	}

	return;
}

int getconfig_argv(int argc, char ** argv) {
	int ch=0;
	char conffile[512];

#define OPTS	\
		"b:" "B:" "c" "d:" "D" "e:" "E" "F" "G:" "h" "H" "i:" "I" "j:" "l:" "L:" "m:" "M:" "o:" "p:" "P:" "q:" "Q" \
		"r:" "R:" "s:" "S" "t:" "T:" "u:" "U" "w:" "W:" "v" "V" "z" "Z:"

#ifdef WITH_LONGOPTS
	const struct option long_opts[]={
		{"broken-crc",		1, NULL, 'b'},
		{"source-port",		1, NULL, 'B'},
		{"proc-duplicates",	0, NULL, 'c'},
		{"delay-type",		1, NULL, 'd'},
		{"no-defpayload",	0, NULL, 'D'},
		{"enable-modules",	1, NULL, 'e'},
		{"show-errors",		0, NULL, 'E'},
		{"try-frags",		0, NULL, 'F'},
		{"payload-group",	1, NULL, 'G'},
		{"help",		0, NULL, 'h'},
		{"do-dns",		0, NULL, 'H'},
		{"interface",		1, NULL, 'i'},
		{"immediate",		0, NULL, 'I'},
		{"ignore-seq",		1, NULL, 'j'},
		{"logfile",		1, NULL, 'l'},
		{"packet-timeout",	1, NULL, 'L'},
		{"mode",		1, NULL, 'm'},
		{"module-dir",		1, NULL, 'M'},
		{"format",		1, NULL, 'o'},
		{"ports",		1, NULL, 'p'},
		{"pcap-filter",		1, NULL, 'P'},
		{"covertness",		1, NULL, 'q'},
		{"quiet",		0, NULL, 'Q'},
		{"pps",			1, NULL, 'r'},
		{"repeats",		1, NULL, 'R'},
		{"source-addr",		1, NULL, 's'},
		{"no-shuffle",		0, NULL, 'S'},
		{"ip-ttl",		1, NULL, 't'},
		{"ip-tos",		1, NULL, 'T'},
		{"debug",		1, NULL, 'u'},
		{"no-openclosed",	0, NULL, 'U'},
		{"savefile",		1, NULL, 'w'},
		{"fingerprint",		1, NULL, 'W'},
		{"verbose",		1, NULL, 'v'}, /* this is different in the long / short opts */
		{"version",		0, NULL, 'V'},
		{"sniff",		0, NULL, 'z'},
		{"drone-str",		1, NULL, 'Z'},
		{NULL,			0, NULL,  0 }
	};
#endif /* LONG OPTION SUPPORT */

	scan_setdefaults();

	snprintf(conffile, sizeof(conffile) -1, CONF_FILE, s->profile);
	if (readconf(conffile) < 0) {
		return -1;
	}

#ifdef WITH_LONGOPTS
	while ((ch=getopt_long(argc, argv, OPTS, long_opts, NULL)) != -1) {
#else
	while ((ch=getopt(argc, argv, OPTS)) != -1) {
#endif
		switch (ch) {
			case 'b':
				if (scan_setbroken(optarg) < 0) {
					usage();
				}
				break;

			case 'B':
				if (scan_setsrcp(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 'c':
				if (scan_setprocdups(1) < 0) {
					usage();
				}
				break;

			case 'D': /* set no default payload */
				if (scan_setdefpayload(0) < 0) {
					usage();
				}
				break;

			case 'd':
				if (scan_setdelaytype(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 'e': /* enable modules */
				if (scan_setenablemodule(optarg) < 0) {
					usage();
				}
				break;

			case 'E': /* report and listen for non open/closed responses */
				if (scan_setprocerrors(1) < 0) {
					usage();
				}
				break;

			case 'F': /* fragment packets if possible */
				if (scan_settryfrags(1) < 0) {
					usage();
				}
				break;

			case 'G':
				if (scan_setpayload_grp(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 'h': /* help */
				usage();
				break;

			case 'H': /* resolve ip addresses into names during reporting phase */
				if (scan_setdodns(1) < 0) {
					usage();
				}
				break;

			case 'i': /* interface name */
				if (scan_setinterface(optarg) < 0) {
					usage();
				}
				break;

			case 'I':
				if (scan_setimmediate(1) < 0) {
					usage();
				}
				break;

			case 'j': /* ignore sequence numbers during tcp scanning */
				if (scan_setignoreseq(optarg) < 0) {
					usage();
				}
				break;

			case 'L': /* how long to wait for replies after done sending */
				if (scan_setrecvtimeout(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 'l': /* log to file, not tty */
				if ((s->_stdout=fopen(optarg, "a+")) == NULL) {
					terminate("logfile `%s' cant be opened", optarg);
				}
				s->_stderr=s->_stdout;
				break;

			case 'm': /* scan mode, tcp udp, etc */
				if (scan_setoptmode(optarg) < 0) {
					usage();
				}
				break;

			case 'M': /* module directory base */
				if (scan_setmoddir(optarg) < 0) {
					usage();
				}
				break;

			case 'o': /* report format string */
				if (scan_setformat(optarg) < 0) {
					usage();
				}
				break;
			

			case 'p': /* Global ports to scan */
				if (scan_setgports(optarg) < 0) {
					usage();
				}
				break;

			case 'P': /* pcap filter to use, like "! port 162" */
				if (scan_setpcapfilter(optarg) < 0) {
					usage();
				}
				break;

			case 'q': /* covertness */
				if (scan_setcovertness(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 'Q':
				if (scan_setreportquiet(1) < 0) {
					usage();
				}
				break;

			case 'r': /* rate of scan */
				if (scan_setpps(optarg) < 0) {
					usage();
				}
				break;

			case 'R': /* repeat scan n times */
				if (scan_setrepeats(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 's': /* set source ip address to optarg */
				if (scan_setsrcaddr(optarg) < 0) {
					usage();
				}
				break;

			case 'S': /* do not shuffle ports */
				if (scan_setshuffle(1) < 0) {
					usage();
				}
				break;

			case 't': /* ttl on outgoing IP datagrams */
				if (scan_setttl(optarg) < 0) {
					usage();
				}
				break;

			case 'T': /* TOS on outgoing IP datagram */
				if (scan_settos(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 'u': /* debug mask */
				if (scan_setdebug(optarg) < 0) {
					usage();
				}
				break;

			case 'U': /* do NOT translate Open/Closed in output, display as is */
				if (scan_settrans(0) < 0) {
					usage();
				}
				break;

			case 'v': /* verbose */
				if (optarg != NULL) {
					if (scan_setverbose(atoi(optarg)) < 0) usage();
				}
				else if (scan_setverboseinc() < 0) {
					usage();
				}
				break;

			case 'V':
				display_version();
				break;

			case 'w': /* write to pcap logfile optarg */
				if (scan_setsavefile(optarg) < 0) {
					usage();
				}
				break;

			case 'W': /* what stack to pretend to have */
				if (scan_setfingerprint(atoi(optarg)) < 0) {
					usage();
				}
				break;

			case 'z': /* im too lazy to run tcpdump mode */
				if (scan_setsniff(1) < 0) {
					usage();
				}
				break;

			case 'Z': /* used for cluster scanning */
				if (scan_setdronestring(optarg) < 0) {
					usage();
				}
				break;

			default:
				usage();
				break;
		} /* switch option */
	} /* getopt loop */

	/* its not set if its null, so set it, otherwise it is */
	if (s->mod_dir == NULL) {
		scan_setmoddir(MODULE_DIR);
	}

	s->argv_ext=fifo_init();

	for (; optind < argc; optind++) {
		fifo_push(s->argv_ext, xstrdup(argv[optind]));
	}

	return 1;
}


void do_targets(void) {
	union {
		void *ptr;
		char *str;
	} s_u;
	char *estr=NULL;

	for (s_u.ptr=fifo_pop(s->argv_ext); s_u.ptr != NULL; s_u.ptr=fifo_pop(s->argv_ext)) {
		if (workunit_add(s_u.str, &estr) < 0) {
			if (access(s_u.str, R_OK) == 0) {
				FILE *rfile=NULL;
				char lbuf[2048];
				char *tok=NULL, *rent=NULL;

				CLEAR(lbuf);

				rfile=fopen(s_u.str, "r");
				if (rfile == NULL) {
					continue;
				}

				while (fgets(lbuf, sizeof(lbuf) -1, rfile) != NULL) {
					for (tok=strtok_r(lbuf, "\t\r\n\v\f ", &rent); tok != NULL; tok=strtok_r(NULL, "\t\r\n\v\f ", &rent)) {
						if (workunit_add(tok, &estr) < 0) {
							ERR("cant add workunit `%s' from file `%s': %s", tok, s_u.str, estr);
						}
					}
				}

				fclose(rfile);
			}
			else {
				ERR("cant add workunit for argument `%s': %s", s_u.str, estr != NULL ? estr : ""); /* bad hostname? */
			}
		}
	}

	/* if we are not a drone */
	if (!(GET_LISTENDRONE() || GET_SENDDRONE())) {
		if (s->num_hosts < 1) {
			INF("what host(s) should i scan?, ive got nothing to do");
			uexit(0);
		}
	}

	return;
}

static void usage(void) {

	INF("%s (version %s)\n"
	"usage: %s [options `%s' ] X.X.X.X/YY:S-E\n"
	"\t-b, --broken-crc     *set broken crc sums on [T]ransport layer, [N]etwork layer, or both[TN]\n"
	"\t-B, --source-port    *set source port? or whatever the scan module expects as a number\n"
	"\t-c, --proc-duplicates process duplicate replies\n"
	"\t-d, --delay-type     *set delay type (numeric value, valid options are `%s')\n"
	"\t-D, --no-defpayload   no default Payload, only probe known protocols\n"
	"\t-e, --enable-module  *enable modules listed as arguments (output and report currently)\n"
	"\t-E, --proc-errors     for processing `non-open' responses (icmp errors, tcp rsts...)\n"
	"\t-F, --try-frags       \n"
	"\t-G, --payload-group	*payload group (numeric) for tcp/udp type payload selection (default all)\n"
	"\t-h, --help            help\n"
	"\t-H, --do-dns          resolve hostnames during the reporting phase\n"
	"\t-i, --interface      *interface name, like eth0 or fxp1, not normally required\n"
	"\t-I, --immediate       immediate mode, display things as we find them\n"
	"\t-j, --ignore-seq     *ignore `A'll, 'R'eset sequence numbers for tcp header validation\n"
	"\t-l, --logfile        *write to this file not my terminal\n"
	"\t-L, --packet-timeout *wait this long for packets to come back (default %d secs)\n"
	"\t-m, --mode           *scan mode, tcp (syn) scan is default, U for udp T for tcp `sf' for tcp connect scan and A for arp\n"
	"\t                       for -mT you can also specify tcp flags following the T like -mTsFpU for example\n"
	"\t                       that would send tcp syn packets with (NO Syn|FIN|NO Push|URG)\n"
	"\t-M, --module-dir     *directory modules are found at (defaults to %s)\n"
	"\t-o, --format         *format of what to display for replies, see man page for format specification\n"
	"\t-p, --ports           global ports to scan, if not specified in target options\n"
	"\t-P, --pcap-filter    *extra pcap filter string for reciever\n"
	"\t-q, --covertness     *covertness value from 0 to 255\n"
	"\t-Q, --quiet           dont use output to screen, its going somewhere else (a database say...)\n"
	"\t-r, --pps            *packets per second (total, not per host, and as you go higher it gets less accurate)\n"
	"\t-R, --repeats        *repeat packet scan N times\n"
	"\t-s, --source-addr    *source address for packets `r' for random\n"
	"\t-S, --no-shuffle      do not shuffle ports\n"
	"\t-t, --ip-ttl         *set TTL on sent packets as in 62 or 6-16 or r64-128\n"
	"\t-T, --ip-tos         *set TOS on sent packets\n"
	"\t-u, --debug		*debug mask\n"
	"\t-U, --no-openclosed	 dont say open or closed\n"
	"\t-w, --safefile       *write pcap file of recieved packets\n"
	"\t-W, --fingerprint    *OS fingerprint 0=cisco(def) 1=openbsd 2=WindowsXP 3=p0fsendsyn 4=FreeBSD 5=nmap\n"
	"\t                      6=linux 7:strangetcp\n"
	"\t-v, --verbose         verbose (each time more verbose so -vvvvv is really verbose)\n"
	"\t-V, --version         display version\n"
	"\t-z, --sniff           sniff alike\n"
	"\t-Z, --drone-str      *drone String\n"
	"*:\toptions with `*' require an argument following them\n\n"
	"  address ranges are cidr like 1.2.3.4/8 for all of 1.?.?.?\n"
	"  if you omit the cidr mask then /32 is implied\n"
	"  port ranges are like 1-4096 with 53 only scanning one port, a for all 65k and p for 1-1024\n"
	"example: %s -i eth1 -Ir 160 -E 192.168.1.0/24:1-4000 gateway:a",
	PROGNAME, VERSION, PROGNAME, OPTS, delay_getopts(), DEF_SCANTIMEOUT, MODULE_DIR, PROGNAME);

	uexit(0);
}

static void display_version(void) {
	uint8_t min, maj;

	MOD_VERSION(MODULE_IVER, maj, min);

	INF("%s version `%s' using module version %d.%02d build options [%s ]", TARGETNAME, VERSION, maj, min, BUILDOPTS);
#ifdef HAVE_PCAP_LIB_VERSION
	INF("pcap version %s", pcap_lib_version());
#endif
	INF("%s", COMPILE_STR);
	INF("report bugs to %s", BUGURL);

	uexit(0);
}
