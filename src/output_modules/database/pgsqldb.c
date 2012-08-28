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

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <scan_progs/workunits.h>

#include <settings.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/modules.h>
#include <unilib/cidr.h>

#include <libpq-fe.h>

static int pgsql_disable=0;
static unsigned long long int pgscanid=0;

static mod_entry_t *_m=NULL;
static char *pgsql_escstr(const char *);

static PGconn *pgconn=NULL;
static PGresult *pgres=NULL;
static ExecStatusType pgret;
static const settings_t *s=NULL;
static char querybuf[1024 * 8];
static char db_os[4096], db_banner[4096];

void pgsql_database_init(void);
void pgsql_database_fini(void);

static int pgsql_dealwith_sworkunit(uint32_t, const send_workunit_t *);
static int pgsql_dealwith_rworkunit(uint32_t, const recv_workunit_t *);
static int pgsql_dealwith_ipreport(const ip_report_t *);
static int pgsql_dealwith_arpreport(const arp_report_t *);
static int pgsql_dealwith_wkstats(uint32_t /* magic */, const workunit_stats_t *);
static void database_walk_func(void *);

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "Output to PostgreSQL Database");
	snprintf(m->name, sizeof(m->name) -1, "pgsqldb");
	snprintf(m->errstr, sizeof(m->errstr) -1, "No Error");

	m->iver=0x0103; /* 1.0 */
	m->type=MI_TYPE_OUTPUT;

	m->param_u.output_s.init_output=&pgsql_database_init;
	m->param_u.output_s.fini_output=&pgsql_database_fini;

	s=m->s;
	_m=m;
	return 1;
}

int delete_module(void) {

	return 1;
}

void pgsql_database_init(void) {
	keyval_t *kv=NULL;
	char *connstr=NULL, *escres=NULL;
	char profile[200], dronestr[200], modules[200], user[200], pcap_dumpfile[200], pcap_readfile[200];
	long long int est_e_time=0;

	grab_keyvals(_m);

	if (_m == NULL || _m->mp == NULL) {
		return;
	}

	DBG(M_MOD, "PostgreSQL module is enabled");

	for (kv=_m->mp->kv ; kv != NULL ; kv=kv->next) {
		if (strcmp(kv->key, "dbconf") == 0) {
			connstr=kv->value;
		}
		if (strcmp(kv->key, "logpacket") == 0) {
			if (strcmp(kv->value, "true") == 0) {
				if (scan_setretlayers(0xff) < 0) {
					ERR("cant request whole packet transfer, ignoring log packet option");
				}
			}
		}
	}

	if (connstr == NULL) {
		ERR("no configuration for PostGreSQL, need an entry in config for `dbconf' with a valid PostGreSQL connection string");
		pgsql_disable=1;
		return;
	}

	pgconn=PQconnectdb(connstr);
	if (pgconn == NULL || PQstatus(pgconn) != CONNECTION_OK) {
		ERR("PostgreSQL connection fails: %s",
			pgconn == NULL ? "unknown" : PQerrorMessage(pgconn)
		);
		pgsql_disable=1;
		return;
	}

	VRB(0, "PostgreSQL: connected to host %s, database %s, as user %s, with protocol version %d",
		PQhost((const PGconn *)pgconn),
		PQdb((const PGconn *)pgconn),
		PQuser((const PGconn *)pgconn),
		PQprotocolVersion((const PGconn *)pgconn)
	);

	escres=pgsql_escstr(s->profile);
	strncpy(profile, escres, sizeof(profile) -1);

	dronestr[0]='\0';
	if (s->drone_str != NULL) {
		escres=pgsql_escstr(s->drone_str);
		strncpy(dronestr, escres, sizeof(dronestr) -1);
	}

	modules[0]='\0';
	if (s->module_enable != NULL) {
		escres=pgsql_escstr(s->module_enable);
		strncpy(modules, escres, sizeof(modules) -1);
	}

	user[0]='\0';
	if (s->user != NULL) {
		escres=pgsql_escstr(s->user);
		strncpy(user, escres, sizeof(user) -1);
	}

	pcap_dumpfile[0]='\0';
	if (s->pcap_dumpfile != NULL) {
		escres=pgsql_escstr(s->pcap_dumpfile);
		strncpy(pcap_dumpfile, escres, sizeof(pcap_dumpfile) -1);
	}

	pcap_readfile[0]='\0';
	if (s->pcap_readfile != NULL) {
		escres=pgsql_escstr(s->pcap_readfile);
		strncpy(pcap_readfile, escres, sizeof(pcap_readfile) -1);
	}

	est_e_time=(long long int )s->s_time + (long long int )s->ss->recv_timeout + (long long int )s->num_secs;

	snprintf(querybuf, sizeof(querybuf) -1,
	"insert into uni_scans (									"
		"\"s_time\",		\"e_time\",		\"est_e_time\",		\"senders\",	"
		"\"listeners\",		\"scan_iter\",		\"profile\",		\"options\",	"
		"\"payload_group\",	\"dronestr\",		\"covertness\",		\"modules\",	"
		"\"user\",		\"pcap_dumpfile\",	\"pcap_readfile\",	\"tickrate\",	"
		"\"num_hosts\",		\"num_packets\"							"
	") 												"
	"values(											"
		"%lld,			%lld,			%lld,			%d,		"
		"%d,			%d,			'%s',			%hu,		"
		"%hu,			'%s',			%hu,			'%s',		"
		"'%s',			'%s',			'%s',			%hu,		"
		"%f,			%f								"
	");												"
	"select currval('uni_scans_id_seq') as scanid;							",
	(long long int )s->s_time,	(long long int )0,	est_e_time,		s->senders,
	s->listeners,			s->scan_iter,		profile,		s->options,
	s->payload_group,		dronestr,		s->covertness,		modules,
	user,				pcap_dumpfile,		pcap_readfile,		s->master_tickrate,
	s->num_hosts,			s->num_packets
	);

	pgres=PQexec(pgconn, querybuf);
	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_TUPLES_OK) {
		ERR("PostgreSQL scan insert id returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		pgsql_disable=1;
		return;
	}

	if (PQntuples(pgres) != 1) {
		ERR("PostgreSQL returned a row count other than 1, disable");
		pgsql_disable=1;
		return;
	}
	else {
		char *res_ptr=NULL;

		res_ptr=PQgetvalue(pgres, 0, 0);

		if (res_ptr == NULL) {
			ERR("database returned NULL result pointer, disable");
			pgsql_disable=1;
			return;
		}

		if (sscanf(res_ptr, "%llu", &pgscanid) != 1) {
			ERR("malformed pgscanid from database");
			pgsql_disable=1;
			return;
		}
	}
	PQclear(pgres);

	return;
}

int send_output(const void *p) {
	union {
		const uint32_t *magic;
		const void *p;
		const struct wk_s *wrk;
		const ip_report_t *ir;
		const arp_report_t *arrrrr; /* pirate report */
		const struct workunit_stats_t *wks;
	} d_u;

	d_u.p=p;

	if (p == NULL) {
		return -1;
	}

	switch (*d_u.magic) {
		case WK_MAGIC:
			if (d_u.wrk->s != NULL) {
				return pgsql_dealwith_sworkunit(d_u.wrk->wid, d_u.wrk->s);
			}
			else if (d_u.wrk->r != NULL) {
				return pgsql_dealwith_rworkunit(d_u.wrk->wid, d_u.wrk->r);
			}
			else {
				ERR("unknown workunit type");
			}
			break;

		case WKS_SEND_MAGIC:
		case WKS_RECV_MAGIC:
			return pgsql_dealwith_wkstats(*d_u.magic, d_u.wks);
			break;

		case IP_REPORT_MAGIC:
			return pgsql_dealwith_ipreport(d_u.ir);
			break;

		case ARP_REPORT_MAGIC:
			return pgsql_dealwith_arpreport(d_u.arrrrr);
			break;

		default:
			ERR("unknown output magic type %08x", *d_u.magic);
			break;
	}

	return 1;
}

static int pgsql_dealwith_sworkunit(uint32_t wid, const send_workunit_t *w) {
	char myaddr[128], mymask[128], macaddr[64], target[128], targetmask[128], port_str[1024 * 4];
	char *ipopts=NULL, *tcpopts=NULL, *pstr=NULL, *escret=NULL;
	char blank[1];
	size_t ipopts_len=0, tcpopts_len=0;

	blank[0]='\0';

	if (w->tcpoptions_len > 0) {
		tcpopts=PQescapeBytea(w->tcpoptions, w->tcpoptions_len, &tcpopts_len);
	}
	else {
		tcpopts=blank;
	}

	if (w->ipoptions_len > 0) {
		ipopts=PQescapeBytea(w->ipoptions, w->ipoptions_len, &ipopts_len);
	}
	else {
		ipopts=blank;
	}

	escret=pgsql_escstr(cidr_saddrstr((const struct sockaddr *)&w->myaddr));
	strncpy(myaddr, escret, sizeof(myaddr) -1);

	escret=pgsql_escstr(cidr_saddrstr((const struct sockaddr *)&w->mymask));
	strncpy(mymask, escret, sizeof(mymask) -1);

	escret=pgsql_escstr(cidr_saddrstr((const struct sockaddr *)&w->target));
	strncpy(target, escret, sizeof(target) -1);

	escret=pgsql_escstr(cidr_saddrstr((const struct sockaddr *)&w->targetmask));
	strncpy(targetmask, escret, sizeof(targetmask) -1);

	pstr=workunit_pstr_get(w);

	port_str[0]='\0';
	if (pstr != NULL) {
		escret=pgsql_escstr(pstr);
		strncpy(port_str, escret, sizeof(port_str) -1);
	}

	snprintf(macaddr, sizeof(macaddr) -1, "%02x:%02x:%02x:%02x:%02x:%02x",
		w->hwaddr[0], w->hwaddr[1], w->hwaddr[2],
		w->hwaddr[3], w->hwaddr[4], w->hwaddr[5]
	);

	snprintf(querybuf, sizeof(querybuf) -1,
	"insert into uni_sworkunits (									"
		"\"magic\",		\"scans_id\",		\"repeats\",	\"send_opts\",		"
		"\"pps\",		\"delay_type\",		\"myaddr\",	\"mymask\",		"
		"\"macaddr\",		\"mtu\",		\"target\",	\"targetmask\",		"
		"\"tos\",		\"minttl\",		\"maxttl\",	\"fingerprint\",	"
		"\"src_port\",		\"ip_off\",		\"ipoptions\",	\"tcpflags\",		"
		"\"tcpoptions\",	\"window_size\",	\"syn_key\",	\"port_str\",		"
		"\"wid\",		\"status\"							"
	")												"
	"values(											"
		"%u,			%llu,			%hu,		%hu,			"
		"%u,			%hu,			'%s',		'%s',			"
		"'%s',			%hu,			'%s',		'%s',			"
		"%hu,			%hu,			%hu,		%hu,			"
		"%hu,			%u,			'%s',		%u,			"
		"'%s',			%hu,			%u,		'%s',			"
		"%u,			%d								"
	");												",
		w->magic,		pgscanid,		w->repeats,	w->send_opts,
		w->pps,			w->delay_type,		myaddr,		mymask,
		macaddr,		w->mtu,			target,		targetmask,
		w->tos,			w->minttl,		w->maxttl,	w->fingerprint,
		w->src_port,		w->ip_off,		ipopts,		w->tcphdrflgs,
		tcpopts,		w->window_size,		w->syn_key,	port_str,
		wid,			0
	);

	pgres=PQexec(pgconn, querybuf);
	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_COMMAND_OK) {
		ERR("PostgreSQL scan insert id returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		pgsql_disable=1;
		return -1;
	}
	PQclear(pgres);

	if (ipopts != blank) {
		free(ipopts); /* not allocated with xmalloc, so dont use xfree */
	}
	if (tcpopts != blank) {
		free(tcpopts);
	}

	return 1;
}

static int pgsql_dealwith_wkstats(uint32_t magic, const workunit_stats_t *w) {
	char msg[2048], *escret=NULL;

	if (w->msg == NULL) {
		return -1;
	}
	escret=pgsql_escstr(w->msg);
	strncpy(msg, escret, sizeof(msg) -1);

	snprintf(querybuf, sizeof(querybuf) -1,
	"insert into uni_workunitstats (\"wid\", \"scans_id\", \"msg\") "
	" values(%u, %llu, '%s');					"
	"update %s set status=1 where wid=%u and scans_id=%llu;		",
		w->wid,	pgscanid, msg,
		magic == WKS_SEND_MAGIC ? "uni_sworkunits" : "uni_lworkunits",
		w->wid, pgscanid
	);

	pgres=PQexec(pgconn, querybuf);
	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_COMMAND_OK) {
		ERR("PostgreSQL scan insert id returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		pgsql_disable=1;
		return -1;
	}
	PQclear(pgres);

	return 1;
}

static int pgsql_dealwith_rworkunit(uint32_t wid, const recv_workunit_t *w) {
	char pcap_str[1024], *fstr=NULL, *escret=NULL;

	pcap_str[0]='\0';

	fstr=workunit_fstr_get(w);
	if (fstr != NULL) {
		escret=pgsql_escstr(fstr);
		strncpy(pcap_str, escret, sizeof(pcap_str) -1);
	}

	snprintf(querybuf, sizeof(querybuf) -1,
	"insert into uni_lworkunits (									"
	"	\"magic\",	\"scans_id\",		\"recv_timeout\",	\"ret_layers\",		"
	"	\"recv_opts\",	\"window_size\",	\"syn_key\",		\"pcap_str\",		"
	"	\"wid\",	\"status\"								"
	")												"
	"values(											"
	"	%u,		%llu,			%hu,			%hu,			"
	"	%hu,		%u,			%u,			'%s',			"
	"	%u,		%d									"
	");												",
		w->magic,	pgscanid,		w->recv_timeout,	w->ret_layers,
		w->recv_opts,	w->window_size,		w->syn_key,		pcap_str,
		wid,		0
	);

	pgres=PQexec(pgconn, querybuf);
	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_COMMAND_OK) {
		ERR("PostgreSQL scan insert id returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		pgsql_disable=1;
		return -1;
	}
	PQclear(pgres);

	return 1;
}

/*
 * XXX we have to trust other code to not lie about the length here
 */
static int pgsql_dealwith_ipreport(const ip_report_t *i) {
	uint32_t tv_sec=0, tv_usec=0;
	char send_addr[128], host_addr[128], trace_addr[128];
	unsigned long long int ipreportid=0;
	struct in_addr ia;

	ia.s_addr=i->send_addr;
	snprintf(send_addr, sizeof(send_addr) -1, "%s", inet_ntoa(ia));
	ia.s_addr=i->host_addr;
	snprintf(host_addr, sizeof(host_addr) -1, "%s", inet_ntoa(ia));
	ia.s_addr=i->trace_addr;
	snprintf(trace_addr, sizeof(trace_addr) -1, "%s", inet_ntoa(ia));

	tv_sec=(uint32_t )i->recv_time.tv_sec;
	tv_usec=(uint32_t )i->recv_time.tv_usec;

	snprintf(querybuf, sizeof(querybuf) -1,
	"insert into uni_ipreport (							\n"
	"	\"scans_id\",		\"magic\",	\"sport\",	\"dport\",	\n"
	"	\"proto\",		\"type\",	\"subtype\",	\"send_addr\",	\n"
	"	\"host_addr\",		\"trace_addr\",	\"ttl\",	\"tstamp\",	\n"
	"	\"utstamp\",		\"flags\",	\"mseq\",	\"tseq\",	\n"
	"	\"window_size\",	\"t_tstamp\",	\"m_tstamp\"			\n"
	")										\n"
	"values(									\n"
	"	%llu,			%u,		%hu,		%hu,		\n"
	"	%hu,			%hu,		%hu,		'%s',		\n"
	"	'%s',			'%s',		%hu,		%u,		\n"
	"	%u,			%hu,		%u,		%u,		\n"
	"	%hu,			%u,		%u				\n"
	");										\n"
	"select currval('uni_ipreport_id_seq') as ipreportid;				\n",
		pgscanid,		i->magic,	i->sport,	i->dport,
		i->proto,		i->type,	i->subtype,	send_addr,
		host_addr,		trace_addr,	i->ttl,		tv_sec,
		tv_usec,		i->flags,	i->mseq,	i->tseq,
		i->window_size,		i->t_tstamp,	i->m_tstamp
	);

	pgres=PQexec(pgconn, querybuf);
	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_TUPLES_OK) {
		ERR("PostgreSQL scan insert id returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		pgsql_disable=1;
		return -1;
	}

	if (PQntuples(pgres) != 1) {
		ERR("PostgreSQL returned a row count other than 1, disable");
		pgsql_disable=1;
		return -1;
	}
	else {
		char *res_ptr=NULL;

		res_ptr=PQgetvalue(pgres, 0, 0);

		if (res_ptr == NULL) {
			ERR("database returned NULL result pointer, disable");
			pgsql_disable=1;
			return -1;
		}

		if (sscanf(res_ptr, "%llu", &ipreportid) != 1) {
			ERR("malformed pgscanid from database");
			pgsql_disable=1;
			return -1;
		}
	}
	PQclear(pgres);

	/*
	 * trust problem
	 */
	if (i->doff > 0) {
		const void *packet=NULL;
		size_t packet_len=i->doff, packet_strlen=0;
		union {
			const void *p;
			const ip_report_t *i;
		} d_u;
		char *packet_str=NULL;

		d_u.i=i;

		d_u.i++;
		packet=d_u.p;

		packet_str=PQescapeBytea(packet, packet_len, &packet_strlen);

		snprintf(querybuf, sizeof(querybuf) -1,
			"insert into uni_ippackets (\"ipreport_id\", \"packet\") values(%llu, '%s');",
			ipreportid, packet_str
		);

		pgres=PQexec(pgconn, querybuf);

		pgret=PQresultStatus(pgres);
		if (pgret != PGRES_COMMAND_OK) {
			ERR("PostgreSQL insert returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
			pgsql_disable=1;
			return -1;
		}
		PQclear(pgres);

		free(packet_str); /* not from xfree */
	}

	CLEAR(db_banner);
	CLEAR(db_os);

	fifo_walk(i->od_q, database_walk_func);

	if (strlen(db_banner)) {
		snprintf(querybuf, sizeof(querybuf) -1,
			"insert into uni_ipreportdata (ipreport_id, type, data) values(%llu, 1, '%s');", ipreportid, pgsql_escstr(db_banner));
                pgres=PQexec(pgconn, querybuf);
                pgret=PQresultStatus(pgres);
                if (pgret != PGRES_COMMAND_OK) {
                        ERR("PostgreSQL banner insert returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
                        pgsql_disable=1;
                        return -1;
                }
                PQclear(pgres);
        }

        if (strlen(db_os)) {
                CLEAR(querybuf);
                snprintf(querybuf, sizeof(querybuf) -1, "insert into uni_ipreportdata (ipreport_id, type, data) values(%llu, 2, '%s');", ipreportid, pgsql_escstr(db_os));
                pgres=PQexec(pgconn, querybuf);
                pgret=PQresultStatus(pgres);
                if (pgret != PGRES_COMMAND_OK) {
                        ERR("PostgreSQL banner insert returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
                        pgsql_disable=1;
                        return -1;
                }
                PQclear(pgres);
        }

	return 1;
}

/*
 * XXX we have to trust other code to not lie about the length here
 */
static int pgsql_dealwith_arpreport(const arp_report_t *a) {
	uint32_t tv_sec=0, tv_usec=0;
	char host_addr[128], hwaddr[32], *str=NULL;
	struct in_addr ia;
	long long unsigned int arpreportid=0;

	ia.s_addr=a->ipaddr;

	str=inet_ntoa(ia);
	assert(str != NULL);

	memset(host_addr, 0, sizeof(host_addr));
	memcpy(host_addr, str, MIN(sizeof(host_addr) -1, strlen(str)));

	snprintf(hwaddr, sizeof(hwaddr) -1, "%02x:%02x:%02x:%02x:%02x:%02x",
		a->hwaddr[0], a->hwaddr[1], a->hwaddr[2],
		a->hwaddr[3], a->hwaddr[4], a->hwaddr[5]
	);

	tv_sec=(uint32_t )a->recv_time.tv_sec;
	tv_usec=(uint32_t )a->recv_time.tv_usec;

	snprintf(querybuf, sizeof(querybuf) -1,
	"insert into uni_arpreport (							\n"
	"	\"scans_id\",		\"magic\",	\"host_addr\",	\"hwaddr\",	\n"
	"	\"tstamp\",		\"utstamp\"					\n"
	")										\n"
	"values(									\n"
	"	%llu,			%u,		'%s',		'%s',		\n"
	"	%u,			%u						\n"
	");										\n"
	"select currval('uni_arpreport_id_seq') as arpreportid;				\n",
		pgscanid,		a->magic,	host_addr,	hwaddr,
		tv_sec,			tv_usec
	);

	pgres=PQexec(pgconn, querybuf);
	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_TUPLES_OK) {
		ERR("PostgreSQL scan insert id returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		pgsql_disable=1;
		return -1;
	}

	if (PQntuples(pgres) != 1) {
		ERR("PostgreSQL returned a row count other than 1, disable");
		pgsql_disable=1;
		return -1;
	}
	else {
		char *res_ptr=NULL;

		res_ptr=PQgetvalue(pgres, 0, 0);

		if (res_ptr == NULL) {
			ERR("database returned NULL result pointer, disable");
			pgsql_disable=1;
			return -1;
		}

		if (sscanf(res_ptr, "%llu", &arpreportid) != 1) {
			ERR("malformed pgscanid from database");
			pgsql_disable=1;
			return -1;
		}
	}
	PQclear(pgres);

	/*
	 * trust problem
	 */
	if (a->doff > 0) {
		const void *packet=NULL;
		size_t packet_len=a->doff, packet_strlen=0;
		union {
			const void *p;
			const arp_report_t *a;
		} d_u;
		char *packet_str=NULL;

		d_u.a=a;

		d_u.a++;
		packet=d_u.p;

		packet_str=PQescapeBytea(packet, packet_len, &packet_strlen);

		snprintf(querybuf, sizeof(querybuf) -1,
			"insert into uni_arppackets (\"arpreport_id\", \"packet\") values(%llu, '%s');",
			arpreportid, packet_str
		);

		pgres=PQexec(pgconn, querybuf);

		pgret=PQresultStatus(pgres);
		if (pgret != PGRES_COMMAND_OK) {
			ERR("PostgreSQL insert returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
			pgsql_disable=1;
			return -1;
		}
		PQclear(pgres);

		free(packet_str); /* not from xfree */
	}

	return 1;
}

void pgsql_database_fini(void) {

	if (pgsql_disable) {
		return;
	}

	snprintf(querybuf, sizeof(querybuf) -1, "update uni_scans set e_time=%lld where scans_id=%llu;",
		(long long int )s->e_time,
		pgscanid
	);

	pgres=PQexec(pgconn, querybuf);

	pgret=PQresultStatus(pgres);
	if (pgret != PGRES_COMMAND_OK) {
		ERR("PostgreSQL finalize scan returned a strange return code %s: %s", PQresStatus(pgret), PQresultErrorMessage(pgres));
		pgsql_disable=1;
		return;
	}
	PQclear(pgres);

	PQfinish(pgconn);

	return;
}

static void database_walk_func(void *data) {
	union { 
		void *p;
		output_data_t *o;
	} d_u;

	d_u.p=data;

	switch (d_u.o->type) {

		case OD_TYPE_BANNER:
			CLEAR(db_banner);
			snprintf(db_banner, sizeof(db_banner) -1, "%s", pgsql_escstr(d_u.o->t_u.banner));
			break;

		case OD_TYPE_OS:
			CLEAR(db_os);
			snprintf(db_os, sizeof(db_os) -1, "%s", pgsql_escstr(d_u.o->t_u.os));
			break;

		default:
			ERR("unknown output format type %d in database push", d_u.o->type);
			break;
	}

        return;
}

static char *pgsql_escstr(const char *in) {
	static char *outstr=NULL;
	static size_t outstr_len=0;
	size_t inlen=0;

	if (in == NULL) {
		return NULL;
	}

	inlen=strlen(in) + 1;

	assert(inlen < 0xffff);

	if (outstr == NULL) {
		outstr_len=inlen * 2;
		outstr=xmalloc(outstr_len);
	}
	else if ((inlen * 2) > outstr_len) {

		outstr_len=inlen * 2;

		outstr=xrealloc(outstr, outstr_len);
	}

	memset(outstr, 0, outstr_len);

	PQescapeString(outstr, in, inlen - 1);

	return outstr;
}
