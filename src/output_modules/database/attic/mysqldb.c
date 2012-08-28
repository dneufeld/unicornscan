#include <config.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/modules.h>

#include "template.h"
#include "default_dbinfo.h"

#include <mysql/mysql.h>

void mysql_database_init(void);
void mysql_database_fini(void);
static char *mysql_escstr(const char *);

static MYSQL *myconn=NULL;
static MYSQL_RES *myres=NULL;

static uint64_t scanid;
static int db_disable=0;
static void database_walk_func(const void *);
static mod_entry_t *_m=NULL;
static char db_banner[256], db_os[256];
static const settings_t *s=NULL;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "Output to MySQL Database");
	snprintf(m->name, sizeof(m->name) -1, "mysqldb");
	snprintf(m->errstr, sizeof(m->errstr) -1, "No Error");

	m->iver=0x0102; /* 1.0 */
	m->type=MI_TYPE_OUTPUT;

	m->param_u.output_s.init_output=&mysql_database_init;
	m->param_u.output_s.fini_output=&mysql_database_fini;

	s=m->s;
	_m=m;
	return 1;
}

void mysql_database_fini(void) {
	char query[512];

	if (db_disable) return;

	CLEAR(query); snprintf(query, sizeof(query) -1, mysql_scanfini, (long long int)s->e_time, scanid);
	if (mysql_query(myconn, query) == 0) {
		if (myres) mysql_free_result(myres);
		myres=mysql_store_result(myconn);
		if (myres == NULL) {
			MSG(M_ERR, "Store Result `%s' errors with `%s'", query, mysql_error(myconn));
			db_disable=1;
			return;
		}
	}
	else {
		MSG(M_WARN, "Query `%s' errors with `%s'", query, mysql_error(myconn));
		db_disable=1;
		return;
	}

	return;
}

int delete_module(void) {
	if (db_disable) return 1;

	if (myres) mysql_free_result(myres);
	mysql_close(myconn);

	db_disable=1;
	return 1;
}

void mysql_database_init(void) {
	int results=0;
	char query[2048], ptstr[256], pcstr[256];
	char *hostname=NULL, *dbname=NULL, *username=NULL, *password=NULL;
	unsigned int port=3306;
	keyval_t *kv=NULL;
	seo_t scanopts;

	grab_keyvals(_m);

	if (_m == NULL || _m->mp == NULL) return;

	if (myconn != NULL) {
		if (myres) mysql_free_result(myres); myres=NULL;
		mysql_close(myconn); myconn=NULL;
		return;
	}

	for (kv=_m->mp->kv ; kv != NULL ; kv=kv->next) {
		if (strcmp(kv->key, "hostname") == 0) {
			hostname=kv->value;
		}
		else if (strcmp(kv->key, "port") == 0) {
			port=(unsigned int)atoi(kv->value);
		}
		else if (strcmp(kv->key, "username") == 0) {
			username=kv->value;
		}
		else if (strcmp(kv->key, "password") == 0) {
			password=kv->value;
		}
		else if (strcmp(kv->key, "dbname") == 0) {
			dbname=kv->value;
		}
	}

	if (dbname == NULL) {
		dbname=xstrdup(DBNAME);
	}

	if (_m->s->verbose > 1) MSG(M_DBG1, "MySQL Database module is enabled");

	myconn=mysql_init(NULL);
	if (myconn == NULL) {
		MSG(M_ERR, "Cant initialize a mysql structure, disabling");
		db_disable=1;
		return;
	}

	if (mysql_real_connect(myconn, hostname, username, password, dbname, (hostname != NULL ? port : 0), NULL, 0) == NULL) {
		MSG(M_WARN, "MySQL real connect fails: %s", mysql_error(myconn));
		db_disable=1;
		return;
	}
	if (myconn == NULL) {
		MSG(M_ERR, "sldfkskfsdkfsdf: %s", mysql_error(myconn));
		exit(32);
	}

	if (_m->s->verbose) {
		MSG(M_INFO, "database: Connected to host %s:%u, database %s, as user %s, with protocol version %u", hostname, port, dbname, username, mysql_get_proto_info(myconn));
	}

	if (get_scanopts(&scanopts) < 0) {
		MSG(M_ERR, "Serious problems getting scan options for insertion into database");
		db_disable=1;
		return;
	}

	snprintf(ptstr, sizeof(ptstr) -1, "%s", mysql_escstr(s->port_str));
	snprintf(pcstr, sizeof(pcstr) -1, "%s", mysql_escstr((const char *)(s->extra_pcapfilter != NULL ? s->extra_pcapfilter : "None")));

	CLEAR(query);
	snprintf(query, sizeof(query) -1, mysql_scaninfo,
	(long long int)s->s_time, (long long int)0, (uint64_t )ntohl(s->vi[0]->myaddr.sin_addr.s_addr), ptstr,
	(uint64_t )s->_low_ip, (uint64_t )s->_high_ip, scanopts.mode, s->pps, s->payload_group,
	pcstr, (s->drone_str != NULL ? mysql_escstr(s->drone_str) : "None"), scanopts.fingerprint, scanopts.tos,
	scanopts.ttl, scanopts.ip_off, scanopts.tcphdrflgs, scanopts.src_port, s->repeats,
	s->send_opts, s->recv_opts, s->options);

	if (mysql_query(myconn, query) == 0) {
		if (myres) mysql_free_result(myres); /* shouldnt be needed */
		myres=mysql_store_result(myconn);
		if (myres == NULL) {
			MSG(M_ERR, "Store Result `%s' errors with `%s'", query, mysql_error(myconn));
			db_disable=1;
			return;
		}
	}
	else {
		MSG(M_WARN, "Query `%s' errors with `%s'", query, mysql_error(myconn));
		db_disable=1;
		return;
	}

	sprintf(query, "select last_insert_id()");
	if (mysql_query(myconn, query) == 0) {
		if (myres) mysql_free_result(myres);
		myres=mysql_store_result(myconn);
		if (myres == NULL) {
			MSG(M_ERR, "Store Result `%s' errors with `%s'", query, mysql_error(myconn));
			db_disable=1;
			return;
		}
	}
	else {
		MSG(M_WARN, "Query `%s' errors with `%s'", query, mysql_error(myconn));
		db_disable=1;
		return;
	}

	results=mysql_num_rows(myres);
	if (results == 1) {
		MYSQL_ROW myrow;

		mysql_data_seek(myres, 0);
		myrow=mysql_fetch_row(myres);
		if (myrow == NULL) {
			MSG(M_ERR, "Cant fetch row: %s", mysql_error(myconn));
			db_disable=1;
			return;
		}

		if (myrow[0] == NULL) { 
			MSG(M_ERR, "mysql returned a null result");
			db_disable=1;
			return;
		}

		if (sscanf(myrow[0], "%llu", &scanid) != 1) {
			MSG(M_ERR, "Malformed scanid from database");
			db_disable=1;
			return;
		}
	}
	else {
		MSG(M_ERR, "mysql returned no scanid, disable mysql");
		db_disable=1;
		return;
	}

	return;
}

int send_output(const void *r) {
	union {
		const ip_report_t *ir;
		const arp_report_t *ar;
		const void *ptr;
		const uint16_t *r_magic;
	} r_u;
	char query[2048];
	uint64_t sb_id=0;

	if (db_disable) return 0;

	CLEAR(db_banner); CLEAR(db_os);
	CLEAR(query);

	r_u.ptr=r;

	if (*r_u.r_magic != IP_REPORT_MAGIC) {
		return 0;
	}

	fifo_walk(r_u.ir->od_q, &database_walk_func);

	snprintf(query, sizeof(query) -1, mysql_scandata,
	scanid, r_u.ir->proto, r_u.ir->type, r_u.ir->subtype, r_u.ir->dport, r_u.ir->sport, r_u.ir->ttl,
	htonl(r_u.ir->host_addr), htonl(r_u.ir->trace_addr), (long long unsigned int )r_u.ir->recv_time.tv_sec,
	(long long unsigned int)r_u.ir->recv_time.tv_usec);

	if (mysql_query(myconn, query) == 0) {
		if (myres) mysql_free_result(myres);
		myres=mysql_store_result(myconn);
		if (myres == NULL) {
			MSG(M_ERR, "Store Result `%s' errors with `%s'", query, mysql_error(myconn));
			db_disable=1;
			return -1;
		}
	}
	else {
		MSG(M_WARN, "Query `%s' errors with `%s'", query, mysql_error(myconn));
		db_disable=1;
		return -1;
	}

	if (strlen(db_banner) == 0 || strlen(db_os) == 0) {
		return 1;
	}

	sprintf(query, "select last_insert_id()");
	if (mysql_query(myconn, query) == 0) {
		if (myres) mysql_free_result(myres);
		myres=mysql_store_result(myconn);
		if (myres == NULL) {
			MSG(M_ERR, "Store Result `%s' errors with `%s'", query, mysql_error(myconn));
			db_disable=1;
			return -1;
		}
	}
	else {
		MSG(M_WARN, "Query `%s' errors with `%s'", query, mysql_error(myconn));
		db_disable=1;
		return -1;
	}

	if (mysql_num_rows(myres) == 1) {
		MYSQL_ROW myrow;

		mysql_data_seek(myres, 0);
		myrow=mysql_fetch_row(myres);

		if (myrow[0] == NULL) {
			MSG(M_ERR, "mysql returned a NULL col");
			db_disable=1;
			return -1;
		}

		if (sscanf(myrow[0], "%llu", &sb_id) != 1) {
			MSG(M_ERR, "Malformed scan bucket id from database");
			db_disable=1;
			return -1;
		}
	}

	if (strlen(db_banner)) {
		snprintf(query, sizeof(query) -1, mysql_scandata_b, sb_id, mysql_escstr(db_banner));
		if (mysql_query(myconn, query) == 0) {
			if (myres) mysql_free_result(myres);
			myres=mysql_store_result(myconn);
			if (myres == NULL) {
				MSG(M_ERR, "Store Result `%s' errors with `%s'", query, mysql_error(myconn));
				db_disable=1;
				return -1;
			}
		}
		else {
			MSG(M_WARN, "Query `%s' errors with `%s'", query, mysql_error(myconn));
			db_disable=1;
			return -1;
		}
	}

	if (strlen(db_os)) {
		snprintf(query, sizeof(query), mysql_scandata_o, sb_id, mysql_escstr(db_os));
		if (mysql_query(myconn, query) == 0) {
			if (myres) mysql_free_result(myres);
			myres=mysql_store_result(myconn);
			if (myres == NULL) {
				MSG(M_ERR, "Store Result `%s' errors with `%s'", query, mysql_error(myconn));
				db_disable=1;
				return -1;
			}
		}
		else {
			MSG(M_WARN, "Query `%s' errors with `%s'", query, mysql_error(myconn));
			db_disable=1;
			return -1;
		}
	}

	return 1;
}

static void database_walk_func(const void *item) {
	union {
		const void *ptr;
		const output_data_t *d;
	} d_u;

	d_u.ptr=item;
	switch (d_u.d->type) {
		case OD_TYPE_BANNER:
			CLEAR(db_banner); /* XXX */
			snprintf(db_banner, sizeof(db_banner) -1, "%s", mysql_escstr(d_u.d->t_u.banner));
			break;
		case OD_TYPE_OS:
			CLEAR(db_os);
			snprintf(db_os, sizeof(db_os) -1, "%s", mysql_escstr(d_u.d->t_u.os));
			break;
		default:
			MSG(M_ERR, "Unknown output format type %d in database push", d_u.d->type);
			break;
	}

	return;
}

char *mysql_escstr(const char *from) {
	static char buf[256], buf2[127];

	CLEAR(buf2); CLEAR(buf);
	snprintf(buf2, sizeof(buf2) -1, "%s", from);

	/* this function doesnt stop on \0, it would seem */
	/* The string pointed to by from must be length bytes long. (p 3) */
	(void) mysql_real_escape_string(myconn, buf, (const char *)buf2, (unsigned long) strlen(buf2));

	return buf;
}
