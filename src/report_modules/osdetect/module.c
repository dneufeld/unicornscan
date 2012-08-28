/**********************************************************************
 * Copyright (C) 2005-2006 (Jack Louis) <jack@rapturesecurity.org>    *
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
#include <scan_progs/packets.h>
#include <settings.h>
#include <unilib/qfifo.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/modules.h>

#include "module.h"
#include "dodetect.h"

static mod_entry_t *_m=NULL;
const settings_t *s=NULL;
static int _disabled=0;

void osdetect_init(void);
void osdetect_fini(void);
int osdetect_handle_report(const void *);

osd_t osd;

/* i wrote all this the day before the defcon talk, so umm, yah... */

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "OS Detection");
	snprintf(m->name, sizeof(m->name) -1, "osdetect");
	snprintf(m->errstr, sizeof(m->errstr) -1, "No Error");

	m->iver=0x0103; /* 1.0 */
	m->type=MI_TYPE_REPORT;

	m->param_u.report_s.ip_proto=6;
	m->param_u.report_s.sport=-1;
	m->param_u.report_s.sport=-1;
	m->param_u.report_s.immed=1;
	m->param_u.report_s.init_report=&osdetect_init;
	m->param_u.report_s.fini_report=&osdetect_fini;

	_disabled=1;

	_m=m;
	s=_m->s;
	return 1;
}

int delete_module(void) {
	return 1;
}

void osdetect_init(void) {
	keyval_t *kv=NULL;

	_disabled=0;

	if (_m == NULL) {
		ERR("no mod_entry structure, disabling osdetect module");
		_disabled=1;
		return;
	}

	grab_keyvals(_m);

	if (_m->mp == NULL) {
		ERR("no fingerprints possible [no fingerprint data], disabling osdetect module");
		_disabled=1;
		return;
	}

	osd.dump_unknown=0;

	for (kv=_m->mp->kv ; kv != NULL ; kv=kv->next) {
		if (strcmp(kv->key, "DATA") == 0) {
			if (osd_add_fingerprint(kv->value) != 1) {
				ERR("cant add fingerprint %s", kv->value);
			}
		}
		else {
			if (strcmp(kv->key, "dumpunknown") == 0) {
				if (kv->value[0] == '1') {
					osd.dump_unknown=1;
					DBG(M_MOD, "osdetect, dumping unknown fingerprints");
				}
			}
			else {
				ERR("Unknown configuration statement %s=%s",
					kv->key, kv->value
				);
			}
		}
	}

	if (scan_setretlayers(0xff) < 0) {
		ERR("Unable to request packet transfer though IPC, disabling osdetect module");
		_disabled=1;
		return;
	}

	osd.stim_fp=_m->s->ss->fingerprint;
	osd.mtu=_m->s->ss->mtu;

	return;
}

void osdetect_fini(void) {
	return;
}

int create_report(const void *r) {
	union {
		const ip_report_t *ir;
		const arp_report_t *ar;
		const void *ptr;
		const uint8_t *cr;
		const uint32_t *r_magic;
		const uint16_t *len;
		struct myiphdr *i;
	} r_u;
	size_t dlen=0;
	output_data_t *e_out=NULL;
	char *res=NULL;
	struct in_addr ia;

	r_u.ptr=r;

	if (_disabled == 1 || *r_u.r_magic != IP_REPORT_MAGIC) {
		return 1;
	}

	if (r_u.ir->proto != IPPROTO_TCP) {
		return 1;
	}

	if (r_u.ir->doff > 0) {
		dlen=(size_t)r_u.ir->doff;
		r_u.cr += sizeof(ip_report_t);

		if (*r_u.len != dlen) {
			ERR("Mis-Match length of packet data");
			return 1;
		}

		r_u.len++;

		if (dlen < sizeof(struct myiphdr)) {
			return 1;
		}

		ia.s_addr=r_u.i->saddr;

		res=do_osdetect(r_u.cr, dlen);

		if (GET_IMMEDIATE() && res != NULL && strlen(res)) {
			OUT("System at %s matches OS %s", inet_ntoa(ia), res);
		}

		if (res != NULL) {
			e_out=(output_data_t *)xmalloc(sizeof(output_data_t));
			e_out->type=OD_TYPE_OS;
			e_out->t_u.os=(char *)xstrdup(res);
			r_u.ptr=r; /* reset */
			assert(r_u.ir->od_q != NULL);
			fifo_push(r_u.ir->od_q, (void *)e_out);
		}
	}

	return 1;
}
