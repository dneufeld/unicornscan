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
#include <settings.h>

#include <unilib/terminate.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <unilib/qfifo.h>
#include <unilib/prng.h>

const char *ident_name_ptr=NULL;
int ident=0;

settings_t *s=NULL;
void *r_queue=NULL, *p_queue=NULL;
pcap_dumper_t *pdump=NULL;

void startit(void) {
        ident=IDENT_ANY;
        ident_name_ptr=IDENT_ANY_NAME;

	s=xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));
	s->vi=(interface_info_t **)xmalloc(sizeof(interface_info_t *));
	s->vi[0]=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	prng_init();
	memset(s->vi[0], 0, sizeof(interface_info_t));
	s->ss=xmalloc(sizeof(scan_settings_t));
	s->_stdout=stdout;
	s->_stderr=stderr;
	bluescreen_register();

	s->verbose=255;
	s->ss->mode=MODE_TCPSCAN;
	s->ss->header_len=8;

	s->forked=0;

	r_queue=fifo_init();
	p_queue=fifo_init();

}
