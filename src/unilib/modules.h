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
#ifndef _MODULES_H
# define _MODULES_H

#define MI_TYPE_PAYLOAD		1
#define MI_TYPE_REPORT		2
#define MI_TYPE_OUTPUT		3
#define MI_TYPE_PREFILTER	4
#define MI_TYPE_FILTER		5

#define MI_STATE_INITED	1
#define MI_STATE_HOOKED	2
#define MI_STATE_DISABL	3

#include <ltdl.h>

typedef struct mod_entry_t {
	/* */
	char license[64];
	/* name, (company) (<email>) */
	char author[64];
	/* this is a brief description of what it does */
	char desc[64];
	/* the full path to the file */
	char fname[2048];
	/* the module can write errors to here */
	char errstr[256];
	char name[32]; /* mostly for report and output modules that are default to disabled currently */

	/* interface version */
	uint16_t iver; /* 0x01 0x00 = 1.0 */
	/* state as in init_module has been run, or its hooked into the correct place already */
	uint8_t state;
	/* dlopen handle return */
	lt_dlhandle handle;

	int (*dl_init_module)(struct mod_entry_t *);
	void (*dl_delete_module)(void);

	const settings_t *s;

	/* what type of module is this? a payload generator? an output module? */
	uint8_t type;

	mod_params_t *mp;

	union {
		struct payload_mod {
			int16_t proto;
			int32_t sport;
			uint16_t dport;
			uint16_t payload_group;
		} payload_s;
		struct report_mod {
			int32_t	ip_proto; /* -1 for all */
			int32_t sport; /* -1 for all */
			int32_t dport; /* -1 for all */
			int32_t immed;
			/* XXX need a better way to do this */
			void (*init_report)(void);
			void (*fini_report)(void);
		} report_s;
		struct output_mod {
			void (*init_output)(void);
			void (*fini_output)(void);
		} output_s;
	} param_u;
	union {
		int (*dl_create_payload)(uint8_t **, uint32_t *, void * /* report */);
		int (*dl_create_report)(const void * /* report */);
		int (*dl_send_output)(const void * /* report */);
	} func_u;
	struct mod_entry_t *next;
} mod_entry_t;

int init_modules(void);

/* a module calls this function to get its params */
void grab_keyvals(mod_entry_t *);

/* these guys currently act a bit different than the rest */
int init_payload_modules(int (*)(uint16_t, uint16_t, int32_t, const uint8_t *, uint32_t, int (*)(uint8_t **, uint32_t *, void *), uint16_t ));
void close_payload_modules(void);

int init_output_modules(void);
int init_report_modules(void);

void push_output_modules(const void * /* report */);
void push_report_modules(const void * /* report */);
void push_jit_report_modules(const void * /* report */);

int fini_output_modules(void);
int fini_report_modules(void);

void close_output_modules(void);
void close_report_modules(void);

#endif
