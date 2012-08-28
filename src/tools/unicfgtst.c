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
#include <settings.h>
#include <unilib/xmalloc.h>
#include <unilib/qfifo.h>
#include <parse/parse.h>

int ident;
const char *ident_name_ptr;
static void *kvq=NULL;

settings_t *s=NULL;

int main(int argc, char ** argv) {
	if (argc != 2) {
		printf("Usage: test (conf file)\n");
		exit(1);
	}

	ident=IDENT_ANY;
	ident_name_ptr=IDENT_ANY_NAME;

	s=(settings_t *)xmalloc(sizeof(settings_t));
	memset(s, 0, sizeof(settings_t));
	s->vi=(interface_info_t **)xmalloc(sizeof(interface_info_t *));
	s->vi[0]=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	memset(s->vi[0], 0, sizeof(interface_info_t));
	s->ss=(scan_settings_t *)xmalloc(sizeof(scan_settings_t));
	memset(s->ss, 0, sizeof(scan_settings_t));
	s->verbose=3;
	s->_stdout=stdout;
	s->_stderr=stderr;

	if (readconf(argv[1])) {
		keyval_t *kv=NULL;
		mod_params_t *mp=NULL;

		for (mp=s->mod_params ; mp != NULL ; mp=mp->next) {
			printf("Module `%s'\n", mp->name);
			for (kv=mp->kv ; kv != NULL ; kv=kv->next) {
				printf("\tKey: `%s' Value: `%s'\n", kv->key, kv->value);
			}
		}
	}
	else {
		fprintf(stderr, "Error parsing configuration from `%s'\n", argv[1]);
		exit(1);
	}
	exit(0);
}

int add_payload(uint16_t proto, uint16_t port, int32_t local_port, const uint8_t *payload, uint32_t payload_size, int (*create_payload)(uint8_t **, uint32_t *), uint16_t payload_flags) {
	printf("Added payload for proto %u dport %u sport %d size %u payload group %u\n", proto, port, local_port, payload_size, payload_flags);
	return 1;
}

int add_default_payload(uint16_t proto, int32_t local_port, const uint8_t *payload, uint32_t payload_size, int (*create_payload)(uint8_t **, uint32_t *), uint16_t payload_flags) {
	printf("Added default payload for proto %u sport %d size %u payload group %u\n", proto, local_port, payload_size, payload_flags);
	return 1;
}

void *scan_optmap(const char *key, const char *val) {
	printf("Option `%s'=`%s'\n", key, val);
	return NULL;
}
void *scan_optmapi(const char *key, int val) {
	printf("Option `%s'=%d\n", key, val);
	return NULL;
}

void scan_modaddkeyval(const char *key, const char *value) {
	char str[512];
	if (kvq == NULL) kvq=fifo_init();
	snprintf(str, sizeof(str) -1, "%s=%s", key, value);
	fifo_push(kvq, xstrdup(str));
}

void scan_collectkeyval(const char *modname) {
	union {
		void *ptr;
		char *str;
	} c_u;
	printf("Module: %s\n", modname);

	if (kvq == NULL) {
		fprintf(stderr, "Blank module line?\n");
		exit(1);
	}

	while ((c_u.ptr=fifo_pop(kvq)) != NULL) {
		printf("\t%s\n", c_u.str);
		xfree(c_u.ptr);
	}

	fifo_destroy(kvq);
	kvq=NULL;
}
