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

#include <dirent.h>
#include <errno.h>

#include <scan_progs/scan_export.h>
#include <packageinfo.h>
#include <settings.h>
#include <unilib/modules.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/qfifo.h>

/*
 * XXX this module interface was kinda ltdl'ized but it needs quite a bit of work
 */

static mod_entry_t *mod_list_head=NULL;
static const void *_r=NULL;

int init_modules(void) {
	DIR *moddir=NULL;
	struct dirent *de=NULL;
	mod_entry_t *mnew=NULL, *last=NULL;
	const char *dl_estr=NULL;

	if (lt_dlinit() != 0) {
		dl_estr=lt_dlerror();
		ERR("lt_dlinit fails: %s", (dl_estr == NULL ? "unknown reason" : dl_estr));
		return -1;
	}

	DBG(M_MOD, "opening module directory `%s'", s->mod_dir);

	if (s->mod_dir == NULL || strlen(s->mod_dir) < 1) {
		ERR("module directory is not set");
		return -1;
	}

	moddir=opendir(s->mod_dir);
	if (moddir == NULL) {
		ERR("opendir `%s' fails: %s", s->mod_dir, strerror(errno));
		return -1;
	}

	while ((de=readdir(moddir)) != NULL) {
		struct stat sb;
		int ret=0;
		char type[32];
		int maj=0, min=0, bad=0;

		/* ignore . dirs and files and non .so files */
		if (de->d_name[0] == '.' || strstr(de->d_name, SHLIB_EXT) == NULL) {
			continue;
		}

		mnew=(mod_entry_t *)xmalloc(sizeof(mod_entry_t));
		memset(mnew, 0, sizeof(mod_entry_t));

		mnew->s=(const settings_t *)s;

		snprintf(mnew->fname, sizeof(mnew->fname) -1, "%s/%s", s->mod_dir, de->d_name);

		if (stat(mnew->fname, &sb) < 0) {
			ERR("stat `%s' fails: %s", mnew->fname, strerror(errno));
			xfree(mnew);
			continue;
		}

		/* XXX check parent directories too */
		if (S_ISREG(sb.st_mode) && 
		((S_IWGRP|S_IWOTH) & sb.st_mode) == 0) {
			DBG(M_MOD, "loading module `%s'", mnew->fname);
		}
		else {
			ERR("ignoring module `%s', check file type and permissions (no group write or other write permissions allowed)", mnew->fname);
			xfree(mnew);
			continue;
		}

		mnew->handle=lt_dlopen(mnew->fname);
		if (mnew->handle == NULL) {
			ERR("cant load shared object `%s': %s", mnew->fname, lt_dlerror());
			xfree(mnew);
			continue;
		}

		mnew->dl_init_module=(int (*)(mod_entry_t * ))lt_dlsym(mnew->handle, "init_module");
		dl_estr=lt_dlerror();
		if (dl_estr != NULL) {
			ERR("cant find initialization hook for module `%s': %s", mnew->fname, dl_estr);
			lt_dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		mnew->dl_delete_module=(void (*)(void ))lt_dlsym(mnew->handle, "delete_module");
		dl_estr=lt_dlerror();
		if (dl_estr != NULL) {
			ERR("cant find shutdown hook for module `%s': %s", mnew->fname, dl_estr);
			lt_dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		DBG(M_MOD, "module `%s' init_module: %p delete_module: %p, calling init hook",
			mnew->fname,
			mnew->dl_init_module,
			mnew->dl_delete_module
		);

		if ((ret=mnew->dl_init_module(mnew)) != 1) {
			ERR("module `%s' failed to initialize, failure code %d: `%s'", mnew->fname, ret, mnew->errstr);
			lt_dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		switch (mnew->type) {
			case MI_TYPE_PREFILTER:
				strcpy(type, "prefilter");
				break;

			case MI_TYPE_PAYLOAD:
				strcpy(type, "payload");
				break;

			case MI_TYPE_FILTER:
				strcpy(type, "filter");
				break;

			case MI_TYPE_REPORT:
				strcpy(type, "report");
				break;

			case MI_TYPE_OUTPUT:
				strcpy(type, "output");
				break;

			default:
				ERR("module `%s' unknown type, unloading", mnew->fname);
				lt_dlclose(mnew->handle);
				xfree(mnew);
				bad=1;
				break;
		}

		if (bad) {
			continue;
		}

		MOD_VERSION(mnew->iver, maj, min);

		DBG(M_MOD, "module `%s' license `%s' author `%s' description `%s' type `%s' interface version %d.%02d loaded",
			mnew->fname,
			mnew->license,
			mnew->author,
			mnew->desc,
			type,
			maj,
			min
		);

		if (mnew->iver != MODULE_IVER) {
			int mymaj=0, mymin=0;

			MOD_VERSION(MODULE_IVER, mymaj, mymin);

			ERR("module version mismatch for `%s', expected version %d.%02d and found version %d.%02d",
				mnew->fname,
				mymaj,
				mymin,
				maj,
				min
			);
			lt_dlclose(mnew->handle);
			xfree(mnew);
			continue;
		}

		mnew->state=MI_STATE_INITED;

		if (last) {
			last->next=mnew;
		}
		else {
			mod_list_head=mnew;
		}

		mnew->next=NULL;
		last=mnew;
		mnew=NULL;
	}

	closedir(moddir);

	return 1;
}

int init_payload_modules(int (*add_pl)(uint16_t, uint16_t, int32_t, const uint8_t *, uint32_t, int (*)(uint8_t **, uint32_t *, void *), uint16_t )) {
	mod_entry_t *walk=NULL;
	const char *dl_estr=NULL;

	if (mod_list_head == NULL) {
		return 1;
	}

	if (add_pl == NULL) {
		PANIC("init payload modules with no add_payload hook");
	}

	walk=mod_list_head;

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		if (walk->type == MI_TYPE_PAYLOAD) {
			walk->func_u.dl_create_payload=(int (*)(uint8_t **, uint32_t *, void *))lt_dlsym(walk->handle, "create_payload");
			dl_estr=lt_dlerror();
			if (dl_estr != NULL) {
				ERR("cant find payload initialization hook for module `%s': %s", walk->fname, dl_estr);
				lt_dlclose(walk->handle);
				continue;
			}

			DBG(M_MOD, "create_payload found at %p", walk->func_u.dl_create_payload);

			walk->state=MI_STATE_HOOKED;

			/*
			 * XXX
			 */
			if (add_pl(walk->param_u.payload_s.proto,
				(uint16_t)walk->param_u.payload_s.dport,
				walk->param_u.payload_s.sport,
				NULL,
				0,
				walk->func_u.dl_create_payload,
				walk->param_u.payload_s.payload_group
				) != 1) {
				ERR("cant register payload for module `%s'", walk->fname);
				lt_dlclose(walk->handle);
				continue;
			}

			VRB(1, "added module payload for port %d proto %u",
				walk->param_u.payload_s.dport,
				walk->param_u.payload_s.proto
			);
		}
	}

	return 1;
}

int init_output_modules(void) {
	mod_entry_t *walk=NULL;
	const char *dl_estr=NULL;

	if (mod_list_head == NULL) {
		return 1;
	}

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		if (walk->type == MI_TYPE_OUTPUT) {
			walk->func_u.dl_send_output=(int (*)(const void *))lt_dlsym(walk->handle, "send_output");

			if (s->module_enable == NULL || strstr(s->module_enable, walk->name) == NULL) {
				walk->state=MI_STATE_DISABL;
				lt_dlclose(walk->handle);
				continue;
			}

			DBG(M_MOD, "enabling module `%s' `%s'", walk->fname, walk->name);

			dl_estr=lt_dlerror();
			if (dl_estr != NULL) {
				ERR("cant find output initialization hook for module `%s': %s", walk->fname, dl_estr);
				lt_dlclose(walk->handle);
				continue;
			}

			DBG(M_MOD, "send_output found at %p", walk->func_u.dl_send_output);

			if (walk->param_u.output_s.init_output != NULL) {
				walk->param_u.output_s.init_output();
			}

			walk->state=MI_STATE_HOOKED;

			DBG(M_MOD, "module `%s' name `%s' is active", walk->fname, walk->name);
		}
	}

	return 1;
}

int init_report_modules(void) {
	mod_entry_t *walk=NULL;
	const char *dl_estr=NULL;

	if (mod_list_head == NULL) {
		return 1;
	}

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		if (walk->type == MI_TYPE_REPORT) {
			walk->func_u.dl_create_report=(int (*)(const void *))lt_dlsym(walk->handle, "create_report");

			if (s->module_enable == NULL || strstr(s->module_enable, walk->name) == NULL) {
				walk->state=MI_STATE_DISABL;
				lt_dlclose(walk->handle);
				continue;
			}

			dl_estr=lt_dlerror();
			if (dl_estr != NULL) {
				ERR("cant find report initialization hook for module `%s': %s", walk->fname, dl_estr);
				lt_dlclose(walk->handle);
				continue;
			}

			DBG(M_MOD, "create_report: found at %p", walk->func_u.dl_create_report);

			if (walk->param_u.report_s.init_report != NULL) {
				walk->param_u.report_s.init_report();
			}
			walk->state=MI_STATE_HOOKED;

			if (walk->param_u.report_s.immed != 0) {
				union {
					void *ptr;
					mod_entry_t *m;
				} f_u;

				f_u.m=walk;

				if (s->report_mod_jit == NULL) {
					s->report_mod_jit=fifo_init();
				}

				fifo_push(s->report_mod_jit, f_u.ptr);

				DBG(M_MOD, "immediate report module, adding to jit list");
			}
		}
	}

	return 1;
}

void close_payload_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) {
		return;
	}

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		/* XXX clean up structure after dlclose */
		if (walk->type == MI_TYPE_PAYLOAD && walk->state == MI_STATE_HOOKED) {
			lt_dlclose(walk->handle);
			walk->state=MI_STATE_DISABL;
		}
	}

	return;
}

void close_output_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) {
		return;
	}

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		/* XXX clean up structure after dlclose */
		if (walk->type == MI_TYPE_OUTPUT && walk->state == MI_STATE_HOOKED) {
			lt_dlclose(walk->handle);
			walk->state=MI_STATE_DISABL;
		}
	}

	return;
}

void close_report_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) {
		return;
	}

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		/* XXX clean up structure after dlclose */
		if (walk->type == MI_TYPE_REPORT && walk->state == MI_STATE_HOOKED) {
			lt_dlclose(walk->handle);
			walk->state=MI_STATE_DISABL;
		}
	}

	return;
}

void push_report_modules(const void *r) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) {
		return;
	}

	if (r == NULL) {
		ERR("report null");
		return;
	}

	DBG(M_MOD, "in push report modules");

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		if (walk->type == MI_TYPE_REPORT && walk->state == MI_STATE_HOOKED && walk->param_u.report_s.immed == 0) {
			if (walk->func_u.dl_create_report != NULL) {
				walk->func_u.dl_create_report(r);
				DBG(M_MOD, "pushed report module");
			}
		}
	}

	return;
}

static void do_jit_report(void *i) {
	union {
		mod_entry_t *m;
		void *ptr;
	} i_u;

	i_u.ptr=i;

	/*
	 * XXX we need to filter HERE (based upon the report_s settings) not in the module
	 */

	assert(i != NULL && _r != NULL);

	if (i_u.m->type != MI_TYPE_REPORT || i_u.m->param_u.report_s.immed == 0) {
		ERR("bad report module inside jit list, ignoring it");
		return;
	}

	DBG(M_MOD, "jit'ing report to function %p with data %p", i_u.m->func_u.dl_create_report, _r);

	i_u.m->func_u.dl_create_report(_r);

	return;
}

void push_jit_report_modules(const void *r) {

	if (s->report_mod_jit == NULL) {
		return;
	}

	_r=r;

	DBG(M_MOD, "walking module jit list");

	fifo_walk(s->report_mod_jit, do_jit_report);

	_r=NULL;

	return;
}

void push_output_modules(const void *r) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) {
		return;
	}
	if (r == NULL) {
		ERR("report null");
		return;
	}

	DBG(M_MOD, "in push output modules");

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		if (walk->type == MI_TYPE_OUTPUT && walk->state == MI_STATE_HOOKED) {
			if (walk->func_u.dl_send_output != NULL) {
				walk->func_u.dl_send_output(r);
				DBG(M_MOD, "pushed output module");
			}
		}
	}

	return;
}

int fini_output_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) {
		return 1;
	}

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		if (walk->type == MI_TYPE_OUTPUT && walk->state == MI_STATE_HOOKED) {
			if (walk->param_u.output_s.fini_output != NULL) {
				walk->param_u.output_s.fini_output();
			}
		}
	}
	return 1;
}

int fini_report_modules(void) {
	mod_entry_t *walk=NULL;

	if (mod_list_head == NULL) {
		return 1;
	}

	for (walk=mod_list_head; walk != NULL; walk=walk->next) {
		if (walk->type == MI_TYPE_REPORT && walk->state == MI_STATE_HOOKED) {
			if (walk->param_u.report_s.fini_report != NULL) {
				walk->param_u.report_s.fini_report();
			}
		}
	}
	return 1;
}

void grab_keyvals(mod_entry_t *me) {
	mod_params_t *mp=NULL, *last=NULL;

	if (me == NULL) {
		return;
	}

	for (mp=s->mod_params; mp != NULL; last=mp, mp=mp->next) {
		if (strcmp(mp->name, me->name) == 0) {
			me->mp=mp;
			/*
			 * remove it from the list now a module has claimed it
			 */
			if (last == NULL) {
				s->mod_params=mp->next;
			}
			else {
				last->next=mp->next;
			}
			break;
		}
	}

	return;
}
