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
#include <settings.h>

#include <errno.h>
#include <ctype.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/panic.h>

static char *my_strdup(const char *, const char *, unsigned int);
static void xdebug_display_memory(FILE *, void *, size_t);
static void xdebug_verify_guard(void *, size_t );

#define STRICT	1

typedef struct memchunk_t {
	struct memchunk_t *next;
	void *p;
	size_t sz;
	char *file;
	unsigned int lineno;
	int realloced;
} memchunk_t;

static memchunk_t *head=NULL;
static uint32_t guard=0x410043ef;

static void xdebug_atexit(void) __attribute__((destructor));
static void xdebug_start(void) __attribute__((constructor));
static void xdebug_dumpleak(int /* not used */);

static size_t track(void *, size_t, const char *, unsigned int, int);

#define ACTION_MALLOCED		1
#define ACTION_REALLOCED	2
#define ACTION_FREED		3
#define ACTION_GETSIZE		4

static void xdebug_start(void) {
	struct sigaction sa;

	sa.sa_handler=xdebug_dumpleak;
	sa.sa_flags=0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(XDEBUG_SIGNAL, &sa, NULL) < 0) {
		ERR("sigaction failts: %s", strerror(errno));
	}

	srand(getpid());

	/*
	 * this guard stuff was never really intended for security, but what the heck, lets at least
	 * add a bit of spice to the mix
	 */
	guard ^= (UINT_MAX & (unsigned int)rand());

	/* fprintf(stderr, "signal %d to dump memory in real time", XDEBUG_SIGNAL); */
}

static size_t track(void *pointer, size_t len, const char *file, unsigned int lineno, int action) {

	if (action == ACTION_MALLOCED) {
		memchunk_t *walk=NULL, *old=NULL;

		if (head == NULL) {
			head=(memchunk_t *)malloc(sizeof(memchunk_t));
			assert(head != NULL);
			head->next=NULL;
			head->p=pointer;
			head->sz=len;
			if (file != NULL) {
				size_t sz=0;

				sz=strlen(file) + 1;
				head->file=malloc(sz);
				assert(head->file != NULL);
				memcpy(head->file, file, sz - 1);
				head->file[sz - 1]='\0';
			}
			else {
				head->file=NULL;
			}
			head->lineno=lineno;
			head->realloced=0;

			return head->sz;
		}

		for (walk=head ; walk->next != NULL ; old=walk, walk=walk->next) {
			;
		}

		walk->next=(memchunk_t *)malloc(sizeof(memchunk_t));
		walk=walk->next;
		walk->next=NULL;
		walk->p=pointer;
		walk->sz=len;
		if (file != NULL) {
			size_t sz=0;

			sz=strlen(file) + 1;
			walk->file=malloc(sz);
			assert(walk->file != NULL);
			memcpy(walk->file, file, sz - 1);
			walk->file[sz - 1]='\0';
		}
		else {
			walk->file=NULL;
		}
		walk->lineno=lineno;
		walk->realloced=0;

		return walk->sz;
	}
	else if (action == ACTION_FREED) {
		memchunk_t *old=NULL, *walk=NULL;
		int found=0;
		size_t ret=0;

		if (head == NULL) {
			PANIC("free non-existant pointer (head null)");
		}
		for (walk=head ; walk != NULL ; old=walk, walk=walk->next) {
			if (walk->p == pointer) {
				found=1;
				ret=walk->sz;
				break;
			}
		}
		if (found == 0) {
			PANIC("delting non-existant pointer (not on list)");
		}
		assert(walk != NULL);
		if (old == NULL) {
			assert(walk == head);
			if (head->next == NULL) {
				head=NULL;
			}
			else {
				head=head->next;
			}
			if (walk->file != NULL) {
				free(walk->file);
				walk->file=NULL;
			}
			free(walk);
			walk=NULL;
		}
		else {
			assert(old->next == walk);
			old->next=walk->next;
			if (walk->file != NULL) {
				free(walk->file);
				walk->file=NULL;
			}
			free(walk);
			walk=NULL;
		}

		return ret;
	}
	else if (action == ACTION_GETSIZE) {
		memchunk_t *walk=NULL;

		if (head == NULL) {
			PANIC("getsize for non-existant pointer (head null)");
		}
		for (walk=head ; walk != NULL ; walk=walk->next) {
			if (walk->p == pointer) {
				return walk->sz;
			}
		}
		PANIC("getsize for non-existant pointer");
	}
	else {
		PANIC("track unknown action");
	}

	return 0;
}

void *_xmalloc(size_t n, const char *file, unsigned int lineno) {
	union {
		uint32_t *g;
		char *w;
		void *p;
	} g_u;
	char *e=NULL;

#ifdef STRICT
	if (n < 1) {
		PANIC("attempt to allocate 0 or less bytes of memory");
	}
#endif

	g_u.p=malloc(n + (sizeof(uint32_t) * 2));
	if (g_u.p == NULL) {
		PANIC("malloc failed");
	}

	memset(g_u.p, 0x41, n);
	*g_u.g=guard;
	e=(char *)g_u.p;
	e += (sizeof(uint32_t) + n);
	*(uint32_t *)e=guard;

	track(g_u.p, n, file, lineno, ACTION_MALLOCED);
	g_u.g++;
	return g_u.p;
}

void *_xcalloc(size_t n, size_t l, const char *file, unsigned int lineno) {
	void *p=NULL;
	size_t asz=0;

	asz=n * l;

#ifdef STRICT
	assert(asz > n && asz > l);
#endif

	p=_xmalloc(asz, file, lineno);

	memset(p, 0, asz);

	return p;
}

void *_xrealloc(void *obuf, size_t n, const char *file, unsigned int lineno) {
	union {
		uint32_t *g;
		void *p;
	} g_u, ng_u;
	size_t sz=0;

	if (obuf == NULL) {
#ifndef STRICT
		return _xmalloc(n, file, lineno);
#else
		PANIC("attempt to realloc a null pointer");
#endif
	}

#ifdef STRICT
	if (n < 1) {
		PANIC("attempt to increase allocation by 0 bytes");
	}
#endif

#ifndef STRICT
	if (n == 0) {
		__xfree(obuf, file, lineno);
		return NULL;
	}
#endif

	g_u.p=obuf;
	g_u.g--;
	if (*g_u.g != guard) {
		PANIC("guard %08x != %08x, heap corruption", *g_u.g, guard);
	}
	sz=track(g_u.p, 0, file, lineno, ACTION_GETSIZE);
	g_u.g++;

#ifdef STRICT
	assert(n > sz);
#endif

	ng_u.p=_xmalloc(n, file, lineno);

	memcpy(ng_u.p, g_u.p, sz);

	__xfree(g_u.p, file, lineno);

	return ng_u.p;
}

void __xfree(void *p, const char *file, unsigned int lineno) {
	union {
		uint32_t *g;
		void *p;
		char *c;
	} g_u;
	char *e=NULL;
	size_t sz=0;

#ifdef STRICT
	if (p == NULL) {
		PANIC("attempt to free a NULL pointer");
	}
#else
	if (p == NULL) {
		return;
	}
#endif
	g_u.p=p;
	g_u.g--;
	if (*g_u.g != guard) {
		PANIC("guard %08x != %08x, heap corruption", *g_u.g, guard);
	}
	e=g_u.p;

	sz=track(g_u.p, 0, file, lineno, ACTION_FREED);

	e += (sz + sizeof(uint32_t));
	if (*(uint32_t *)e != guard) {
		PANIC("guard %08x != %08x, heap corruption", *(uint32_t *)e, guard);
	}

	memset(g_u.p, 0x42, sz + (sizeof(uint32_t) * 2));

	free(g_u.p);
	g_u.p=NULL;

	return;
}

char *_xstrdup(const char *p, const char *file, unsigned int lineno) {
	char *_p=NULL;

#ifdef STRICT
	if (p == NULL || strlen(p) < 1) {
		PANIC("Attempt to dup a %s string", p == NULL ? "null" : "blank");
	}
#endif

	_p=my_strdup(p, file, lineno);
	if (_p == NULL) {
		PANIC("strdup failed");
	}

	return _p;
}

static char *my_strdup(const char *in, const char *file, unsigned int lineno) {
	size_t asz=0;
	char *ret=NULL;

	asz=strlen(in) + 1;
	ret=_xmalloc(asz, file, lineno);
	memcpy(ret, in, asz - 1);
	ret[asz - 1]='\0';

	return ret;
}

static void xdebug_dumpleak(int unused) {
	memchunk_t *walk=NULL, *old=NULL;
	char *fname=NULL;
	FILE *out=NULL;

	if ((fname=getenv("XDEBUG_OUTFILE")) != NULL) {
		out=fopen(fname, "w+");
		if (out == NULL) {
			ERR("fopen `%s' fails, using stderr: %s", fname, strerror(errno));
			out=stderr;
		}
	}
	else {
		out=stderr;
	}

	for (walk=head ; walk != NULL ; old=walk, walk=walk->next) {
		xdebug_verify_guard(walk->p, walk->sz);

		fprintf(out, "leak %p size %zu%s from %s:%u\n", walk->p, walk->sz, walk->realloced == 0 ? "" : " Reallocated", walk->file, walk->lineno);
		if (getenv("XDEBUG_LEAKDUMP") != NULL) {
			xdebug_display_memory(out, walk->p, walk->sz);
		}
	}

	return;
}

static void xdebug_atexit(void) {
	memchunk_t *walk=NULL, *old=NULL;
	char *fname=NULL;
	FILE *out=NULL;

	if ((fname=getenv("XDEBUG_OUTFILE")) != NULL) {
		out=fopen(fname, "w+");
		if (out == NULL) {
			ERR("fopen `%s' fails, using stderr: %s", fname, strerror(errno));
			out=stderr;
		}
	}
	else {
		out=stderr;
	}

	if (getenv("XDEBUG_LEAK") != NULL) {
		for (walk=head ; walk != NULL ; old=walk, walk=walk->next) {
			xdebug_verify_guard(walk->p, walk->sz);

			fprintf(out, "leak %p size %zu%s from %s:%u\n", walk->p, walk->sz, walk->realloced == 0 ? "" : " Reallocated", walk->file, walk->lineno);
			if (getenv("XDEBUG_LEAKDUMP") != NULL) {
				xdebug_display_memory(out, walk->p, walk->sz);
			}
			if (old != NULL) {
				if (old->file != NULL) {
					free(old->file);
					old->file=NULL;
				}
				free(old);
				old=NULL;
			}
		}
		if (old != NULL) {
			if (old->file != NULL) {
				free(old->file);
				old->file=NULL;
			}
			free(old);
			old=NULL;
		}
	}

	return;
}

static void display_char(FILE *out, char in) {
	if (isgraph(in)) {
		fprintf(out, "%c", in);
	}
	else {
		switch (in) {
			case '\n':
				fprintf(out, "\\n"); break;
			case '\v':
				fprintf(out, "\\v"); break;
			case '\t':
				fprintf(out, "\\t"); break;
			case '\f':
				fprintf(out, "\\f"); break;
			case '\r':
				fprintf(out, "\\r"); break;
			default:
				fprintf(out, "\\x%02x", (uint8_t )in);
				break;
		}
	}
}

void xdebug_display_memory(FILE *out, void *in, size_t len) {
	union {
		char *c;
		void *p;
	} m_u;
	size_t j=0;

	m_u.p=in;

	for (j=0 ; j < len ; j++) {
		if (j != 0 && (j % 16) == 0) {
			fprintf(out, "\n");
		}
		display_char(out, *m_u.c);
		m_u.c++;
	}

	fprintf(out, "\n");

	return;
}

static void xdebug_verify_guard(void *p, size_t sz) {
	union {
		uint32_t *g;
		uint8_t *c;
		void *p;
	} g_u;

	g_u.p=p;

	assert(p != NULL);

	if (*g_u.g != guard) {
		PANIC("guard %08x != %08x, heap corruption", *g_u.g, guard);
	}

	g_u.g++;
	g_u.c += sz;

	if (*g_u.g != guard) {
		PANIC("guard %08x != %08x, heap corruption", *g_u.g, guard);
	}

	return;
}

#ifdef _WRAP_

#include <stdio.h>
#include <stdlib.h>
#include <settings.h>

settings_t *s=NULL;

int main(int argc, char ** argv) {
	char *cow=NULL;

	s=(settings_t *)xmalloc(sizeof(settings_t));
	s->_stdout=stdout;
	s->_stderr=stderr;

	cow=xstrdup("frog frog");
	fprintf(stderr, "%s\n", cow);

	xfree(cow);

	cow=xmalloc(16);
	//memset(cow, 0x41, 17);
	//memset(cow - 1, 0x41, 17);

	cow=xrealloc(cow, 32);

	memset(cow, 0x31, 32);

	xfree(cow);

	exit(0);
}

#endif
