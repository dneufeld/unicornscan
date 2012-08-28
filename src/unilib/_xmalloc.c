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

#include <unilib/xmalloc.h>

void *_xrealloc(void *obuf, size_t n) {
	void *p=NULL;
	if (obuf == NULL) {
		return _xmalloc(n);
	}
	if (n < 1) {
		PANIC("attempt to increase allocation by 0 bytes");
	}
	p=realloc(obuf, n);
	if (p == NULL) {
		PANIC("realloc fails");
	}
	return p;
}

void *_xmalloc(size_t n) {
	void *p=NULL;

	if (n < 1) {
		PANIC("attempt to allocate 0 or less bytes of memory");
	}

	p=malloc(n);
	if (p == NULL) {
		PANIC("malloc failed");
	}
	return p;
}

void _xfree(void *p) {
	if (p == NULL) {
		PANIC("attempt to free a NULL pointer");
	}
	free(p);
	return;
}

char *_xstrdup(const char *p) {
	char *_p=NULL;

	_p=strdup(p);
	if (_p == NULL) {
		PANIC("strdup failed");
	}
	return _p;
}
