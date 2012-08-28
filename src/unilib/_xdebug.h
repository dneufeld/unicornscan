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
#ifndef XMALLOC_H
 #define XMALLOC_H

#define xfree(ptr) _xfree(ptr); ptr=NULL
#define _xfree(ptr) __xfree((ptr), __FILE__, __LINE__)
#define xmalloc(ptr) _xmalloc((ptr), __FILE__, __LINE__)
#define xrealloc(ptr, size) _xrealloc((ptr), (size), __FILE__, __LINE__)
#define xstrdup(ptr) _xstrdup((ptr), __FILE__, __LINE__)
#define xcalloc(nmemb, len) _xcalloc((nmemb), (len))

void *_xmalloc(size_t, const char *, unsigned int);
void *_xcalloc(size_t, size_t, const char *, unsigned int);
void *_xrealloc(void *, size_t, const char *, unsigned int);
void __xfree(void *, const char *, unsigned int);
char *_xstrdup(const char *, const char *, unsigned int);

void *debug_malloc(size_t);
void *debug_calloc(size_t, size_t);
void *debug_realloc(void *, size_t);
void  debug_free(void *);
char *debug_strdup(const char *);

#define libc_malloc malloc
#define libc_strdup strdup
#define libc_realloc realloc
#define libc_free free
#define libc_calloc calloc
#endif
