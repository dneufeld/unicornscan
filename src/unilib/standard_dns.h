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
#ifndef _STANDARD_DNS_H
# define _STANDARD_DNS_H

typedef struct sockaddr_list_t {
	union {
		struct f_s fs;
		struct sockaddr s;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} s_u;
	char *ename;
} sockaddr_list_t;

#define OUTPUT_REVERSE	1
#define OUTPUT_FORWARD	2
#define OUTPUT_ALIAS	3

/*
 * returns context or NULL on failure
 * callback may be NULL, but take care not to call any of the *_cb functions
 * callback is a function that:
 * first argument is type "type" of data being sent to the callback,
 * and the 2 following arguments are the subject and result respectively
 */
extern void *stddns_init(void (* /* callback */)(int, const void *, const void *), int /* flags */);

#define STDDNS_FLG_IPV4		1
#define STDDNS_FLG_IPV6		2
#define STDDNS_FLG_EXACT	4

#define STDDNS_FLG_ALL		7

/*
 * returns the hostname or NULL if not found
 */
extern char *stddns_getname(void * /* context */, const struct sockaddr *);

/*
 * returns 0 if nothing matched
 */
int stddns_getname_cb(void * /* context */, const struct sockaddr *);

/*
 * writes the address family and struct sockaddr * for name,
 * returns 1 for sucess or something else on failure
 */
sockaddr_list_t **stddns_getaddr(void * /* context */, const char *);

/*
 * returns 0 if nothing matched
 */
int stddns_getaddr_cb(void * /* context */, const char *);

/*
 */
void stddns_freeaddr(void * /* context */, struct sockaddr_list_t ***);

extern void stddns_fini(void ** /* pointer to context */);

#endif
