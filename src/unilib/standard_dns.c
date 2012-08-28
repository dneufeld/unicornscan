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
#include <settings.h>

#include <unilib/xmalloc.h>
#include <unilib/cidr.h>
#include <unilib/standard_dns.h>
#include <unilib/output.h>

#define STDDNS_MAGIC	0xed01dda6
#define EXACT		1
#define CHECK_WILDCARD(x)	(0)

typedef struct stddns_context_t {
	uint32_t magic;
	void (*fp)(int, const void *, const void *);
	int flags;
} stddns_context_t;

void *stddns_init(void (*callback)(int /* type */, const void *, const void *), int flags) {
	stddns_context_t *sc=NULL;

	sc=xmalloc(sizeof(stddns_context_t));
	sc->magic=STDDNS_MAGIC;
	sc->fp=callback;
	sc->flags=flags;

	return (void *)sc;
}

/*
 * returns the hostname or NULL if not found
 */
char *stddns_getname(void *c, const struct sockaddr *is) {
	socklen_t sl=0;
	int ret=0;
	static char hname[2048];
	union {
		const struct sockaddr *p;
		struct f_s *fs;
	} is_u;
	union {
		stddns_context_t *c;
		void *p;
	} c_u;


	if (is == NULL || c == NULL) {
		return NULL;
	}

	c_u.p=c;
	assert(c_u.c->magic == STDDNS_MAGIC);

	is_u.p=is;

	memset(hname, 0, sizeof(hname));

	switch (is_u.fs->family) {
		case AF_INET:
			sl=(socklen_t )sizeof(struct sockaddr_in);
			break;

		case AF_INET6:
			sl=(socklen_t )sizeof(struct sockaddr_in6);
			break;

		default:
			break;
	}

	ret=getnameinfo(is, sl, hname, sizeof(hname), NULL /* service */, 0, NI_NAMEREQD);

	if (ret == 0) {
		if (strlen(hname) > 0) {
			return hname;
		}
		ERR("whoa, no name?");
		return NULL;
	}

#ifdef EAI_NODATA
	if (ret != EAI_NONAME && ret != EAI_NODATA) {
#else
	if (ret != EAI_NONAME) {
#endif
		ERR("getnameinfo fails: %s [%d]", gai_strerror(ret), ret);
	}

	return NULL;
}

/*
 * returns 0 if nothing found
 */
int stddns_getname_cb(void *c, const struct sockaddr *is) {
	socklen_t sl=0;
	static char hname[2048];
	union {
		const struct sockaddr *p;
		struct f_s *fs;
	} s_u;
	union {
		void *p;
		stddns_context_t *c;
	} c_u;
	int ret=0;

	if (is == NULL || c == NULL) {
		return -1;
	}
	c_u.p=c;

	assert(c_u.c->magic == STDDNS_MAGIC);
	assert(c_u.c->fp != NULL);

	s_u.p=is;

	memset(hname, 0, sizeof(hname));

	switch (s_u.fs->family) {
		case AF_INET:
			sl=(socklen_t )sizeof(struct sockaddr_in);
			break;

		case AF_INET6:
			sl=(socklen_t )sizeof(struct sockaddr_in6);
			break;

		default:
			ERR("Unknown address family %d", s_u.fs->family);
			return 0;
	}

	ret=getnameinfo(is, sl, hname, sizeof(hname), NULL /* service */, 0, NI_NAMEREQD);

	if (ret == 0) {
		if (strlen(hname) > 0) {
			c_u.c->fp(OUTPUT_REVERSE, (const void *)is, (const void *)hname);
			return 1;
		}
		ERR("whoa, no name?");
		return 0;
	}

#ifdef EAI_NODATA
	if (ret != EAI_NONAME && ret != EAI_NODATA) {
#else
	if (ret != EAI_NONAME) {
#endif
		ERR("getnameinfo fails: %s [%d]", gai_strerror(ret), ret);
	}

	return 0;
}

/*
 */
sockaddr_list_t **stddns_getaddr(void *c, const char *name) {
	struct addrinfo *ret=NULL, *walk=NULL;
	struct addrinfo hint;
	int iret=0;
	unsigned int cnt=0, idx=0;
	union {
		struct sockaddr *p;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *s6in;
	} s_u, s2_u;
	union {
		void *p;
		stddns_context_t *c;
	} c_u;
	sockaddr_list_t **sl=NULL;
	char *sstring=NULL, *ename=NULL;

	if (name == NULL || c == NULL) {
		return NULL;
	}

	c_u.p=c;

	assert(c_u.c->magic == STDDNS_MAGIC);

	memset(&hint, 0, sizeof(hint));

	hint.ai_family=PF_UNSPEC;
	if (s->ipv4_lookup != s->ipv6_lookup) {
		if (s->ipv4_lookup == 1 && s->ipv6_lookup == 0) {
			hint.ai_family=AF_INET;
		}
		else {
			hint.ai_family=AF_INET6;
		}
	}

	if (EXACT) {
		hint.ai_flags=AI_CANONNAME;
	}

	if (name == NULL || strlen(name) < 1) {
		return NULL;
	}

	if ((iret=getaddrinfo(name, NULL, &hint, &ret)) != 0) {
#ifdef EAI_NODATA
		if (iret != EAI_NONAME && iret != EAI_NODATA) {
#else
		if (iret != EAI_NONAME) {
#endif
			ERR("getaddrinfo errors for name `%s': %s", name, gai_strerror(iret));
		}
		DBG(M_DNS, "getaddrinfo fails for %s", name);
		return NULL;
	}

	for (walk=ret; walk != NULL; walk=walk->ai_next) {
		cnt++;
		assert(cnt < 9999);
	}
	DBG(M_DNS, "got %u awnsers for %s", cnt, name);

	cnt++;

	sl=(sockaddr_list_t **)xmalloc(sizeof(sockaddr_list_t *) * cnt);

	for (idx=0, walk=ret; walk != NULL; walk=walk->ai_next, idx++) {

		sl[idx]=(sockaddr_list_t *)xmalloc(sizeof(sockaddr_list_t));

		memset(&sl[idx]->s_u.s, 0, sizeof(struct sockaddr));

		s_u.p=&sl[idx]->s_u.s;
		s2_u.p=walk->ai_addr;

		/* XXX we dont get all the cnames this way */
		sstring=cidr_saddrstr(walk->ai_addr);
		DBG(M_DNS, "index %u for name `%s' ai_flags %d ai_family %d ai_socktype %d ai_protocol %d ai_addrlen %zu ai_addr %p (%s) ai_canonname %s ai_next %p", idx, name, walk->ai_flags, walk->ai_family, walk->ai_socktype, walk->ai_protocol, walk->ai_addrlen, walk->ai_addr, sstring != NULL ? sstring : "Nothing", walk->ai_canonname != NULL ? walk->ai_canonname : "Null", walk->ai_next);

		if (ename == NULL && EXACT && walk->ai_canonname != NULL) {
			ename=walk->ai_canonname;
			DBG(M_DNS, "setting ename to `%s' from `%s'", ename, name);
		}

		switch (walk->ai_family) {
			case AF_INET:
				s_u.sin->sin_addr.s_addr=s2_u.sin->sin_addr.s_addr;
				s_u.sin->sin_family=walk->ai_family;
				break;

			case AF_INET6:
				memcpy(&s_u.s6in->sin6_addr.s6_addr[0], &s2_u.s6in->sin6_addr.s6_addr[0], (128 / 8));
				s_u.s6in->sin6_family=walk->ai_family;
				break;

			default:
				ERR("unknown address family %d", walk->ai_family);
				break;
		}
		if (ename != NULL) {
			sl[idx]->ename=xstrdup(ename);
		}
	}

	sl[idx]=NULL;

	if (ret != NULL) {
		freeaddrinfo(ret);
	}

	return sl;
}

/*
 */
int stddns_getaddr_cb(void *c, const char *name) {
	struct addrinfo *ret=NULL, *walk=NULL;
	struct addrinfo hint;
	int iret=0;
	unsigned int idx=0;
	char *sstring=NULL, *ename=NULL;
	union {
		void *p;
		stddns_context_t *c;
	} c_u;

	if (name == NULL || c == NULL) {
		return -1;
	}

	c_u.p=c;

	assert(c_u.c->magic == STDDNS_MAGIC);
	assert(c_u.c->fp != NULL);

	memset(&hint, 0, sizeof(hint));

	if (s->ipv4_lookup != s->ipv6_lookup) {
		if (s->ipv4_lookup == 1 && s->ipv6_lookup == 0) {
			hint.ai_family=AF_INET;
		}
		else {
			hint.ai_family=AF_INET6;
		}
	}

	if (EXACT) {
		hint.ai_flags=AI_CANONNAME;
	}

	if (name == NULL || strlen(name) < 1) {
		return 0;
	}

	if ((iret=getaddrinfo(name, NULL, &hint, &ret)) != 0) {
#ifdef EAI_NODATA
		if (iret != EAI_NONAME && iret != EAI_NODATA) {
#else
		if (iret != EAI_NONAME) {
#endif
			ERR("getaddrinfo errors for name `%s': %s", name, gai_strerror(iret));
		}
		DBG(M_DNS, "getaddrinfo fails for %s", name);
		return 0;
	}

	for (idx=0, walk=ret; walk != NULL; walk=walk->ai_next, idx++) {

		/* XXX we dont get all the cnames this way */
		sstring=cidr_saddrstr(walk->ai_addr);
		DBG(M_DNS, "index %u for name `%s' ai_flags %d ai_family %d ai_socktype %d ai_protocol %d ai_addrlen %zu ai_addr %p (%s) ai_canonname %s ai_next %p", idx, name, walk->ai_flags, walk->ai_family, walk->ai_socktype, walk->ai_protocol, walk->ai_addrlen, walk->ai_addr, sstring != NULL ? sstring : "Nothing", walk->ai_canonname != NULL ? walk->ai_canonname : "Null", walk->ai_next);

		if (ename == NULL && EXACT == 1 && walk->ai_canonname != NULL) {

			ename=xstrdup(walk->ai_canonname);
			DBG(M_DNS, "setting ename to `%s' from `%s'", ename, name);

			/*
			 * this is a little weird, we need to check that we arent
			 * blabbering on about cnames for wildcard hosts, so we will
			 * manually check this fact
			 */
			if (CHECK_WILDCARD(walk->ai_addr) == 1) {
				continue;
			}
			c_u.c->fp(OUTPUT_ALIAS, name, ename);
		}

		c_u.c->fp(OUTPUT_FORWARD, ename != NULL ? ename : name, walk->ai_addr);
	}

	if (ret != NULL) {
		freeaddrinfo(ret);
	}

	return 1;
}

void stddns_freeaddr(void *c, struct sockaddr_list_t ***in) {
	unsigned int j=0;
	union {
		void *p;
		stddns_context_t *c;
	} c_u;

	assert(in != NULL && c != NULL);

	c_u.p=c;

	assert(c_u.c->magic == STDDNS_MAGIC);

	for (j=0; (*in)[j] != NULL; j++) {
		if ((*in)[j]->ename != NULL) {
			DBG(M_DNS, "free %p", (*in)[j]->ename);
			xfree((*in)[j]->ename);
			(*in)[j]->ename=NULL;
		}
		xfree((*in)[j]);
	}

	xfree(*in);
	*in=NULL;
	
	return;
}

void stddns_fini(void **p) {
	union {
		void *p;
		stddns_context_t *c;
	} c_u;

	c_u.p=*p;

	if (p == NULL || *p == NULL) {
		return;
	}

	assert(c_u.c->magic == STDDNS_MAGIC);
	xfree(*p);
	*p=NULL;

	return;
}
