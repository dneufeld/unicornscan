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
#include <unilib/xmalloc.h>
#include <unilib/standard_dns.h>
#include <unilib/output.h>
#include <unilib/prng.h>
#include <unilib/cidr.h>

#ifndef ntohll
# if BIGENDIAN == 0
#  define ntohll(x) (((unsigned long long)ntohl((x))) << 32) + ntohl((x) >> 32)
# else
#  define ntohll(x) (x)
# endif
#endif
#ifndef htonll
# if BIGENDIAN == 0
#  define htonll(x) (((unsigned long long)htonl((x))) << 32) + htonl((x) >> 32)
# else
#  define htonll(x) (x)
# endif
#endif

static inline int  cidr_in6cmp(const void *, const void *);
static inline void cidr_in6inc(void *);
static void cidr_fill6mask(void *, unsigned int );
static void cidr_u128str(const void *) __attribute__((unused));

typedef struct __attribute__((packed)) u128_t {
	uint64_t u;
	uint64_t l;
} u128_t;

static const uint32_t cidrmasktbl[]={
	0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
	0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
	0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
	0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
	0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
	0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
	0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
	0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
};

#if 0
void mktbl6data(void) {
#define TBIT	(((0ULL - 1) / 2) + 1)
#define EV(x)	((x) != 0 && (((x) + 1) % 2) == 0)
	uint64_t a=TBIT, b=0, *c=&a, f=0;
	for (;; f++) {
		printf("%s{0x%016llxULL, 0x%016llxULL},%c", EV(f) ? "" : "\t", a, b, EV(f) ? '\n' : ' ');
		*c=(*c >> 1) | TBIT;
		if (*c == (uint64_t)(0 - 1)) {
			if (c == &b) {
				printf("{0x%016llxULL, 0x%016llxULL}\n", a, b);
				break;
			}
			c=&b;
		}
	}
}
#endif

static const u128_t cidrmasktbl_6[]={
	{0x8000000000000000ULL, 0x0000000000000000ULL}, {0xc000000000000000ULL, 0x0000000000000000ULL},
	{0xe000000000000000ULL, 0x0000000000000000ULL}, {0xf000000000000000ULL, 0x0000000000000000ULL},
	{0xf800000000000000ULL, 0x0000000000000000ULL}, {0xfc00000000000000ULL, 0x0000000000000000ULL},
	{0xfe00000000000000ULL, 0x0000000000000000ULL}, {0xff00000000000000ULL, 0x0000000000000000ULL},
	{0xff80000000000000ULL, 0x0000000000000000ULL}, {0xffc0000000000000ULL, 0x0000000000000000ULL},
	{0xffe0000000000000ULL, 0x0000000000000000ULL}, {0xfff0000000000000ULL, 0x0000000000000000ULL},
	{0xfff8000000000000ULL, 0x0000000000000000ULL}, {0xfffc000000000000ULL, 0x0000000000000000ULL},
	{0xfffe000000000000ULL, 0x0000000000000000ULL}, {0xffff000000000000ULL, 0x0000000000000000ULL},
	{0xffff800000000000ULL, 0x0000000000000000ULL}, {0xffffc00000000000ULL, 0x0000000000000000ULL},
	{0xffffe00000000000ULL, 0x0000000000000000ULL}, {0xfffff00000000000ULL, 0x0000000000000000ULL},
	{0xfffff80000000000ULL, 0x0000000000000000ULL}, {0xfffffc0000000000ULL, 0x0000000000000000ULL},
	{0xfffffe0000000000ULL, 0x0000000000000000ULL}, {0xffffff0000000000ULL, 0x0000000000000000ULL},
	{0xffffff8000000000ULL, 0x0000000000000000ULL}, {0xffffffc000000000ULL, 0x0000000000000000ULL},
	{0xffffffe000000000ULL, 0x0000000000000000ULL}, {0xfffffff000000000ULL, 0x0000000000000000ULL},
	{0xfffffff800000000ULL, 0x0000000000000000ULL}, {0xfffffffc00000000ULL, 0x0000000000000000ULL},
	{0xfffffffe00000000ULL, 0x0000000000000000ULL}, {0xffffffff00000000ULL, 0x0000000000000000ULL},
	{0xffffffff80000000ULL, 0x0000000000000000ULL}, {0xffffffffc0000000ULL, 0x0000000000000000ULL},
	{0xffffffffe0000000ULL, 0x0000000000000000ULL}, {0xfffffffff0000000ULL, 0x0000000000000000ULL},
	{0xfffffffff8000000ULL, 0x0000000000000000ULL}, {0xfffffffffc000000ULL, 0x0000000000000000ULL},
	{0xfffffffffe000000ULL, 0x0000000000000000ULL}, {0xffffffffff000000ULL, 0x0000000000000000ULL},
	{0xffffffffff800000ULL, 0x0000000000000000ULL}, {0xffffffffffc00000ULL, 0x0000000000000000ULL},
	{0xffffffffffe00000ULL, 0x0000000000000000ULL}, {0xfffffffffff00000ULL, 0x0000000000000000ULL},
	{0xfffffffffff80000ULL, 0x0000000000000000ULL}, {0xfffffffffffc0000ULL, 0x0000000000000000ULL},
	{0xfffffffffffe0000ULL, 0x0000000000000000ULL}, {0xffffffffffff0000ULL, 0x0000000000000000ULL},
	{0xffffffffffff8000ULL, 0x0000000000000000ULL}, {0xffffffffffffc000ULL, 0x0000000000000000ULL},
	{0xffffffffffffe000ULL, 0x0000000000000000ULL}, {0xfffffffffffff000ULL, 0x0000000000000000ULL},
	{0xfffffffffffff800ULL, 0x0000000000000000ULL}, {0xfffffffffffffc00ULL, 0x0000000000000000ULL},
	{0xfffffffffffffe00ULL, 0x0000000000000000ULL}, {0xffffffffffffff00ULL, 0x0000000000000000ULL},
	{0xffffffffffffff80ULL, 0x0000000000000000ULL}, {0xffffffffffffffc0ULL, 0x0000000000000000ULL},
	{0xffffffffffffffe0ULL, 0x0000000000000000ULL}, {0xfffffffffffffff0ULL, 0x0000000000000000ULL},
	{0xfffffffffffffff8ULL, 0x0000000000000000ULL}, {0xfffffffffffffffcULL, 0x0000000000000000ULL},
	{0xfffffffffffffffeULL, 0x0000000000000000ULL}, {0xffffffffffffffffULL, 0x0000000000000000ULL},
	{0xffffffffffffffffULL, 0x8000000000000000ULL}, {0xffffffffffffffffULL, 0xc000000000000000ULL},
	{0xffffffffffffffffULL, 0xe000000000000000ULL}, {0xffffffffffffffffULL, 0xf000000000000000ULL},
	{0xffffffffffffffffULL, 0xf800000000000000ULL}, {0xffffffffffffffffULL, 0xfc00000000000000ULL},
	{0xffffffffffffffffULL, 0xfe00000000000000ULL}, {0xffffffffffffffffULL, 0xff00000000000000ULL},
	{0xffffffffffffffffULL, 0xff80000000000000ULL}, {0xffffffffffffffffULL, 0xffc0000000000000ULL},
	{0xffffffffffffffffULL, 0xffe0000000000000ULL}, {0xffffffffffffffffULL, 0xfff0000000000000ULL},
	{0xffffffffffffffffULL, 0xfff8000000000000ULL}, {0xffffffffffffffffULL, 0xfffc000000000000ULL},
	{0xffffffffffffffffULL, 0xfffe000000000000ULL}, {0xffffffffffffffffULL, 0xffff000000000000ULL},
	{0xffffffffffffffffULL, 0xffff800000000000ULL}, {0xffffffffffffffffULL, 0xffffc00000000000ULL},
	{0xffffffffffffffffULL, 0xffffe00000000000ULL}, {0xffffffffffffffffULL, 0xfffff00000000000ULL},
	{0xffffffffffffffffULL, 0xfffff80000000000ULL}, {0xffffffffffffffffULL, 0xfffffc0000000000ULL},
	{0xffffffffffffffffULL, 0xfffffe0000000000ULL}, {0xffffffffffffffffULL, 0xffffff0000000000ULL},
	{0xffffffffffffffffULL, 0xffffff8000000000ULL}, {0xffffffffffffffffULL, 0xffffffc000000000ULL},
	{0xffffffffffffffffULL, 0xffffffe000000000ULL}, {0xffffffffffffffffULL, 0xfffffff000000000ULL},
	{0xffffffffffffffffULL, 0xfffffff800000000ULL}, {0xffffffffffffffffULL, 0xfffffffc00000000ULL},
	{0xffffffffffffffffULL, 0xfffffffe00000000ULL}, {0xffffffffffffffffULL, 0xffffffff00000000ULL},
	{0xffffffffffffffffULL, 0xffffffff80000000ULL}, {0xffffffffffffffffULL, 0xffffffffc0000000ULL},
	{0xffffffffffffffffULL, 0xffffffffe0000000ULL}, {0xffffffffffffffffULL, 0xfffffffff0000000ULL},
	{0xffffffffffffffffULL, 0xfffffffff8000000ULL}, {0xffffffffffffffffULL, 0xfffffffffc000000ULL},
	{0xffffffffffffffffULL, 0xfffffffffe000000ULL}, {0xffffffffffffffffULL, 0xffffffffff000000ULL},
	{0xffffffffffffffffULL, 0xffffffffff800000ULL}, {0xffffffffffffffffULL, 0xffffffffffc00000ULL},
	{0xffffffffffffffffULL, 0xffffffffffe00000ULL}, {0xffffffffffffffffULL, 0xfffffffffff00000ULL},
	{0xffffffffffffffffULL, 0xfffffffffff80000ULL}, {0xffffffffffffffffULL, 0xfffffffffffc0000ULL},
	{0xffffffffffffffffULL, 0xfffffffffffe0000ULL}, {0xffffffffffffffffULL, 0xffffffffffff0000ULL},
	{0xffffffffffffffffULL, 0xffffffffffff8000ULL}, {0xffffffffffffffffULL, 0xffffffffffffc000ULL},
	{0xffffffffffffffffULL, 0xffffffffffffe000ULL}, {0xffffffffffffffffULL, 0xfffffffffffff000ULL},
	{0xffffffffffffffffULL, 0xfffffffffffff800ULL}, {0xffffffffffffffffULL, 0xfffffffffffffc00ULL},
	{0xffffffffffffffffULL, 0xfffffffffffffe00ULL}, {0xffffffffffffffffULL, 0xffffffffffffff00ULL},
	{0xffffffffffffffffULL, 0xffffffffffffff80ULL}, {0xffffffffffffffffULL, 0xffffffffffffffc0ULL},
	{0xffffffffffffffffULL, 0xffffffffffffffe0ULL}, {0xffffffffffffffffULL, 0xfffffffffffffff0ULL},
	{0xffffffffffffffffULL, 0xfffffffffffffff8ULL}, {0xffffffffffffffffULL, 0xfffffffffffffffcULL},
	{0xffffffffffffffffULL, 0xfffffffffffffffeULL}, {0xffffffffffffffffULL, 0xffffffffffffffffULL}
};

int cidr_get(const char *instr, struct sockaddr *net_id, struct sockaddr *netmask, unsigned int *cmask) {
	union {
		struct sockaddr *p;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
	} net_u, mask_u;
	struct in_addr ia;
	struct in6_addr ia6;
	sockaddr_list_t **sl=NULL;
	char *masksl=NULL, tbuf[4096];
	int exp_family=AF_INET, j=0, sd_flags;
	unsigned int maskset=0, tehmask=0;

	net_u.p=net_id;
	mask_u.p=netmask;

	if (net_id == NULL || netmask == NULL || instr == NULL) {
		return -1;
	}

	if (cmask != NULL) {
		*cmask=0;
	}

	if (sscanf(instr, "ipv4:%4095[^/]", tbuf) == 1) {
	}
	else if (sscanf(instr, "ipv6:%4095[^/]", tbuf) == 1) {
		exp_family=AF_INET6;
	}
	else if (sscanf(instr, "%4095[^/]", tbuf) != 1) {
		return -1;
	}

	if (s->ipv6_lookup == 1 && s->ipv4_lookup == 0) {
		exp_family=AF_INET6;
	}

	if ((masksl=strrchr(instr, '/')) != NULL) {
		masksl++;
		if (sscanf(masksl, "%u", &tehmask) != 1) {
			ERR("bad mask `%s' (non numeric?)", masksl);
			return -1;
		}
		maskset++;
	}

	if (inet_pton(AF_INET, tbuf, &ia) > 0 && exp_family != AF_INET6) {
		if (maskset == 0) {
			tehmask=32;
		}
		else if (tehmask > 32) {
			ERR("mask too big for ipv4");
			return -1;
		}

		net_u.sin->sin_family=AF_INET;
		mask_u.sin->sin_family=AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_LEN
		net_u.sin->sin_len=(uint8_t )sizeof(struct sockaddr_in);
		mask_u.sin->sin_len=(uint8_t )sizeof(struct sockaddr_in);
#endif
		mask_u.sin->sin_addr.s_addr=tehmask == 0 ? 0 : htonl(cidrmasktbl[tehmask - 1]);
		net_u.sin->sin_addr.s_addr=ia.s_addr & mask_u.sin->sin_addr.s_addr;

		if (cmask != NULL) {
			*cmask=tehmask;
		}

		DBG(M_DNS, "ip family %u for host %s", AF_INET, tbuf);
		return exp_family;
	}
	else if (inet_pton(AF_INET6, tbuf, &ia6) > 0) {
		if (maskset == 0) {
			tehmask=128;
		}
		else if (tehmask > 128) {
			ERR("mask too large for ipv6");
			return -1;
		}

		net_u.sin6->sin6_family=AF_INET6;
		mask_u.sin6->sin6_family=AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_LEN
		net_u.sin6->sin6_len=(uint8_t )sizeof(struct sockaddr_in6);
		mask_u.sin6->sin6_len=(uint8_t )sizeof(struct sockaddr_in6);
#endif
		cidr_fill6mask(mask_u.sin6->sin6_addr.s6_addr, tehmask);
		memcpy(net_u.sin6->sin6_addr.s6_addr, ia6.s6_addr, sizeof(struct in6_addr));

		for (j=0; j < 16; j++) {
			net_u.sin6->sin6_addr.s6_addr[j]=net_u.sin6->sin6_addr.s6_addr[j] & mask_u.sin6->sin6_addr.s6_addr[j];
		}

		if (cmask != NULL) {
			*cmask=tehmask;
		}

		DBG(M_DNS, "ipv6 family %u for host %s", AF_INET6, tbuf);
		return exp_family;
	}

	sd_flags=0;
	if (exp_family == AF_INET) {
		sd_flags=STDDNS_FLG_IPV4;
	}
	else {
		sd_flags=STDDNS_FLG_IPV6;
	}

	sl=stddns_getaddr(s->dns, tbuf);
	if (sl == NULL) {

		ERR("dns lookup fails for `%s': %s", tbuf, hstrerror(h_errno));
		return -1;
	}

	for (j=0; sl[j] != NULL; j++) {
		if (exp_family == AF_INET && sl[j]->s_u.fs.family == AF_INET) {
			if (maskset == 0) {
				tehmask=32;
			}
			else if (tehmask > 32) {

				ERR("mask too big for ipv4");
				stddns_freeaddr(s->dns, &sl);

				return -1;
			}

			net_u.sin->sin_family=AF_INET;
			mask_u.sin->sin_family=AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_LEN
			net_u.sin->sin_len=(uint8_t )sizeof(struct sockaddr_in);
			mask_u.sin->sin_len=(uint8_t )sizeof(struct sockaddr_in);
#endif
			mask_u.sin->sin_addr.s_addr=tehmask == 0 ? 0 : htonl(cidrmasktbl[tehmask - 1]);
			net_u.sin->sin_addr.s_addr=sl[j]->s_u.sin.sin_addr.s_addr & mask_u.sin->sin_addr.s_addr;

			stddns_freeaddr(s->dns, &sl);

			if (cmask != NULL) {
				*cmask=tehmask;
			}

			DBG(M_DNS, "ipv4 family %u for dns host %s", AF_INET, tbuf);
			return exp_family;
		}
		else {
			if (maskset == 0) {
				tehmask=128;
			}
			else if (tehmask > 128) {

				ERR("mask too large for ipv6");
				stddns_freeaddr(s->dns, &sl);

				return -1;
			}

			net_u.sin6->sin6_family=AF_INET6;
			mask_u.sin6->sin6_family=AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_LEN
			net_u.sin6->sin6_len=(uint8_t )sizeof(struct sockaddr_in6);
			mask_u.sin6->sin6_len=(uint8_t )sizeof(struct sockaddr_in6);
#endif
			cidr_fill6mask(mask_u.sin6->sin6_addr.s6_addr, tehmask);
			memcpy(net_u.sin6->sin6_addr.s6_addr, sl[j]->s_u.sin6.sin6_addr.s6_addr, sizeof(struct in6_addr));

			for (j=0; j < 16; j++) {
				net_u.sin6->sin6_addr.s6_addr[j]=net_u.sin6->sin6_addr.s6_addr[j] & mask_u.sin6->sin6_addr.s6_addr[j];
			}

			stddns_freeaddr(s->dns, &sl);

			if (cmask != NULL) {
				*cmask=tehmask;
			}

			DBG(M_DNS, "ipv6 family %u for dns host %s", AF_INET6, tbuf);
			return exp_family;
		}
	}

	/*
	 * we didnt match anything
	 */
	stddns_freeaddr(s->dns, &sl);

	return -1;
}

static void cidr_fill6mask(void *a, unsigned int mask) {
	union {
		void *p;
		uint64_t *dw;
	} p_u;

	if (mask == 0) {
		memset(p_u.p, 0, sizeof(struct in6_addr));
		return;
	}
	p_u.p=a;
	*p_u.dw=htonll(cidrmasktbl_6[mask - 1].u);
	p_u.dw++;
	*p_u.dw=htonll(cidrmasktbl_6[mask - 1].l);
	return;
}

void cidr_inchost(struct sockaddr *p) {
	union {
		struct sockaddr *p;
		struct sockaddr_in *sin;
		struct sockaddr_in6 *sin6;
		struct f_s *fs;
	} s_u;
	uint32_t tmp=0;

	s_u.p=p;

	switch (s_u.fs->family) {
		case AF_INET:
			tmp=ntohl(s_u.sin->sin_addr.s_addr) + 1;
			s_u.sin->sin_addr.s_addr=htonl(tmp);
			return;

		case AF_INET6:
			cidr_in6inc(s_u.sin6->sin6_addr.s6_addr);
			return;

		default:
			break;
	}

	return;
}

int cidr_within(const struct sockaddr *host, const struct sockaddr *net, const struct sockaddr *mask) {
	union {
		const struct sockaddr *p;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
		const struct f_s *fs;
	} host_u, net_u, mask_u;

	if (host == NULL || net == NULL || mask == NULL) {
		ERR("one or more arguments null");
		return -1;
	}

	host_u.p=host;
	net_u.p=net;
	mask_u.p=mask;

	if (net_u.fs->family != mask_u.fs->family) {
		ERR("net family not same as mask family");
		return -1;
	}

	if (host_u.fs->family != net_u.fs->family) {
		ERR("host family not same as network family");
		return 0;
	}

	if (host_u.fs->family == AF_INET) {
		uint32_t host_max, host_min, host_cur;

		host_min=ntohl(net_u.sin->sin_addr.s_addr);
		host_max=host_min | ~(ntohl(mask_u.sin->sin_addr.s_addr));
		host_cur=ntohl(host_u.sin->sin_addr.s_addr);

		if (host_cur > host_max || host_cur < host_min) {
			return 0;
		}

		return 1;
	}
	else if (host_u.fs->family == AF_INET6) {
		u128_t host_max, host_min, host_cur;
		union {
			u128_t *p;
			uint8_t *c;
		} dw_u;
		int j=0;

		memcpy(&host_min, net_u.sin6->sin6_addr.s6_addr, sizeof(host_min));
		memcpy(&host_max, net_u.sin6->sin6_addr.s6_addr, sizeof(host_max));

		dw_u.p=&host_max;
		for (j=0; j < 16; j++) {
			*dw_u.c=net_u.sin6->sin6_addr.s6_addr[j] | ~(mask_u.sin6->sin6_addr.s6_addr[j]);
			dw_u.c++;
		}

		memcpy(&host_cur, host_u.sin6->sin6_addr.s6_addr, sizeof(struct in6_addr));

		if (	(cidr_in6cmp(&host_cur, &host_min) != -1 /* so cur is >= host_min */) &&
			(cidr_in6cmp(&host_cur, &host_max) != 1  /* so cur is <= host_max */)) {
			return 1;
		}

		return 0;
	}
	else {
		return -1;
	}

	return 0;
}

void cidr_randhost(struct sockaddr *host, const struct sockaddr *network, const struct sockaddr *netmask) {
	union sock_u host_u;
	union csock_u net_u, mask_u;

	net_u.s=network;
	mask_u.s=netmask;
	host_u.s=host;

	memcpy(host, network, sizeof(struct sockaddr_storage));

	if (netmask == NULL) {
		return;
	}

	if (net_u.fs->family == AF_INET) {
		uint32_t mix=0;

		assert(mask_u.fs->family == AF_INET);
		mix=prng_get32() & ~(mask_u.sin->sin_addr.s_addr);

		host_u.sin->sin_addr.s_addr ^= mix;
	}
	else {
		ERR("randhost: fixme");
	}

	return;
}

double  cidr_numhosts(const struct sockaddr *network, const struct sockaddr *netmask) {
	double ret=0.0;
	union sock_u net_u, mask_u;

	net_u.s=network;
	mask_u.s=netmask;

	if (netmask == NULL) {
		return 1.0;
	}

	if (net_u.fs->family == AF_INET) {
		uint32_t high_ip=0, low_ip=0, mask=0;

		if (mask_u.sin->sin_addr.s_addr == 0xffffffff) {
			return 1;
		}

		mask=ntohl(mask_u.sin->sin_addr.s_addr);
		low_ip=ntohl(net_u.sin->sin_addr.s_addr);
		high_ip=low_ip | ~(mask);
		high_ip++;

		assert(high_ip > low_ip);

		return (double )high_ip - low_ip;
	}
	else {
		ERR("nyi");
	}

	return ret;
}

unsigned int cidr_getmask(const struct sockaddr *in) {
	union {
		struct f_s *fs;
		const struct sockaddr *s;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} s_u;
	unsigned int mask=0, tgt=0;

	s_u.s=in;

	switch (s_u.fs->family) {
		case AF_INET:
			tgt=ntohl(s_u.sin->sin_addr.s_addr);

			if (tgt == 0) {
				return 0;
			}

			for (mask=0; mask < sizeof(cidrmasktbl); mask++) {
				if (cidrmasktbl[mask] == tgt) {
					return mask + 1;
				}
			}
			break;

		case AF_INET6:
			ERR("nyi");
			break;

		default:
			ERR("unsupported address family");
			break;
	}

	return 0;
}

char *cidr_saddrstr(const struct sockaddr *in) {
	union {
		struct f_s *fs;
		const struct sockaddr *s;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
	} s_u;
	static char nbuf[256], *ret=NULL;
	const void *p=NULL;

	if (in == NULL) {
		return NULL;
	}

	s_u.s=in;

	switch (s_u.fs->family) {
		case AF_INET:
			p=&s_u.sin->sin_addr;
			break;

		case AF_INET6:
			p=&s_u.sin6->sin6_addr;
			break;

		default:
			ERR("unknown address family `%d'?", s_u.fs->family);
			return NULL;
	}

	ret=inet_ntop(s_u.fs->family, p, nbuf, sizeof(nbuf) - 1); /* GAH */
	if (ret == NULL) {
		ERR("inet_ntop fails: %s", strerror(errno));
	}

	return ret;
}

/*
 * returns:
 * 1  if a >  b
 * 0  if a == b
 * -1 if a <  b
 */
static inline int  cidr_in6cmp(const void *a, const void *b) {
	union {
		const uint8_t *c;
		const void *p;
	} p1_u, p2_u;
	int j=0;

	p1_u.p=a;
	p2_u.p=b;
	for (j=0; j < 16; j++) {
		if (p1_u.c[j] > p2_u.c[j]) {
			return 1;
		}
		else if (p1_u.c[j] != p2_u.c[j]) {
			return -1;
		}
	}

	return 0;
}

static inline void cidr_in6inc(void *a) {
#if BIGENDIAN == 0
	union {
		uint8_t *c;
		uint64_t *dw;
		void *p;
	} p_u;
	uint64_t dw;
#endif
	u128_t tmp;

#if BIGENDIAN == 0
	p_u.p=a;
	tmp.l=ntohll(*p_u.dw);
	p_u.dw++;
	tmp.u=ntohll(*p_u.dw);
#else
	memcpy(&tmp, a, sizeof(tmp));
#endif

#if BIGENDIAN == 0
	tmp.u++;
	if (tmp.u == 0ULL) {
		tmp.l++;
	}
#else
	tmp.l++;
	if (tmp.l == 0ULL) {
		tmp.u++;
	}
#endif


#if BIGENDIAN == 0
	dw=htonll(tmp.l);
	p_u.p=a;
	memcpy(p_u.p, &dw, sizeof(dw));
	p_u.dw++;
	dw=htonll(tmp.u);
	memcpy(p_u.p, &dw, sizeof(dw));
#else
	memcpy(a, &tmp, sizeof(tmp));
#endif

        return;
}

static void cidr_u128str(const void *in) {
	const uint8_t *c=NULL;
	int cnt=0;

	printf("BUF DUMP: ");
	for (c=(const uint8_t *)in, cnt=0; cnt < 16; cnt++, c++) {
		printf(":%02x", *c);
	}
	printf("\n");

	return;
}
