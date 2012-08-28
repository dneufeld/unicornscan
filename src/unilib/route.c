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
#include <net/route.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/cidr.h>

#include <patricia.h>

static void get_netroutes(void);
static int masktocidr(uint32_t );

static int need_netroutes=1;
static patricia_tree_t *rt=NULL;
static patricia_node_t *node=NULL;

typedef union route_info_t {
	struct info_s {
		char *intf;
		uint16_t metric;
		uint16_t flags;
		struct sockaddr_storage gw;
	} *info_s;
	void *p;
} route_info_t;

int getroutes(char **intf, struct sockaddr *tgt, struct sockaddr *tgtmask, struct sockaddr **gw) {
	static char lookup[128];
	route_info_t ri_u;
	union sock_u ts_u, gws_u;
	static struct sockaddr_storage gw_s;
	char *rstr=NULL;
	unsigned int rmask=0;

	assert(intf != NULL && tgt != NULL && tgtmask != NULL && gw != NULL);

	ts_u.s=tgt;
	*gw=NULL;

	rstr=cidr_saddrstr(tgt);
	if (rstr == NULL) {
		return -1;
	}

	rmask=cidr_getmask(tgtmask);

	snprintf(lookup, sizeof(lookup) -1, "%s/%u", rstr, rmask);

	DBG(M_RTE, "looking up route for `%s'", lookup);

	if (need_netroutes) {
		get_netroutes();
	}

	node=try_search_best(rt, lookup);
	if (node == NULL) {
		ERR("no route to host for `%s'", lookup);
		*intf=NULL;
		*gw=NULL;
		return -EHOSTUNREACH;
	}
	ri_u.p=node->data;
	assert(node->data != NULL);

	DBG(M_RTE, "found interface `%s' for network `%s'", ri_u.info_s->intf, lookup);

	*intf=ri_u.info_s->intf;
	if (ri_u.info_s->gw.ss_family != 0) {
		memcpy(&gw_s, &ri_u.info_s->gw, sizeof(struct sockaddr_storage));
		gws_u.ss=&gw_s;
		*gw=gws_u.s;
	}
	else {
		*gw=NULL;
	}

	return 1;
}

static int masktocidr(uint32_t mask) {
	int j=0, cidr=0;

	/* endian */
	for (j=0; j < 32; j++) {
		if ((mask & 0x80000000) == 0x80000000) {
			cidr++;
		}
		mask <<= 1;
	}

	return cidr;
}

#ifdef HAVE_PROC_NET_ROUTE

static void get_netroutes(void) {
	FILE *pnr=NULL;
	char lbuf[1024], intf[32];
	uint32_t dest, gw, refcnt, use, mask, irtt;
	uint16_t metric, flags, window, mtu;
	char destnet[128], gwstr[128], addstr[128];
	int lineno=0;

	pnr=fopen("/proc/net/route", "r");
	if (pnr == NULL) {
		ERR("cant open /proc/net/route: `%s'", strerror(errno));
		exit(1);
	}

	rt=New_Patricia(128);

	/*
	 * Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
	 * eth1    0045A8C0        00000000        0001    0       0       0       00FFFFFF        0       0       0
	 */

	for (lineno=0; fgets(lbuf, sizeof(lbuf) -1, pnr) != NULL; lineno++) {
		if (lineno == 0) {
			continue;
		}
#if 0
#define RTF_UP          0x0001          /* route usable                 */
#define RTF_GATEWAY     0x0002          /* destination is a gateway     */
#define RTF_HOST        0x0004          /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008          /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010          /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020          /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040          /* specific MTU for this route  */
#define RTF_MSS         RTF_MTU         /* Compatibility :-(            */
#define RTF_WINDOW      0x0080          /* per route window clamping    */
#define RTF_IRTT        0x0100          /* Initial round trip time      */
#define RTF_REJECT      0x0200          /* Reject route                 */
#endif
		/*                 in  de gw fl  ref us me ma mt  wi  ir	*/
		if (sscanf(lbuf, "%31s %x %x %hx %u %u %hu %x %hu %hu %u", intf, &dest, &gw, &flags, &refcnt, &use, &metric, &mask, &mtu, &window, &irtt) == 11) {
			int mycidr=0;
			struct in_addr ia;

			ia.s_addr=dest;
			strcpy(destnet, inet_ntoa(ia));
			mycidr=masktocidr(mask);
			ia.s_addr=gw;
			strcpy(gwstr, inet_ntoa(ia));

			if (flags & RTF_UP && mycidr > -1) {
				union sock_u s_u;
				route_info_t ri_u;

				ri_u.p=xmalloc(sizeof(*ri_u.info_s));
				memset(ri_u.p, 0, sizeof(*ri_u.info_s));

				ri_u.info_s->intf=xstrdup(intf);
				ri_u.info_s->metric=metric; /* could only be 0xff anyhow */
				ri_u.info_s->flags=flags;
				if ((flags & RTF_GATEWAY) == RTF_GATEWAY) {
					s_u.ss=&ri_u.info_s->gw;
					s_u.sin->sin_addr.s_addr=gw;
					s_u.sin->sin_family=AF_INET;
				}

				sprintf(addstr, "%s/%d", destnet, mycidr);
				DBG(M_RTE, "net %s via %s metric %u", addstr, (flags & RTF_GATEWAY) == 0 ? intf : gwstr, metric);
				node=make_and_lookup(rt, addstr);
				if (node == NULL) {
					exit(1);
				}
				node->data=ri_u.p;

			}
		}
		else {
			ERR("can not parse `%s'", lbuf);
		}
	}

	fclose(pnr);
	need_netroutes=0;

	return;
}

#else /* then use dnet , no proc net routes */

#include <dnet.h>

#endif
