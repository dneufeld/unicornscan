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

#include <pcap.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/cidr.h>

static char pcap_errors[PCAP_ERRBUF_SIZE];

int get_interface_info(const char *iname, interface_info_t *ii) {
	pcap_if_t *pif=NULL, *walk=NULL;
	struct pcap_addr *pa=NULL;
	int got_linkaddr=0, got_ipaddr=0;

	CLEAR(pcap_errors);

	assert(iname != NULL && strlen(iname) > 0);
	assert(ii != NULL);

	if (pcap_findalldevs(&pif, pcap_errors) < 0) {
		ERR("pcap findalldevs fails: %s", pcap_errors);
		return -1;
	}

	for (walk=pif; walk != NULL; walk=walk->next) {

		assert(walk->name != NULL && strlen(walk->name) > 0);

		if (strcmp(walk->name, iname) == 0) {
			union sock_u pcapaddr_u, myaddr_u, mymask_u;

			DBG(M_INT, "got interface `%s' description `%s' looking for `%s'",
				walk->name,
				walk->description != NULL ? walk->description : "none",
				iname
			);

			for (pa=walk->addresses; pa != NULL; pa=pa->next) {
				pcapaddr_u.s=pa->addr;

				if (got_linkaddr == 0 && pcapaddr_u.fs->family == AF_PACKET) {
					if (pcapaddr_u.sl->sll_halen != 6) {
						ERR("not ethernet?!");
						return -1;
					}
					memcpy(ii->hwaddr, pcapaddr_u.sl->sll_addr, THE_ONLY_SUPPORTED_HWADDR_LEN);
					got_linkaddr=1;
				}
				else if (got_ipaddr == 0 && pcapaddr_u.fs->family == AF_INET) {
					myaddr_u.ss=&ii->myaddr;
					mymask_u.ss=&ii->mymask;

					/* XXX */
					memcpy(&ii->myaddr, pcapaddr_u.ss, sizeof(struct sockaddr_in));
					mymask_u.sin->sin_addr.s_addr=0xffffffff;
					mymask_u.sin->sin_family=AF_INET;
					got_ipaddr=1;
				}
			}

		}
	}

	if (got_linkaddr == 0) {
		ERR("cant find the link address for interface `%s'", iname);
		return -1;
	}

	if (got_ipaddr == 0) {
		ERR("cant find the ip address for interface `%s'", iname);
		return -1;
	}

        ii->mtu=1500;

	sprintf(ii->hwaddr_s, "%02x:%02x:%02x:%02x:%02x:%02x",
		ii->hwaddr[0], ii->hwaddr[1], ii->hwaddr[2],
		ii->hwaddr[3], ii->hwaddr[4], ii->hwaddr[5]
	);

        sprintf(ii->myaddr_s, "%s", cidr_saddrstr((const struct sockaddr *)&ii->myaddr));

        DBG(M_INT, "intf %s mtu %u addr %s ethaddr %s",
                iname, ii->mtu,
                ii->myaddr_s,
		ii->hwaddr_s
        );


	return 1;
}
