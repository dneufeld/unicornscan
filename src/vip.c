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

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/cidr.h>

#include <vip.h>

static unsigned int vip_off=0;

void vip_add(const struct sockaddr *hwaddr, const struct sockaddr *ipaddr, const char *iname) {

	DBG(M_DBG, "adding VIP (%s) hwaddr %s ipaddr %s interface %s", s->vi != NULL ? "new" : "additional", cidr_saddrstr(hwaddr), cidr_saddrstr(ipaddr), iname);

	if (s->vi == NULL) {
		s->vi=(interface_info_t **)xmalloc(sizeof(interface_info_t *));
	}
	else {
		s->vi=xrealloc(s->vi, sizeof(interface_info_t *) * vip_off) + sizeof(interface_info_t *);
	}
	s->vi[vip_off]=(interface_info_t *)xmalloc(sizeof(interface_info_t));
	memset(s->vi[vip_off], 0, sizeof(interface_info_t));

	return;
}
