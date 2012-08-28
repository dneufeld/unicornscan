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

#include <sys/ioctl.h>
#include <errno.h>

#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#include <pcap.h>
#else
#include <pcap.h>
#endif

#include <unilib/pcaputil.h>

int util_getheadersize(pcap_t *pdev, char *errorbuf) {
	int linktype=0;

	assert(pdev != NULL); assert(errorbuf != NULL);

	switch((linktype=pcap_datalink(pdev))) {
		case DLT_NULL:
			return 4;
#ifdef DLT_RAW
		case DLT_RAW:
			return 0;
#endif
		case DLT_EN10MB:
			return 14;
#ifdef DLT_LOOP /* NetBSD doesnt have this */
		case DLT_LOOP:
			return 8;
#endif
		case DLT_PPP:
			return 4;
		case DLT_IEEE802:
			return 22;
		default:
			snprintf(errorbuf, PCAP_ERRBUF_SIZE -1, "Unknown pcap linktype `%d'", linktype);
	}

	/* not reached */
	return -1;
}

#if defined(BIOCIMMEDIATE)
int util_preparepcap(pcap_t *pdev, char *errorbuf) {
	int pfd=-1, param=0;

	pfd=pcap_fileno(pdev);
	/* if its not a savefile then ioctl it (not always needed) */
	if (pfd) {
		param=1;
		if (ioctl(pfd, BIOCIMMEDIATE, &param) < 0) {
			;/* failure here is not always bad */
		}
	}
	return 1;
}
#else
int util_preparepcap(pcap_t *pdev, char *errorbuf) {

	if (pdev) errorbuf[0]='\0'; /* for icc */
	return 1;
}
#endif
