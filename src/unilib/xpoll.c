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

#include <poll.h>
#include <sys/poll.h>
#include <errno.h>

#include <settings.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/xpoll.h>

/*
XXX add epoll support and perhaps a wrapper for RT IO etc
XXX make dynamic not bounded
*/

int xpoll(xpoll_t *array, uint32_t len, int timeout) {
	uint32_t j=0;
	int ret=0;
	xpoll_t *start=NULL;
	struct pollfd pdf[MAX_CONNS];

	assert(array != NULL);
	assert(len < MAX_CONNS);

	for (j=0, start=array; j < len; j++, array++) {
		pdf[j].fd=array->fd;
		array->rw=0;
		pdf[j].revents=0;
		pdf[j].events=POLLIN|POLLPRI;
	}

repoll:
	if ((ret=poll(&pdf[0], len, timeout)) < 0) {
		if (ret < 0 && errno == EINTR) {
			goto repoll;
		}
		ERR("poll errors: %s", strerror(errno));
		return -1;
	}

	for (array=start, j=0; j < len; j++, array++) {
		array->rw=0;
		if (pdf[j].revents & (POLLHUP|POLLERR|POLLNVAL)) {
			array->rw |= XPOLL_DEAD;
		}
		if (pdf[j].revents & POLLIN) {
			array->rw |= XPOLL_READABLE;
		}
		if (pdf[j].revents & POLLPRI) {
			array->rw |= XPOLL_PRIREADABLE;
		}
		DBG(M_PIO, "Socket %d is %s %s %s", pdf[j].fd,
			(array->rw & (POLLHUP|POLLERR|POLLNVAL) ? "dead" : "alive"),
			(array->rw & (POLLIN) ? "readable" : "not readable"),
			(array->rw & (POLLPRI) ? "pri-writable" : "not pri-writeable")
		);
	}

	return ret;
}
