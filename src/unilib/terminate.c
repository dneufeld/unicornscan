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

#include <stdarg.h>
#include <errno.h>

#include <settings.h>
#include <unilib/output.h>
#include <unilib/terminate.h>

void terminate(const char *msg, ...) {
	va_list ap;
	char msgbuf[2048];

	if (ident_name_ptr == NULL) ident_name_ptr="Unknown";

	CLEAR(msgbuf);
	va_start(ap, msg);
	vsnprintf(msgbuf, sizeof(msgbuf) -1, msg, ap);

	if (errno) {
		fprintf(s->_stderr, "%s exiting %s: system error %s\n", ident_name_ptr, msgbuf, strerror(errno));
	}
	else {
		fprintf(s->_stderr, "%s exiting %s\n", ident_name_ptr, msgbuf);
	}

	if (s->forked) {
		fflush(NULL);
		_exit(1);
	}
	else {
		exit(1);
	}
}

void uexit(int status) {

	if (s->forked) {
		_exit(status);
	}

	exit(status);
}
