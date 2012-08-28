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

#include <settings.h>
#include <unilib/output.h>

void _display(int type, const char *file, int lineno, const char *fmt, ...) {
	va_list ap;
	FILE *output=NULL;

	output=s->_stdout;

	switch (type) {
		case M_INFO:
		case M_OUT:
		case M_VERB:
			break;

		case M_ERR:
			output=s->_stderr;
			fprintf(output, "%s [Error   %s:%d] ", ident_name_ptr, file, lineno);
			break;

		case M_DBG:
			output=s->_stderr;
			fprintf(output, "%s [Debug   %s:%d] ", ident_name_ptr, file, lineno);
			break;

		default:
			output=s->_stderr;
			fprintf(output, "%s [Unknown %s:%d] ", ident_name_ptr, file, lineno);
	}

	va_start(ap, fmt);
	vfprintf(output, fmt, ap);

	fprintf(output, "\n"); 

#ifdef DEBUG_SUPPORT
	fflush(output);
#endif

	return;
}

void hexdump(const uint8_t *in, size_t len) {
	const uint8_t *ptr=NULL;
	size_t psize=0, hsize=0;
	char hbuf[128];

	INF("## Buffer size is " STFMT " ######################", len);

	for (ptr=in, psize=0; psize < len; psize++, ptr++) {
		if (psize != 0 && ((psize % 16) == 0)) {
			INF("%-40s", hbuf);
			memset(hbuf, 0, sizeof(hbuf)); hsize=0;
		}
		sprintf(&hbuf[hsize], "\\x%02x", (uint8_t)*ptr);
		hsize += 4;
	}

	if (strlen(hbuf)) {
		INF("%-40s\n###########################################", hbuf);
	}
	else {
		INF("###########################################");
	}

	return;
}
