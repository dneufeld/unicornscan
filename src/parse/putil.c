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

#include <unilib/terminate.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <parse/putil.h>
#include <parse/parse.tab.h>

static size_t buffer_size=0;
static char *bbuf=NULL;

extern void uuerror(const char *);

#define PPBLOCK_SIZE 64

int uuescapestr(const char *in, buf_t *bout) {
	uint8_t *out=NULL;
	char bstr=0;
	int j=0, j1=0;
#define BIN bstr=1

	assert(in != NULL);
	if (*in == '"' && *(in + 1) != '\0') in++;

	/* we'll do better down there */
	out=(uint8_t *)xmalloc(strlen(in));
	memcpy(out, in, strlen(in));

	for (j=0, j1=0 ; j < (int)strlen(in) ; j++) {
		if (in[j] == '\\' && in[j + 1] != '\0') {
			const char *tmpptr=NULL;
			int oweight=0, result=0;

			++j;
			switch (in[j]) {
				case 'a':
					out[j1++]='\a'; BIN; break;
				case 'b':
					out[j1++]='\b'; BIN; break;
				case 'f':
					out[j1++]='\f'; BIN; break;
				case 'n':
					out[j1++]='\n'; BIN; break;
				case 'r':
					out[j1++]='\r'; BIN; break;
				case 't':
					out[j1++]='\t'; BIN; break;
				case 'v':
					out[j1++]='\v'; BIN; break;
				case '\'': /* " and ' are escaped to be the same thing */
				case '"':
					out[j1++]=in[j]; j++; break;
				case '\\':
					out[j1++]='\\'; break;
				case '0': case '1': case '2': case '3':
				case '4': case '5': case '6': case '7':
					BIN;
					/* start at index 0, go to max 3 spaces with all chars being 0 - 7 */
					for (tmpptr=&in[j], oweight=0;
					 *tmpptr != '\0' && (*tmpptr >= 0x30 && *tmpptr <= 0x37) && oweight < 65;
					tmpptr++) {
						if (oweight) {
							oweight=(oweight * 8);
						}
						else {
							oweight++;
						}
					}

					for (tmpptr=&in[j], result=0;
					*tmpptr != '\0' && (*tmpptr >= 0x30 && *tmpptr <= 0x37) && oweight > 0;
					tmpptr++, j++, oweight=(oweight / 8)) {
						int add=0; char bob[2];

						bob[0]=*tmpptr; bob[1]='\0';
						add=atoi(bob);
						result += (add * oweight);
					}
					/* truncate \777 to 0xFF like \377 */
					out[j1++]=(result & 0xFF); --j;
					/* im too lazy to refactor this so i dont need the -- so :P */
					break;
				case 'x':
					BIN;
					/* start at index 0, go to max 2 spaces with all chars being 0 - 7 */
					j++;
					tmpptr=&in[j];
					if (*tmpptr == '\0' || *(tmpptr + 1) == '\0') {
						terminate("Broken hex escape, its late, sorry");
					}
					if (1) {
						char str[3];
						int num=0;

						str[0]=*tmpptr; str[1]=*(tmpptr + 1); str[2]='\0'; j++;

						if (sscanf(str, "%x", &num) != 1) {
							terminate("Broken hex escape (from sscanf), sorry `%s'", str);
						}
						out[j1++]=(num & 0xFF);
					}
					break;
				default:
					ERR("unhandled escapechar `%c'", in[j]);
					break;
			}
		}
		else {
			if ((j + 1) != (int)strlen(in)) { /* no trailing " from string */
				out[j1++]=in[j];
			}
		}
	}

	if (bstr) {
		bout->len=0;
		bout->ptr=NULL;
		bout->len=j1;
		bout->ptr=(char *)xmalloc((size_t)j1);
		memset(bout->ptr, 0, (size_t)j1);
		memcpy(bout->ptr, out, (size_t)j1);
	}
	else {
		/* terminate with a \0 if non-binary */
		bout->len=j1;
		bout->ptr=(char *)xmalloc((size_t)(j1 + 1));
		memset(bout->ptr, 0, (size_t)(j1 + 1));
		memcpy(bout->ptr, out, (size_t)j1);
	}

	xfree(out);

	if (bstr) {
		return BSTR;
	}
	return STR;
}

void pbuffer_get(buf_t *in) {
	in->len=buffer_size;
	in->ptr=bbuf;
}

void pbuffer_append(buf_t *in) {
	assert(in != NULL);

	if (in->len == 0 || in->ptr == NULL) {
		 return;
	}

	if (bbuf == NULL) {
		bbuf=(char *)xmalloc(in->len);
		memcpy(bbuf, in->ptr, in->len);
		buffer_size=in->len;
	}
	else {
		char *newbuf=NULL;

		assert((buffer_size + in->len) > buffer_size);

		newbuf=(char *)xrealloc(bbuf, buffer_size + in->len);
		memcpy(newbuf + buffer_size, in->ptr, in->len);

		bbuf=newbuf;
		buffer_size=buffer_size + in->len;
	}

	return;
}

void pbuffer_reset(void) {
	buffer_size=0;
	if (bbuf) {
		xfree(bbuf);
	}
	bbuf=NULL;
	return;
}
