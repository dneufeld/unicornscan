%{
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

#include <errno.h>

#include <unilib/terminate.h>
#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <scan_progs/scan_export.h>
#include <settings.h>

#include <parse/putil.h>

#include "parse.tab.h"

#define INCLUDE_DEPTH 16

static char tmpbuf[2048], *tmpptr=NULL;
char section[1024];

struct incf_s {
	char filename[PATH_MAX];
	int lineno;
	FILE *fp;
};

int incs_index=0;
struct incf_s incs[INCLUDE_DEPTH];
void switchfiles(const char *);
void uuerror(const char *);

%}

%x scomment cppcomment

%option yylineno
%option never-interactive

%%
[ \t\f\r\n]*			/* ignore whitespace */
\/\*				{ BEGIN(scomment); }
<scomment>{
.				/* ignore */
\n				/* ignore */
}
<scomment>\*\/			{ BEGIN(INITIAL); }
\/\/				{ BEGIN(cppcomment); }
<cppcomment>{
.				/* ignore */
}
<cppcomment>\n			{ BEGIN(INITIAL); }
(:wq|:wq!|:q|:q!)		/* :wq! requested by pipes */
0x[0-9A-Fa-f][0-9A-Fa-f]*	{ if (sscanf(uutext, "%x", &uulval.uinum) != 1) {
					uuerror("Malformed hex number");
				} return UNUMBER; }
\\[0-7][0-7]?[0-7]?		{ uutext++; if (sscanf(uutext, "%o", &uulval.uinum) != 1) {
					uuerror("malformed octal number");
				} return UNUMBER; }
-?[0-9][0-9]*			{ if (sscanf(uutext, "%d", &uulval.inum) != 1) {
					uuerror("malformed number");
				} return NUMBER; }
\"[^\"]*\"			{ uulval.buf.ptr=NULL; uulval.buf.len=0; return uuescapestr(uutext, &(uulval.buf)); }
\'[^\']*\'			{ uutext++; uutext[strlen(uutext) - 1]='\0'; uulval.ptr=xstrdup(uutext); return STR; }
([tT]rue|[yY]es)		{ uulval.uinum=1; return BOOL; }
([fF]alse|[nN]o)		{ uulval.uinum=0; return BOOL; }
[gG]lobal			return GLOBAL;
[mM]odule			return MODULE;
[pP]ayloads			return PAYLOADS;
[{}\,;:]			return *uutext;
[a-zA-Z0-9\./]+			{ uulval.ptr=xstrdup(uutext); return WORD; }
include[ \t]+\"[^\"]*\";	{
					if (sscanf(uutext, "include %512s", tmpbuf) != 1) {
						uuerror("include statement malformed");
					}
					if (tmpbuf[0] == '"' && tmpbuf[1] != '\0') {
						tmpptr=&tmpbuf[1];
					}
					if (tmpptr[strlen(tmpptr) -2] == '"') {
						tmpptr[strlen(tmpptr) -2]='\0';
					}
					switchfiles((const char *)tmpptr);
				}
.				{
					uuerror("unknown character in config file");
				}

%%

void switchfiles(const char *newfile) {

	VRB(2, "opening config file `%s'", newfile);

	if (incs_index > (INCLUDE_DEPTH - 2)) {
		ERR("includes too complex %d max", INCLUDE_DEPTH);
		return;
	}
	if (access(newfile, R_OK) != 0) {
		ERR("include file `%s' is not readable", newfile);
		return;
	}
	incs[incs_index].lineno=uulineno;
	incs[incs_index].fp=uuin;

	incs_index++;

	uulineno=0;
	incs[incs_index].lineno=0;

	snprintf(incs[incs_index].filename, sizeof(incs[incs_index].filename) -1, "%s", newfile);
	incs[incs_index].fp=fopen(incs[incs_index].filename, "r");
	if (incs[incs_index].fp == NULL) {
		terminate("cant open file, access said i could?");
	}

	uuin=incs[incs_index].fp;

	return;
}

int uuwrap(void) {
	if (incs_index) {
		assert(incs[incs_index].fp != NULL);
		fclose(incs[incs_index].fp);
		incs_index--;
		uuin=incs[incs_index].fp;
		uulineno=incs[incs_index].lineno;
		return 0;
	}
	else {
		return 1;
	}
}

/* lib entry point */
int readconf(const char *in) {

	if (in == NULL) {
		ERR("no file to open");
		return -1;
	}

	uuin=fopen(in, "r");

	if (uuin == NULL) {
		ERR("error opening file `%s': %s", in, strerror(errno));
		return -1;
	}

	incs_index=0;
	snprintf(incs[incs_index].filename, sizeof(incs[incs_index].filename) -1, "%s", in);
	incs[incs_index].fp=uuin;
	incs[incs_index].lineno=0;
	uuparse();

	if (uuin) {
		fclose(uuin);
	}

	return 1;
}

void uuerror(const char *instr) {
	extern int uulineno;

	terminate("config file error: `%s' at token `%s' in file `%s' line %d",
		instr, uutext, incs[incs_index].filename, uulineno
	);
}

void uuwarn(const char *instr) {
	extern int uulineno;

	ERR("config file warning: `%s' at token `%s' in file `%s' line %d",
		instr, uutext, incs[incs_index].filename, uulineno
	);
}
