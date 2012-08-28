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

#include <parse/putil.h>

#include <scan_progs/scan_export.h>
#include <settings.h>
#include <scan_progs/options.h>
#include <unilib/output.h>
#include <unilib/xmalloc.h>

#define MAIN (ident == IDENT_MASTER || ident == IDENT_ANY)
#define SEND (ident == IDENT_SEND || ident == IDENT_ANY)

extern int uuwarn(const char *);
extern void uuerror(const char *);
static char *eptr=NULL;

%}

%union {
	int inum;
	unsigned int uinum;
	char *ptr;
	buf_t buf;
}

%token NUMBER UNUMBER STR BSTR WORD
%token PAYLOADS GLOBAL MODULE BOOL

%token <inum> NUMBER
%token <uinum> UNUMBER BOOL
%token <ptr> STR WORD
%token <buf> BSTR

%start cfgfile

%{


%}

%%
cfgfile:
	| section cfgfile
	;

section:
	GLOBAL '{' glines '}' ';'
	| PAYLOADS '{' plines '}' ';'
	| MODULE STR '{' mlines '}' ';' {
		scan_collectkeyval((const char *)$2);
	}
	;

glines:
	| g_statement glines
	;

plines: 
	| p_statement plines
	;

mlines: 
	| m_statement mlines
	;

g_statement:
	WORD ':' STR ';' {
		if (MAIN && (eptr=scan_optmap((const char *)$1, (const char *)$3)) != NULL) {
			uuerror(eptr);
		}
	}
	| WORD ':' NUMBER ';' {
		if (MAIN && (eptr=scan_optmapi((const char *)$1, $3)) != NULL) {
			uuerror(eptr);
		}
	}
	| WORD ':' UNUMBER ';' {
		if ($3 > INT_MAX) {
			uuerror("number out of range");
		}
		if (MAIN && (eptr=scan_optmapi((const char *)$1, (int)$3)) != NULL) {
			uuerror(eptr);
		}
	}
	| WORD ':' BOOL ';' {
		if (MAIN && (eptr=scan_optmapi((const char *)$1, (int)$3)) != NULL) {
			uuerror(eptr);
		}
	}
	| WORD ':' WORD ';' {
		if (MAIN && (eptr=scan_optmap((const char *)$1, (const char *)$3)) != NULL) {
			uuerror(eptr);
		}
	}
	| WORD '{' pdata '}' ';' {
		buf_t data;
		char *string=NULL;

		pbuffer_get(&data);

		string=(char *)xmalloc(data.len + 1);
		memcpy(string, data.ptr, data.len);
		string[data.len]='\0';

		if ((eptr=scan_optmap((const char *)$1, (const char *)string)) != NULL) {
			uuerror(eptr);
		}

		pbuffer_reset();
	}
	;

p_statement:
	/*ip  dst   src    plg */
	WORD NUMBER NUMBER NUMBER '{' pdata '}' ';' {
		uint8_t proto=0;
		uint16_t dstport=0;
		buf_t data;
		uint16_t plg=0;

		if (strcasecmp($1, "tcp") == 0) {
			proto=IPPROTO_TCP;
		}
		else if (strcasecmp($1, "udp") == 0) {
			proto=IPPROTO_UDP;
		}
		else {
			uuerror("unsupported ip protocol `%s'");
		}

		if ($4 > 0xFFFF || $4 < 0) {
			uuerror("payload group out of range");
		}
		else {
			plg=(uint16_t)$4;
		}

		pbuffer_get(&data);

		if ($2 > 0xFFFF || $2 < 0) {
			if ($2 == -1) {
				if (SEND && proto == IPPROTO_UDP) {
					add_default_payload(IPPROTO_UDP, $3, (const uint8_t *)data.ptr, (uint32_t)data.len, NULL, plg);
				}
				else if (MAIN && proto == IPPROTO_TCP) {
					add_default_payload(IPPROTO_TCP, $3, (const uint8_t *)data.ptr, (uint32_t)data.len, NULL, plg);
				}
				else if ((SEND && proto == IPPROTO_TCP) || (MAIN && proto == IPPROTO_UDP)) {
				}
				else {
					PANIC("im confused in %s with proto %u from configuration", ((MAIN) ? "Main" : "Send"), proto);
				}
			}
			else {
				uuerror("payload dest port out of range");
			}
		}
		else {
			dstport=(uint16_t)$2;
		}

		if (SEND && proto == IPPROTO_UDP) {
			add_payload(IPPROTO_UDP, dstport, $3, (const uint8_t *)data.ptr, (uint32_t)data.len, NULL, plg);
		}
		else if (MAIN && proto == IPPROTO_TCP) {
			add_payload(IPPROTO_TCP, dstport, $3, (const uint8_t *)data.ptr, (uint32_t)data.len, NULL, plg);
		}
		else if ((SEND && proto == IPPROTO_TCP) || (MAIN && proto == IPPROTO_UDP)) {
		}
		else {
			PANIC("im confused in %s with proto %u from configuration", ((MAIN) ? "Main" : "Send"), proto);
		}

		pbuffer_reset();
	}
	;

m_statement:
	WORD ':' WORD ';' {
		scan_modaddkeyval((const char *)$1, (const char *)$3);
	}
	| WORD ':' NUMBER ';' {
		char numbuf[16];

		snprintf(numbuf, sizeof(numbuf) -1, "%d", $3);
		scan_modaddkeyval((const char *)$1, (const char *)numbuf);
	}
	| WORD ':' BOOL ';' {
		char numbuf[16];

		snprintf(numbuf, sizeof(numbuf) -1, "%d", $3);
		scan_modaddkeyval((const char *)$1, (const char *)numbuf);
	}
	| WORD ':' STR ';' {
		scan_modaddkeyval((const char *)$1, (const char *)$3);
	}
	| multi_line_str ';' {
		char mtls[4096];
		buf_t data;

		pbuffer_get(&data);

		if (data.len > 4095) {
			uuerror("multi-line string too long");
		}
		else if (data.len > 0) {
			memcpy(mtls, data.ptr, data.len);
			mtls[data.len]='\0';

			scan_modaddkeyval("DATA", (const char *)mtls);
		}

		pbuffer_reset();
	}
	;

multi_line_str:
	line_str
	| line_str multi_line_str
	;

line_str:
	STR {
		buf_t data;

		if ($1 && strlen($1)) {
			data.len=strlen($1);
			data.ptr=(char *)$1;

			pbuffer_append(&data);
		}
	}
	;

pdata:
	BSTR {
		if (SEND || MAIN) pbuffer_append(&$1);
	}
	| pdata BSTR {
		if (SEND || MAIN) pbuffer_append(&$2);
	}
	| STR {
		if (SEND || MAIN) {
			buf_t data;

			data.len=strlen($1);
			data.ptr=(char *)$1;
			pbuffer_append(&data);
		}
	}
	| pdata STR {
		if (SEND || MAIN) {
			buf_t data;

			data.len=strlen($2);
			data.ptr=(char *)$2;
			pbuffer_append(&data);
		}
	}
	;
