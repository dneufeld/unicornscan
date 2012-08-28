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
#ifndef _OPTIONS_H
# define _OPTIONS_H

int scan_setdefaults(void);

int scan_setdronestring(const char *);
int scan_settcpquick(const char *);
int scan_setudpquick(const char *);
int scan_setopenclosed(const char * /* open */, const char * /* closed */);
int scan_setformat(const char *);
int scan_setenablemodule(const char *);
int scan_setgports(const char *);
int scan_setidlehosts(const char *);
int scan_setignoreseq(const char *);
int scan_setinterface(const char *);
int scan_setmoddir(const char *);
int scan_setpcapfilter(const char *);
int scan_setpps(const char *);
int scan_setprofile(const char *);
int scan_setreadfile(const char *);
int scan_setsavefile(const char *);
int scan_setdebug(const char *);

int scan_setcovertness(int);
int scan_setdefpayload(int);
int scan_setdelaytype(int);
int scan_setdodns(int);
int scan_setidlescan(int);
int scan_setignroot(int);
int scan_setimmediate(int);
int scan_setlistendrone(int);
int scan_setppsi(int);
int scan_setprocdups(int);
int scan_setprocerrors(int);
int scan_setrepeats(int);
int scan_setreportquiet(int);
int scan_setsenddrone(int);
int scan_setshuffle(int);
int scan_setsniff(int);
int scan_settryfrags(int);
int scan_setverbose(int);
int scan_settrans(int);
int scan_setpayload_grp(int);

int scan_setverboseinc(void); /* kludge for getconfig.c */

char *scan_getgports(void);
char *scan_getdesthosts(void);

/* create or append to a list of key value pairs used for module settings */
void scan_modaddkeyval(const char *, const char *);
/* collect the key value pairs in the list so far, and add them into the module param list in s */
void scan_collectkeyval(const char *);

char *scan_optmap(const char *, const char *);
char *scan_optmapi(const char *, int);

#endif
