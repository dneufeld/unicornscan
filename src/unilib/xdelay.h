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
#ifndef _XDELAY_H
# define _XDELAY_H

#define XDELAY_TSC	1
#define XDELAY_GTOD	2
#define XDELAY_SLEEP	3

#define XDELAY_DEFAULT	XDELAY_TSC

void init_tslot(uint32_t /* packets per second we want to have */, uint8_t /* delay type */);
void start_tslot(void);
void end_tslot(void);
char *delay_getopts(void);
int delay_gettype(const char *);
char *delay_getname(int );
int delay_getdef(uint32_t /* pps */);

#endif
