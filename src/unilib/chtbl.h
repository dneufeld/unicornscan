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
#ifndef _CHTBL_H
# define _CHTBL_H

#define CHEXIT_KEYCOLLIDE -2
#define CHEXIT_FAILURE -1
#define CHEXIT_SUCCESS 1

void     *chtinit(uint32_t /* expected size */);

int      chtinsert (void * /* th */, uint64_t /* key */, void *  /* data */    );
int      chtdelete (void * /* th */, uint64_t /* key */                        );
int      chtfind   (void * /* th */, uint64_t /* key */, void ** /* data_ptr */);
void     chtstats  (void * /* th */);
void     chtwalk   (void * /* rh */, void (* /* walk func */)(uint64_t /* key */, void * /* data ptr */), int /* wt 0-2*/);
uint32_t chtgetsize(void * /* th */);
void     chtdestroy(void * /* rh */);
uint32_t chtsize   (void * /* rh */);

#endif
