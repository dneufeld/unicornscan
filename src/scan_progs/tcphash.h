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
#ifndef _TCPHASH_H
# define _TCPHASH_H

#define TCPHASHTRACK(output, srcip, srcport, dstport, syncookie) \
	output=(syncookie) ^ ((srcip) ^ ( ( (srcport) << 16) + (dstport) ))

/*
 * compare unsigned sequence numbers with wrap correctly
 */

#ifdef SEQ_LEQ
# undef SEQ_LEQ
#endif
#define SEQ_LEQ(a, b)	((int32_t )((a) - (b)) <= 0)

#ifdef SEQ_GEQ
# undef SEQ_GEQ
#endif
#define SEQ_GEQ(a, b)	((int32_t )((a) - (b)) >= 0)

#define SEQ_WITHIN(x, low, high) (SEQ_GEQ(x, low) && SEQ_LEQ(x, high))

#endif
