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
#ifndef _PKTUTIL_H
# define _PKTUTIL_H

char *decode_6mac(const uint8_t * /* macptr */);
char *str_hwtype (uint16_t /* hw type */); /* return a pointer to a static string associated with the hw type */
char *str_opcode (uint16_t /* arp opcode */); /* same as above but for arp opcode */
char *str_hwproto(uint16_t /* arp proto  */); /* same as above but for proto */
char *str_ipproto(uint8_t  /* ip proto   */);
char *strtcpflgs(int /* tcp flags */);

#endif
