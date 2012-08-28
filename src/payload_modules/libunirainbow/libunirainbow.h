/**********************************************************************
 * Copyright (C) 2005-2006 (Jack Louis) <jack@rapturesecurity.org>    *
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
#ifndef _LIBRAINBOW_H
# define _LIBRAINBOW_H

int lr_rand_get(int /* max value */);

/* lame, but think instructional clarity */
#define COLOR_NONE	0
#define COLOR_GREEN	1
#define COLOR_GREEN_S	"[01;32m"
#define COLOR_RED	2
#define COLOR_RED_S	"[40;31;01m"
#define COLOR_YELLOW	3
#define COLOR_YELLOW_S	"[40;33;01m"
#define COLOR_BLUE	5
#define COLOR_BLUE_S	"[01;34m"
#define COLOR_LTBLUE	6
#define COLOR_LTBLUE_S	"[01;36m"
#define	COLOR_RESET_S	"[00m"
/* ... */
#define ALWAYS_HEX	64

#define XOR_BANNED_CHARS	"\v\n\r?&"	/* some silly default */

char *x86_xor_encode(const char * /* shellcode */,
	size_t /* shellcode_len */,
	const char * /* banned chars != \0 */,
	int /* flags */,
	size_t * /* max size of loader or 0, returns length */);

char *x86_alpha_encode(const char * /* shellcode */,
	size_t /* shellcode_len */,
	const char * /* banned chars != \0 */,
	int /* flags */,
	size_t * /* max size of loader or 0, returns length */);

int	x86_rand_nops(char * /* buffer */,
	size_t /* how many nops */,
	const char * /* banned */);

int	x86_jump_sled(char * /* buffer */,
	size_t /* buffer_size */,
	const char * /* banned */);

char	*fstwrtr_32(uint32_t /* write location */,
	uint32_t /* value to write */,
	int /* DPA offset */,
	int /* flags */);

/* fairly straight forward */
#define ENC_ALP	2
#define ENC_XOR	1

/* i dont remeber what the P means, but its basicly more random than random? heh */
#define FLG_VERB	1
#define FLG_RAND	2
#define FLG_RANDP	3

/* ok, so whats up with the distinction you may be wondering ...	*
 * well its mostly for cpus with seperate i|d caches that we're		*
 * going to have to use syscalls to flush things, and untill thats	*
 * in here, its just going to seem stupid ;]				*/
#define PLT_LINXX86	1
#define PLT_FBSDX86	2
#define PLT_NBSDX86	3
#define PLT_OBSDX86	4

char *encode(const char * /* shellcode */,
	size_t /* shellcode_len */,
	const char * /* banned */,
	int /* type */,
	int /* flags */,
	int /* platform */,
	size_t * /* max size of loader or 0, returns length */);

int	rand_nops(char * /* buf */,
	size_t /* buf len */,
	const char * /* banned */,
	int /* platform */);

int	jump_sled(char * /* buf */,
	size_t /* buf len */,
	const char * /* banned */,
	int /* platform */);

#endif	/* _LIBRAINBOW_H */
