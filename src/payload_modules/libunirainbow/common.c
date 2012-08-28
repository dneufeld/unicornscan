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
#include <config.h>
#include <settings.h>

#include <unilib/output.h>
#include <unilib/prng.h>

#include <ctype.h>

#include "libunirainbow.h"

int lr_rand_get(int max) {
	return prng_get32() % max;
}

char *encode(const char *shellcode, size_t shellcode_len, const char *banned, int type, int flags, int platform, size_t *ls) {
	switch (type) {
		case ENC_XOR:
			switch (platform) {
				case PLT_LINXX86:
				case PLT_NBSDX86:
				case PLT_OBSDX86:
				case PLT_FBSDX86:
					return x86_xor_encode(shellcode, shellcode_len, banned, flags, ls);
				default:
					ERR("unsupported XOR encoder platform %d\n", platform);
					return NULL;
			}
			break;
		case ENC_ALP:
			switch (platform) {
				case PLT_LINXX86:
				case PLT_NBSDX86:
				case PLT_OBSDX86:
				case PLT_FBSDX86:
					return x86_alpha_encode(shellcode, shellcode_len, banned, flags, ls);
				default:
					ERR("unsupported ALPHA encoder platform %d\n", platform);
					return NULL;
	
			}
		default:
			ERR("unknown encoding type %d", type);
			return NULL;
	}
}

int rand_nops(char *buf, size_t len, const char *banned, int platform) {
	switch (platform) {
		case PLT_LINXX86:
		case PLT_OBSDX86:
		case PLT_NBSDX86:
		case PLT_FBSDX86:
			return x86_rand_nops(buf, len, banned);
		default:
			ERR("unknown platform for rand_nops %d\n", platform);
			break;
	}
	return -1;
}

int jump_sled(char *buf, size_t len, const char *banned, int platform) {
	switch (platform) {
		case PLT_LINXX86:
		case PLT_OBSDX86:
		case PLT_NBSDX86:
		case PLT_FBSDX86:
			return x86_jump_sled(buf, len, banned);
		default:
			ERR("unknown platform for jump_sled %d\n", platform);
			break;
	}

	return -1;
}
