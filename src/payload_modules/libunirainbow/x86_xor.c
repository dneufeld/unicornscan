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
/*
 * Encode a buffer with shellcode to include a random loader, and the original shellcode in an xor ^ 8bit state
 * as to remove nulls or perhaps to remove certain banned characters in the shellcode.
 *
 * TODO:
 *	Compress shellcode and decode with loader
 *
 */
#include <config.h>
#include <settings.h>

#include <unilib/output.h>
#include <unilib/xmalloc.h>
#include <ctype.h>

#include "libunirainbow.h"

static int xor_rate(char /* chr */, const char * /* banned */);
static int randz=0;

#if 0

XXX LEN1 AND LEN2 are 16 bits (LEN1 ^ LEN2 = length of trailing shellcode)
XXX KEY is 8 bits

Dont touch %ecx, unless loop is replaced.
%e? is esi, edi, eax, ebx or edx.

_start:
	jmp	end			/* \xeb\x14			*/
fixptr:
	pop	%e?			/* ?				*/
	xor|sub	%ecx,	%ecx		/* (\x31|\x29)\xc9		*/
	mov	LEN1,	%cx		/* \x66\xb9(LEN1 16)		*/
	xor	LEN2,	%cx		/* \x66\x81\xf1(LEN2 16)	*/
dec_loop:
	xorb	KEY,	(%e?)		/* \x80?(KEY 8)			*/
	incl	%e?			/* ?				*/
	loop dec_loop			/* \xe2\xfa			*/
	jmp done			/* \xeb\x05			*/
end:
	call fixptr			/* \xe8\xe7\xff\xff\xff		*/
done:
	/* SHELLCODE ^ KEY */
#endif

#define POP_EAX		"\x58"
#define POP_EBX		"\x5b"
#define POP_EDX		"\x5a"
#define POP_EDI		"\x5f"
#define POP_ESI		"\x5e"

#define XOR_ECX_ECX	"\x31\xc9"
#define SUB_ECX_ECX	"\x29\xc9"

#define MOV_CX		"\x66\xb9"
#define XOR_CX		"\x66\x81\xf1"

#define XORB_EAX_P	"\x80\x30"
#define XORB_EBX_P	"\x80\x33"
#define XORB_EDX_P	"\x80\x32"
#define XORB_EDI_P	"\x80\x37"
#define XORB_ESI_P	"\x80\x36"

#define INC_EAX		"\x40"
#define INC_EBX		"\x43"
#define INC_EDX		"\x42"
#define INC_EDI		"\x47"
#define INC_ESI		"\x46"

#define JMP		"\xeb"
#define CALL		"\xe8"
#define LOOP		"\xe2"

#define UREG_NONE	  0
#define UREG_EAX	  1
#define UREG_EBX	  2
#define UREG_ECX	  4
#define UREG_EDX	  8
#define UREG_EDI	 16
#define UREG_ESI	 32
#define USTACK		 64
#define U_INVLD		128

static struct {
	const char *opcd;	/* string containing instruction(s)	*/
	int	regs;		/* registers clobbered after use	*/
} junk_ops[]={
{	"\x37",			UREG_EAX			},	/* aaa			*/
{	"\x3f",			UREG_EAX			},	/* aas			*/
{	"\x40",			UREG_EAX			},	/* incl %eax		*/
{	"\x43",			UREG_EBX			},	/* incl %ebx		*/
{	"\x41",			UREG_ECX			},	/* incl %ecx		*/
{	"\x42",			UREG_EDX			},	/* incl %edx		*/
{	"\x46",			UREG_ESI			},	/* incl %esi		*/
{	"\x47",			UREG_EDI			},	/* incl %edi		*/
{	"\x48",			UREG_EAX			},	/* decl %eax		*/
{	"\x4b",			UREG_EBX			},	/* decl %ebx		*/
{	"\x49",			UREG_ECX			},	/* decl %ecx		*/
{	"\x4a",			UREG_EDX			},	/* decl %edx		*/
{	"\x4e",			UREG_ESI			},	/* decl %esi		*/
{	"\x4f",			UREG_EDI			},	/* decl %edi		*/
{	"\x90",			UREG_NONE			},	/* nop(xchg eax, eax)	*/
{	"\x9f",			UREG_EAX			},	/* lahf			*/
{	"\x93",			UREG_EAX|UREG_EBX		},	/* xchg %eax, %ebx	*/
{	"\x91",			UREG_EAX|UREG_ECX		},	/* xchg %eax, %ecx	*/
{	"\x92",			UREG_EAX|UREG_EDX		},	/* xchg %eax, %edx	*/
{	"\x97",			UREG_EAX|UREG_EDI		},	/* xchg %eax, %edi	*/
{	"\x96",			UREG_EAX|UREG_ESI		},	/* xchg %eax, %esi	*/
{	"\x0f\xc8",		UREG_EAX			},	/* bswap  %eax		*/
{	"\x0f\xcb",		UREG_EBX			},	/* bswap  %ebx		*/
{	"\x0f\xc9",		UREG_ECX			},	/* bswap  %ecx		*/
{	"\x0f\xca",		UREG_EDX			},	/* bswap  %edx		*/
{	"\x0f\xcf",		UREG_EDI			},	/* bswap  %edi		*/
{	"\x0f\xce",		UREG_ESI			},	/* bswap  %esi		*/
{	"\x21\xc0",		UREG_EAX			},	/* and %eax, %eax	*/
{	"\x87\xc9",		UREG_ECX			},	/* xchg   %ecx,%ecx	*/
{	"\x87\xca",		UREG_ECX|UREG_EDX		},	/* xchg   %ecx,%edx	*/
{	"\x87\xcb",		UREG_ECX|UREG_EBX		},	/* xchg   %ecx,%ebx	*/
{	"\x87\xce",		UREG_ECX|UREG_ESI		},	/* xchg   %ecx,%esi	*/
{	"\x87\xcf",		UREG_ECX|UREG_EDI		},	/* xchg   %ecx,%edi	*/
{	"\x87\xd1",		UREG_EDX|UREG_ECX		},	/* xchg   %edx,%ecx	*/
{	"\x87\xd2",		UREG_EDX			},	/* xchg   %edx,%edx	*/
{	"\x87\xd3",		UREG_EDX|UREG_EBX		},	/* xchg   %edx,%ebx	*/
{	"\x87\xd6",		UREG_EDX|UREG_ESI		},	/* xchg   %edx,%esi	*/
{	"\x87\xd7",		UREG_EDX|UREG_EDI		},	/* xchg   %edx,%edi	*/
{	"\x87\xd9",		UREG_EBX|UREG_ECX		},	/* xchg   %ebx,%ecx	*/
{	"\x87\xda",		UREG_EBX|UREG_EDX		},	/* xchg   %ebx,%edx	*/
{	"\x87\xdb",		UREG_EBX			},	/* xchg   %ebx,%ebx	*/
{	"\x87\xde",		UREG_EBX|UREG_ESI		},	/* xchg   %ebx,%esi	*/
{	"\x87\xdf",		UREG_EBX|UREG_EDI		},	/* xchg   %ebx,%edi	*/
{	"\x87\xf1",		UREG_ESI|UREG_ECX		},	/* xchg   %esi,%ecx	*/
{	"\x87\xf2",		UREG_ESI|UREG_EDX		},	/* xchg   %esi,%edx	*/
{	"\x87\xf3",		UREG_ESI|UREG_EBX		},	/* xchg   %esi,%ebx	*/
{	"\x87\xf6",		UREG_ESI			},	/* xchg   %esi,%esi	*/
{	"\x87\xf7",		UREG_ESI|UREG_EDI		},	/* xchg   %esi,%edi	*/
{	"\x87\xf9",		UREG_EDI|UREG_ECX		},	/* xchg   %edi,%ecx	*/
{	"\x87\xfa",		UREG_EDI|UREG_EDX		},	/* xchg   %edi,%edx	*/
{	"\x87\xfb",		UREG_EDI|UREG_EBX		},	/* xchg   %edi,%ebx	*/
{	"\x87\xfe",		UREG_EDI|UREG_ESI		},	/* xchg   %edi,%esi	*/
{	"\x87\xff",		UREG_EDI			},	/* xchg   %edi,%edi	*/
{	"\x58",			UREG_EAX|USTACK			},	/* pop  %eax		*/
{	"\x5b",			UREG_EBX|USTACK			},	/* pop  %ebx		*/
{	"\x59",			UREG_ECX|USTACK			},	/* pop  %ecx		*/
{	"\x5a",			UREG_EDX|USTACK			},	/* pop  %edx		*/
{	"\x5f",			UREG_EDI|USTACK			},	/* pop  %edi		*/
{	"\x5e",			UREG_ESI|USTACK			},	/* pop  %esi		*/
{	"\x50",			UREG_EAX|USTACK			},	/* pushl  %eax		*/
{	"\x53",			UREG_EBX|USTACK			},	/* pushl  %ebx		*/
{	"\x51",			UREG_ECX|USTACK			},	/* pushl  %ecx		*/
{	"\x52",			UREG_EDX|USTACK			},	/* pushl  %edx		*/
{	"\x57",			UREG_EDI|USTACK			},	/* pushl  %edi		*/
{	"\x56",			UREG_ESI|USTACK			},	/* pushl  %esi		*/
{	"\x6a\x30",		USTACK				},	/* pushl $0x30		*/
{	"\x6a\x63",		USTACK				},	/* pushl $0x63		*/
{	"\x6a\x64",		USTACK				},	/* pushl $0x64		*/
{	"\x6a\x65",		USTACK				},	/* pushl $0x65		*/
{	"\x6a\x66",		USTACK				},	/* pushl $0x66		*/
{	"\x6a\x67",		USTACK				},	/* pushl $0x67		*/
{	"\x6a\x68",		USTACK				},	/* pushl $0x68		*/
{	"\x6a\x69",		USTACK				},	/* pushl $0x69		*/
{	"\xe9\x30\x30\x30\x80",	U_INVLD				},	/* jmp -0x7FCFCFD0	*/
{	"\xe9\x30\x30\x30\x30",	U_INVLD				},	/* jmp +0x30303030	*/
{	"\x30",			U_INVLD				},	/* flaming kitty!	*/
{	"\x31",			U_INVLD				},	/* flaming kitty!	*/
{	"\x32",			U_INVLD				},	/* flaming kitty!	*/
{	"\x33",			U_INVLD				},	/* flaming kitty!	*/
{	"\x34",			U_INVLD				},	/* flaming kitty!	*/
{	"\x35",			U_INVLD				},	/* flaming kitty!	*/
{	"\x68", 		U_INVLD				},	/* h			*/
{	"\x69",			U_INVLD				},	/* i			*/
{	"\x6a",			U_INVLD				},	/* j			*/
{	"\x6b",			U_INVLD				},	/* k			*/
{	"\x70",			U_INVLD				},	/* p			*/
{	"\x71",			U_INVLD				},	/* q			*/
{	"\x72",			U_INVLD				},	/* r			*/
{	"\x73",			U_INVLD				},	/* s			*/
{	"\x74",			U_INVLD				},	/* t			*/
{	"\x75",			U_INVLD				},	/* u			*/
{	"\x76",			U_INVLD				},	/* v			*/
{	"\x77",			U_INVLD				},	/* w			*/
};

#define JUNK_OP_SIZE	(sizeof(junk_ops) / sizeof(junk_ops[0]))

/* returns NULL on failure	*/
static const char *get_junkop(int regs_donttouch, const char *banned) {
	int j=0, spin_count=0;

	for (spin_count=0 ; spin_count < 200 ; spin_count++) {
		j=lr_rand_get((int)JUNK_OP_SIZE);

		if ((junk_ops[j].regs & regs_donttouch) == 0) {
			if (banned != NULL) {
				const char *walk=NULL;
				int acceptable=1;

				for (walk=junk_ops[j].opcd ; *walk != '\0' ; walk++) {
					if (strchr(banned, *walk) != NULL) {
						acceptable=0;
					}
				}

				if (acceptable) return junk_ops[j].opcd;
			}
			else {
				return junk_ops[j].opcd;
			}
		}
	}

	ERR("cant get junkop, is banned too restrictive?\n");
	return NULL;
}

static char *gen_loader(uint16_t len1, uint16_t len2, uint8_t key, const char *banned, int flags) {
	static char xor_loader[128];
	uint8_t tmp[5];			/* convert int32_t's uint16_t's and uint8_t's into strings	*/
	char *jump_end_p=NULL;	/* location of the first jump instruction parameter		*/
	char *land_end_p=NULL;	/* where the first jump lands					*/
	char *jump_fixptr_p=NULL;	/* location of the jump fixptr instruction parameter		*/
	char *land_fixptr_p=NULL;	/* location of the pop %e? instruction				*/
	char *loop_land_p=NULL;	/* where loop jmps to						*/
	char *loop_jump_p=NULL;	/* location of the loop instruction parameter			*/
	char *jump_done_p=NULL;
	char *land_done_p=NULL;
	unsigned int xor_off=0;
	int reg=0, state=0, junk_flags=-1;
	int8_t jumpc_off=0;
	int32_t jumpw_off=0;

	memset(xor_loader, 0, sizeof(xor_loader));

	/* pick our pointer register */
	switch (lr_rand_get(5)) {
		case 0:
			reg=UREG_EAX; break;
		case 1:
			reg=UREG_EBX; break;
		case 2:
			reg=UREG_EDX; break;
		case 3:
			reg=UREG_ESI; break;
		case 4:
			reg=UREG_EDI; break;
	}

/* we wont do bounds checking cause thats for pussies	*/
#define	BADD(str) xor_off += sprintf(xor_loader + xor_off, "%s", (str))

/* DITTO!						*/
#define INS_JUNK(regs) \
	if (flags & FLG_RAND && lr_rand_get(2) == 1) { \
		const char *ops=NULL; \
		\
		ops=get_junkop((regs), banned); \
		if (ops == NULL) return NULL; \
		xor_off += sprintf(xor_loader + xor_off, "%s", ops); \
	}

	junk_flags=-1; /* for clarity */

	for (state=0 ; state < 10 ; /* we inc inside for clarity */) {

		if (junk_flags != -1) {
			INS_JUNK(junk_flags);
			if (lr_rand_get(2) == 0) junk_flags=-1;
			continue;
		}

		switch (state) {
			case 0:
				BADD(JMP);				/* jmp ?		*/
				/* we dont know how far to jump yet */
				jump_end_p=&xor_loader[xor_off++];
				junk_flags=UREG_NONE;			/* we can add anything, well jump over it */
				state++;
				break;

			case 1:
				land_fixptr_p=&xor_loader[xor_off];
				switch (reg) {				/* popl %e?		*/
					case UREG_EAX:
						BADD(POP_EAX); break;
					case UREG_EBX:
						BADD(POP_EBX); break;
					case UREG_EDX:
						BADD(POP_EDX); break;
					case UREG_EDI:
						BADD(POP_EDI); break;
					case UREG_ESI:
						BADD(POP_ESI); break;
					default:
						ERR("bad register in state 1\n");
						/* XXX CLEANUP */
						return NULL;
				}
				junk_flags=reg|U_INVLD|USTACK;
				state++;
				break;

			case 2:
				if (flags & FLG_RAND) {
					switch (lr_rand_get(2)) {
						case 0:
							BADD(XOR_ECX_ECX); break;
						case 1:
							BADD(SUB_ECX_ECX); break;
					}
				}
				else {
					BADD(XOR_ECX_ECX);		/* xorl %ecx, %ecx	*/
				}
				junk_flags=reg|U_INVLD|UREG_ECX|USTACK;
				state++;
				break;

			case 3:
				BADD(MOV_CX);				/* mov	len1, %cx	*/
				tmp[2]='\0';
				memcpy(tmp, &len1, 2);
				BADD(tmp);
				junk_flags=reg|U_INVLD|UREG_ECX|USTACK;
				state++;
				break;

			case 4:
				BADD(XOR_CX);				/* xor  len2, %cx       */
				memcpy(tmp, &len2, 2);
				BADD(tmp);
				junk_flags=reg|U_INVLD|UREG_ECX|USTACK;
				state++;
				break;

			case 5:
				loop_land_p=&xor_loader[xor_off];
				switch (reg) {				/* xorb key, (%e?)	*/
					case UREG_EAX:
						BADD(XORB_EAX_P); break;
					case UREG_EBX:
						BADD(XORB_EBX_P); break;
					case UREG_EDX:
						BADD(XORB_EDX_P); break;
					case UREG_EDI:
						BADD(XORB_EDI_P); break;
					case UREG_ESI:
						BADD(XORB_ESI_P); break;
					default:
						ERR("bad register in state 5\n");
						/* XXX CLEANUP */
						return NULL;
				}
				tmp[1]='\0';
				memcpy(tmp, &key, 1);
				BADD(tmp);
				state++;
				junk_flags=reg|U_INVLD|UREG_ECX|USTACK;
				break;

			case 6:
				switch (reg) {				/* inc %e?		*/
					case UREG_EAX:
						BADD(INC_EAX); break;
					case UREG_EBX:
						BADD(INC_EBX); break;
					case UREG_EDX:
						BADD(INC_EDX); break;
					case UREG_EDI:
						BADD(INC_EDI); break;
					case UREG_ESI:
						BADD(INC_ESI); break;
					default:
						ERR("bad register in state 6\n");
						/* XXX CLEANUP */
						return NULL;
				}
				junk_flags=reg|U_INVLD|UREG_ECX|USTACK;
				state++;
				break;

			case 7:
				BADD(LOOP);				/* loop dec_loop	*/
				loop_jump_p=&xor_loader[xor_off];
				jumpc_off=(int8_t)(loop_land_p - loop_jump_p); jumpc_off--;
				memcpy(tmp, &jumpc_off, 1);
				BADD(tmp);
				junk_flags=reg|U_INVLD|UREG_ECX|USTACK;
				state++;
				break;

			case 8:
				BADD(JMP);				/* jmp done		*/
				jump_done_p=&xor_loader[xor_off++];
				junk_flags=UREG_NONE|USTACK;
				state++;
				break;

			case 9:
				land_end_p=&xor_loader[xor_off];	/* now can fix up jump_end_p */
				jumpc_off=(int8_t)(land_end_p - jump_end_p);
				*jump_end_p=jumpc_off - 1;

				BADD(CALL);				/* call fixptr		*/
				jump_fixptr_p=&xor_loader[xor_off + 4];
				jumpw_off=(int32_t)(land_fixptr_p - jump_fixptr_p);
				tmp[4]='\0';
				memcpy(tmp, &jumpw_off, 4);
				BADD(tmp);

				land_done_p=&xor_loader[xor_off];

				land_done_p=&xor_loader[xor_off];
				jumpc_off=(uint8_t)(land_done_p - jump_done_p);
				*jump_done_p=jumpc_off - 1;
				junk_flags=-1; /* for clarity */
				state++;
				break;

			case 10:
				ERR("bad state?\n");
				/* XXX CLEANUP */
				return NULL;
		} /* Switch State */
	} /* for 0-9 */

	return xor_loader;
}

char *x86_xor_encode(const char *shellcode, size_t shellcode_len, const char *banned, int flags, size_t *ls) {
	int xk[256], j=0, maxscore=0, winner=0, verbose=0, lscore=0, lwinner=0, ti=0;
	char *outz=NULL, *walk=NULL, *loader=NULL, *loader_winner=NULL;
	const char *chr=NULL;
	size_t j1=0, max_loaderlen=0;
	union {
		uint16_t lkeys[2];
		uint8_t lchrs[4];
	} lk_u, wkeys_u;
	uint16_t sc_len=0, try_len_key=0;

	assert(shellcode_len < 0xFFFF && shellcode != NULL);

	if (flags & FLG_VERB) verbose=1;
	if (flags & FLG_RAND) randz=1;
	if (flags & FLG_RANDP) randz=2;

	sc_len=(uint16_t)shellcode_len;

	try_len_key=0x0000;

	if (ls != NULL && *ls != 0) {
		max_loaderlen=*ls;
	}

	/*
	 * Encode the two 16bit length xor pairs, scoring all possible
	 * combinations and picking a winner
	 */
	lwinner=0;
	while (1) {
		lk_u.lkeys[0]=try_len_key;
		lk_u.lkeys[1]=try_len_key ^ sc_len;

		lscore=0;
		for (j=0 ; j < 4 ; j++) {
			ti=xor_rate(lk_u.lchrs[j], banned);
			if (ti == -1) {
				lscore=-1; break;
			}
			else {
				lscore += ti;
			}
		}
		if (lscore > lwinner) {
			lwinner=lscore;
			wkeys_u.lkeys[0]=lk_u.lkeys[0];
			wkeys_u.lkeys[1]=lk_u.lkeys[1];

		}
		if (try_len_key > 0xFFFE) {
			break;
		}
		try_len_key += 0x0001;
	}

	if (lwinner < 1) {
		ERR("error cant find suitable length keypair for xor encoder score is %d\n", lwinner);
		return NULL;
	}

	if (verbose) {
		printf("Best length xor pair is 0x%04x, 0x%04x with score of %d\n",
		wkeys_u.lkeys[0], wkeys_u.lkeys[1], lwinner);
	}

	for (j=0 ; j < 256 ; j++) {
		xk[j]=0;
	}

	for (j=1 ; j < 256 ; j++) {
		for (chr=shellcode, j1=0 ; j1 < shellcode_len ; j1++, chr++) {
			ti=xor_rate((*chr) ^ (uint8_t)j, banned);
			if (ti == -1) {
				xk[j]=-1; break;
			}
			else {
				xk[j] += ti;
			}
		}

		if (xk[j] > maxscore) {
			maxscore=xk[j];
			winner=j;
		}
	}

	if (winner < 1) {
		ERR("failed to find a suitable xor key for shellcode, perhaps banned is too restrictive?\n");
		return NULL;
	}

	VRB(0, "Winner Score %d for shellcode xor key 0x%02x", maxscore, (uint8_t)winner);

	lwinner=0;
	for (j=0 ; j < 16 ; j++) {
		loader=gen_loader(wkeys_u.lkeys[0], wkeys_u.lkeys[1], (uint8_t)winner, banned, flags);
		if (loader == NULL) {
			continue;
		}
		lscore=0;
		for (j1=0 ; j1 < strlen(loader) ; j1++) {
			int ret=0;

			ret=xor_rate(loader[j1], banned);
			if (ret == -1) {
				lscore=-1;
				break;
			}
			else {
				lscore += ret;
			}
		}

		if (max_loaderlen != 0 && strlen(loader) > max_loaderlen) {
			lscore=-1;
		}

		if (lscore > lwinner) {
			if (loader_winner != NULL) xfree(loader_winner);
			loader_winner=xstrdup(loader);
			assert(loader_winner != NULL);
			lwinner=lscore;
		}
	}

	VRB(0, "XOR loader winner with score %d\n", lscore);

	if (loader_winner == NULL) {
		ERR("Cant generate loader");
		return NULL;
	}

	loader=loader_winner;

	if (ls != NULL) {
		*ls=strlen(loader);
	}

	outz=(char *)xmalloc(strlen(loader) + shellcode_len + 1);
	walk=outz;

	memcpy(walk, loader, strlen(loader));
	walk += strlen(loader);

	for (j1=0, chr=shellcode ; j1 < shellcode_len ; j1++, chr++) {
		*walk=(*chr) ^ (uint8_t)winner; walk++;
	}
	*walk='\0';

	xfree(loader_winner);

	return outz;
}

static int xor_rate(char chr, const char *banned) {
	int ret=0;

	if (chr == 0 || (banned != NULL && strchr(banned, chr) != NULL)) {
		return -1;
	}
	else if (isalnum(chr)) {
		ret=3;
	}
	else if (isgraph(chr)) {
		ret=2;
	}
	else if (isascii(chr)) {
		ret=1;
	}
	else {
		ret=0;
	}

	if (randz) {
		switch (randz) {
			case 1:
				ret += lr_rand_get(1); break;
			case 2:
				ret += lr_rand_get(4); break;
				break;
			default:
				ERR("Internal Error in xor rate, rejecting data\n");
				return -1;
		}
	}

	return ret;
}
