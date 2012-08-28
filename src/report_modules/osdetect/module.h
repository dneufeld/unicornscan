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
#ifndef _OSD_MODULE_H
# define _OSD_MODULE_H

#define MAX_TCPOPTS     16

const extern settings_t *s;

typedef struct tcpopt_t {
	char	desc[64];
	int	type;
	union {
		uint8_t wscale;
		uint16_t maxseg;
		struct {
			uint32_t them;
			uint32_t us;
		} tstamp_s;
	} tcpopt_u;
} tcpopt_t;

typedef struct fps_t {
	uint16_t		stim_fp;	/* this signature was in response to THIS	*
						 * syn fingerprint				*/

	uint8_t			flag_fin:1;	/* is this a syn-ack, etc?			*/
	uint8_t			flag_syn:1;	/* is this a syn-ack, etc?			*/
	uint8_t			flag_rst:1;	/* is this a syn-ack, etc?			*/
	uint8_t			flag_psh:1;	/* is this a syn-ack, etc?			*/
	uint8_t			flag_ack:1;	/* is this a syn-ack, etc?			*/
	uint8_t			flag_urg:1;	/* is this a syn-ack, etc?			*/
	uint8_t			flag_ece:1;	/* is this a syn-ack, etc?			*/
	uint8_t			flag_cwr:1;	/* is this a syn-ack, etc?			*/

#if 0
	uint8_t			window_flags;	/* if this is based upon MTU for example, or	*
						 * something else				*/
#define OSD_WINDOW_ABS		0		/* the window size is literal			*/
#define OSD_WINDOW_MSSMULT	1		/* in p0f this is S??				*/
#define OSD_WINDOW_MTU40MULT	2		/* in p0f this is T??				*/

	uint8_t			window_mult;	/* this is used when its based upon mtu somehow	*/
#endif
	uint16_t		urg_ptr;

	uint8_t			ttl;		/* initial ttl					*/
	uint8_t			df;		/* ip Dont fragment				*/
	uint16_t		ws;		/* window size					*/
	uint8_t			tos;		/* type of service from ip header		*/

	int			misc_flags;
#define OSD_TIMESTAMP_LOW_LITTLEENDIAN	 1
#define OSD_TIMESTAMP_LOW_BIGENDIAN	 2       /* clearly these should not all be set ;] */
#define OSD_TIMESTAMP_ZERO		 4
#define OSD_URGPTR_LEAK			 8
#define OSD_RESFLAGS_LEAK		16
#define OSD_ECE_ON			32
#define OSD_CWR_ON			64


	char			*ostype;	/*	*/
	char			*osdesc;	/*	*/

	tcpopt_t tcpopts[MAX_TCPOPTS];
	struct fps_t *next;
} fps_t;

typedef struct osd_t {
	uint16_t	stim_fp;
	uint16_t	mtu;
	int		dump_unknown;
	fps_t		**fps;
} osd_t;

extern osd_t osd;

#endif 
