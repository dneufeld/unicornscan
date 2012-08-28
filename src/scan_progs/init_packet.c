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
#include <config.h>

#include <scan_progs/scanopts.h>
#include <scan_progs/scan_export.h>
#include <settings.h>

#include <unilib/prng.h>
#include <unilib/output.h>

#include <scan_progs/packets.h>

/*
 * XXX finger prints are moving into the config file too
 */

static uint16_t mtu=0;

void get_postoptions(uint32_t refl_ts, uint32_t my_tstamp) {
	uint32_t p_tstamp=0, t_tstamp=0;

	p_tstamp=htonl(my_tstamp);
	t_tstamp=htonl(refl_ts);

	s->ss->posttcpoptions_len=0;
	memset(s->ss->posttcpoptions, 0, sizeof(s->ss->posttcpoptions));

	switch (s->ss->fingerprint) {
		case 0: /* cisco ios */
		case 2: /* windows 3.1 */
		case 3: /* p0f sendsyn */
			break;

		case 6: /* linux */
		case 1: /* OpenBSD */
		case 7: /* no comment */
		case 4: /* FreeBSD 5.1 */
			if (refl_ts != 0 && my_tstamp != 0) {
				/* this is impossible to get ;] */
				/* <nop,nop,timestamp XXXX201 XXXX256> */
				s->ss->posttcpoptions_len=12;

				/* N N ( size 2 ) */
				s->ss->posttcpoptions[0]=0x01; s->ss->posttcpoptions[1]=0x01;

				/* T ( size 10 ) */
				s->ss->posttcpoptions[2]=0x08; s->ss->posttcpoptions[3]=0x0a;
				memcpy(s->ss->posttcpoptions + 4, &p_tstamp, sizeof(p_tstamp));
				memcpy(s->ss->posttcpoptions + 8, &t_tstamp, sizeof(t_tstamp));
				break;
			}
			else {
				s->ss->posttcpoptions_len=0;
			}
			break;

		default:
			break;
	}

	return;
}

void init_packet(void) {
	uint32_t l_tstamp=0, r_tstamp=0;

	l_tstamp=prng_get32();
	r_tstamp=0;

	switch (s->ss->fingerprint) {
		case 0:
			/* Cisco IOS 12.1 on a 2600 router type device, from tcpdump */
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				scan_setttl("255");
			}
			s->ss->ip_off=0;

			if (s->ss->mode == MODE_TCPSCAN) {
				s->ss->window_size=4128;
				s->ss->tcpoptions_len=4;
				s->ss->tcpoptions[0]=0x02;
				s->ss->tcpoptions[1]=0x04;
				mtu=htons(s->vi[0]->mtu - 40);
				memcpy(s->ss->tcpoptions + 2, &mtu, sizeof(mtu));
			}
			break;

		case 1:
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				scan_setttl("64");
			}
			if (s->ss->ip_off == 0) {
				s->ss->ip_off=IP_DF;
			}

			/*
			 * openbsd 3.0-3.4 from the p0f fp file
			 */
			if (s->ss->mode == MODE_TCPSCAN) {
				s->ss->window_size=16384;
				s->ss->tcpoptions_len=24;
				/* M*  ( size 4 ) */
				s->ss->tcpoptions[0]=0x02; s->ss->tcpoptions[1]=0x04;
				mtu=htons(s->vi[0]->mtu - 64);
				memcpy(s->ss->tcpoptions + 2, &mtu, sizeof(mtu));
				/* N N ( size 2 ) */
				s->ss->tcpoptions[4]=0x01; s->ss->tcpoptions[5]=0x01;
				/* S ( size 2 ) */
				s->ss->tcpoptions[6]=0x04; s->ss->tcpoptions[7]=0x02;
				/* N ( size 1 )*/
				s->ss->tcpoptions[8]=0x01;
				/* W 0 ( size 3 ) */
				s->ss->tcpoptions[9]=0x03; s->ss->tcpoptions[10]=0x03; s->ss->tcpoptions[11]=0x00;
				/* N N ( size 2 ) */
				s->ss->tcpoptions[12]=0x01; s->ss->tcpoptions[13]=0x01;
				/* T ( size 10 ) */
				s->ss->tcpoptions[14]=0x08; s->ss->tcpoptions[15]=0x0a;
				memcpy(s->ss->tcpoptions + 16, &l_tstamp, sizeof(l_tstamp));
				memcpy(s->ss->tcpoptions + 20, &r_tstamp, sizeof(r_tstamp));
			}
			break;
		case 2:
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				scan_setttl("128");
			}
			if (s->ss->ip_off == 0) {
				s->ss->ip_off=IP_DF;
			}

			/* windows xp or something from the p0f fp file */
			if (s->ss->mode == MODE_TCPSCAN) {
				mtu=htons(s->vi[0]->mtu - 40);
				s->ss->window_size=32767;
				s->ss->tcpoptions_len=8;
				/* MSS size 4 */
				s->ss->tcpoptions[0]=0x02; s->ss->tcpoptions[1]=0x04;
				memcpy(s->ss->tcpoptions + 2, &mtu, sizeof(mtu));
				/* N N size 2 */
				s->ss->tcpoptions[4]=0x01; s->ss->tcpoptions[5]=0x01;
				/* S ( size 2 ) */
				s->ss->tcpoptions[6]=0x04; s->ss->tcpoptions[7]=0x02;
			}
			break;

		case 3: /* p0f sendsyn (aprox) */
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				scan_setttl("255");
			}
			if (s->ss->ip_off == 0) {
				s->ss->ip_off=0;
			}

			if (s->ss->mode == MODE_TCPSCAN) {
				mtu=htons(s->vi[0]->mtu - 40);
				s->ss->window_size=12345;
				s->ss->tcpoptions_len=0;
			}
			break;
		case 4: /* freebsd */
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				scan_setttl("64");
			}
			s->ss->ip_off=IP_DF;
/*
from FreeBSD 5.2.1-RELEASE
 NOTE that im using telnet so the tos is 10, lets just pretend everyone who uses freebsd surfs the net with telnet...
IP (tos 0x10, ttl  63, id 10466, offset 0, flags [DF], length: 60) X.X.X.X.49362 > Y.Y.Y.Y.80: S [tcp sum ok] 3005084049:3005084049(0) win 65535 <mss 1460,nop,wscale 1,nop,nop,timestamp 286071223 0>

minutes later:
IP (tos 0x10, ttl  64, id 51550, offset 0, flags [DF], length: 60) Y.Y.Y.Y.6175 > X.X.X.X.80: S [tcp sum ok] 2333165575:2333165575(0) win 65535 <mss 1460,nop,wscale 1,nop,nop,timestamp 700713127 0>
p0f says:
Y.Y.Y.Y:6175 - FreeBSD 4.7-5.1 (or MacOS X 10.2-10.3) (2) [high throughput] (up: 1946 hrs)
  -> X.X.X.X:80 (distance 0, link: ethernet/modem)
*/

			if (s->ss->mode == MODE_TCPSCAN) {
				if (s->ss->tos == 0) {
					s->ss->tos=0x10; /* its telnet! */
				}
				s->ss->window_size=65535;
				s->ss->tcpoptions_len=20;
				/* M*  ( size 4 ) */
				s->ss->tcpoptions[0]=0x02; s->ss->tcpoptions[1]=0x04;
				mtu=htons(s->vi[0]->mtu - 40);
				memcpy(s->ss->tcpoptions + 2, &mtu, sizeof(mtu));
				/* N ( size 1 ) */
				s->ss->tcpoptions[4]=0x01;
				/* W 1 ( size 3 ) */
				s->ss->tcpoptions[5]=0x03; s->ss->tcpoptions[6]=0x03; s->ss->tcpoptions[7]=0x01;
				/* N N ( size 2 ) */
				s->ss->tcpoptions[8]=0x01; s->ss->tcpoptions[9]=0x01;
				/* T ( size 10 ) */
				s->ss->tcpoptions[10]=0x08; s->ss->tcpoptions[11]=0x0a;
				memcpy(s->ss->tcpoptions + 12, &l_tstamp, sizeof(l_tstamp));
				memcpy(s->ss->tcpoptions + 16, &r_tstamp, sizeof(r_tstamp));
			}
			break;
		case 5:
/*
nmap (doing some OS detection type stuff)
p0f says:
3072:64:0:60:W10,N,M265,T,E:PF:-*NMAP:OS detection probe w/flags (4)
tcpdump says:
IP (tos 0x0, ttl  41, id 19158, offset 0, flags [none], length: 60) X.X.X.X.62266 > Y.Y.Y.Y.5555: S [tcp sum ok] 2696440034:2696440034(0) win 3072 <wscale 10,nop,mss 265,timestamp 1061109567 0,eol>

minutes later:
IP (tos 0x0, ttl  60, id 55261, offset 0, flags [none], length: 60) Y.Y.Y.Y.63138 > X.X.X.X.7777: S [tcp sum ok] 1436422910:1436422910(0) win 3072 <wscale 10,nop,mss 265,timestamp 4258140862 0,eol>

and p0f says:
Y.Y.Y.Y:15303 - NMAP OS detection probe (3) *
*/
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				scan_setttl("61");
			}
			if (s->ss->ip_off == 0) {
				s->ss->ip_off=0;
			}

			if (s->ss->mode == MODE_TCPSCAN) {
				s->ss->window_size=3072;
				s->ss->tcpoptions_len=20;
				/* W 10 ( size 3 ) */
				s->ss->tcpoptions[0]=0x03; s->ss->tcpoptions[1]=0x03; s->ss->tcpoptions[2]=0x0a;
				/* N size 1 */
				s->ss->tcpoptions[3]=0x01;
				/* MSS size 4 */
				mtu=htons(265);
				s->ss->tcpoptions[4]=0x02; s->ss->tcpoptions[5]=0x04;
				memcpy(s->ss->tcpoptions + 6, &mtu, sizeof(mtu));
				/* T ( size 10 ) */
				s->ss->tcpoptions[8]=0x08; s->ss->tcpoptions[9]=0x0a;
				memcpy(s->ss->tcpoptions + 10, &l_tstamp, sizeof(l_tstamp));
				memcpy(s->ss->tcpoptions + 14, &r_tstamp, sizeof(r_tstamp));
				/* EOL size 1 */
				s->ss->tcpoptions[18]=0x00;
				s->ss->tcpoptions[19]=0x00;
			}
			break;
		case 6:
/*
just cause you would expect this to be here:
IP (tos 0x0, ttl  63, id 12954, offset 0, flags [DF], length: 60) Y.Y.Y.Y.32917 > X.X.X.X.7777: S [tcp sum ok] 2611271644:2611271644(0) win 5744 <mss 1436,sackOK,timestamp XXXX32940 0,nop,wscale 0>

minutes later:
IP (tos 0x0, ttl  63, id 34165, offset 0, flags [DF], length: 60) Y.Y.Y.Y.50194 > X.X.X.X.7777: S [tcp sum ok] 1386490716:1386490716(0) win 5744 <mss 1436,sackOK,timestamp 2708977776 0,nop,wscale 0>
and
Y.Y.Y.Y:50194 - Linux 2.4/2.6 (up: 7524 hrs)
  -> X.X.X.X:7777 (distance 1, link: IPSec/GRE)
*/
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				scan_setttl("64");
			}
			if (s->ss->ip_off == 0) {
				s->ss->ip_off=IP_DF;
			}

			if (s->ss->mode == MODE_TCPSCAN) {
				s->ss->tcpoptions_len=20;
				mtu=htons(s->vi[0]->mtu - 64);
				s->ss->window_size=(s->vi[0]->mtu - 64) * 4;
				/* MSS size 4 */
				s->ss->tcpoptions[0]=0x02; s->ss->tcpoptions[1]=0x04;
				memcpy(s->ss->tcpoptions + 2, &mtu, sizeof(mtu));
				/* S ( size 2 ) */
				s->ss->tcpoptions[4]=0x04; s->ss->tcpoptions[5]=0x02;
				/* T ( size 10 ) */
				s->ss->tcpoptions[6]=0x08; s->ss->tcpoptions[7]=0x0a;
				/* random uptime per session */
				memcpy(s->ss->tcpoptions + 8, &l_tstamp, sizeof(l_tstamp));
				memcpy(s->ss->tcpoptions + 12, &r_tstamp, sizeof(r_tstamp));
				/* N size 1 */
				s->ss->tcpoptions[16]=0x01;
				/* W 0 ( size 3 ) */
				s->ss->tcpoptions[17]=0x03; s->ss->tcpoptions[18]=0x03; s->ss->tcpoptions[19]=0x00;
			}
			break;
		case 7: /* some crazy stuff i just made up */
			/* XXX ADD rand ttl option to ttl parser */
			if (s->ss->minttl == 0 && s->ss->maxttl == 0) {
				uint8_t rttl=0;

				rttl=((prng_get32() & 0xFF) | 0x80);
				s->ss->minttl=rttl;
				s->ss->maxttl=rttl;
			}
			if (s->ss->ip_off == 0) {
				s->ss->ip_off=IP_DF;
			}

			if (s->ss->mode == MODE_TCPSCAN) {
				uint32_t hash_w=0;

				s->ss->window_size=(s->vi[0]->mtu - 32) * 8;
				s->ss->tcpoptions_len=24; /* i cant make this as big as i want, not sure where this is breaking */

				/* mss 4 */
				mtu=htons(1024);
				s->ss->tcpoptions[0]=0x02; s->ss->tcpoptions[1]=0x04;
				memcpy(s->ss->tcpoptions + 2, &mtu, sizeof(mtu));

				/* S ( size 2 ) */
				s->ss->tcpoptions[4]=0x04; s->ss->tcpoptions[5]=0x02;

				/* md5 signature length 18 */
				s->ss->tcpoptions[6]=0x13; s->ss->tcpoptions[7]=0x12;

				hash_w=prng_get32();
				memcpy(s->ss->tcpoptions + 8, &hash_w, sizeof(hash_w));
				hash_w=prng_get32();
				memcpy(s->ss->tcpoptions + 12, &hash_w, sizeof(hash_w));
				hash_w=prng_get32();
				memcpy(s->ss->tcpoptions + 16, &hash_w, sizeof(hash_w));
				hash_w=prng_get32();
				memcpy(s->ss->tcpoptions + 20, &hash_w, sizeof(hash_w));

				s->ss->tcpoptions[24]=0x08; s->ss->tcpoptions[25]=0x0a;
				memcpy(s->ss->tcpoptions + 26, &l_tstamp, sizeof(l_tstamp));
				memcpy(s->ss->tcpoptions + 30, &r_tstamp, sizeof(r_tstamp));
				s->ss->tcpoptions[34]=0x01; s->ss->tcpoptions[35]=0x01;
				s->ss->tcpoptions[35]=0x01; s->ss->tcpoptions[36]=0x01;
			}
			break;

		case 8: /* random tcp options */
		default:
			ERR("unknown fingerprint `%d', defaulting to 0", s->ss->fingerprint);
			s->ss->fingerprint=0;
			init_packet();
			break;
	}

	return;
}
