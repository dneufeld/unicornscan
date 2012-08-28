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
#include <stdio.h>
#include <sys/poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include <termios.h>
#ifndef TIOCGWINSZ
 #include <sys/ioctl.h>
#endif

#define PORT 9876


int tty_raw(void) {
        struct termios ti;
        int ret=0;

        ti.c_iflag |= IGNPAR;
        ti.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
#ifdef IUCLC
        ti.c_iflag &= ~IUCLC;
#endif

        ti.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL);
#ifdef IEXTEN
        ti.c_lflag &= ~IEXTEN;
#endif
        ti.c_oflag &= ~OPOST;

        ti.c_cc[VMIN] = 1;
        ti.c_cc[VTIME] = 0;

        ret=tcsetattr(fileno(stdout), TCSADRAIN, &ti);

        return ret;
}

int main(int argc, char ** argv) {
	struct pollfd fds[2];
	struct sockaddr_in sin, cin;
	char rbuf[1024];
	int s=-1, c=-1, pret=0, param=0;
	size_t j=0;
	ssize_t rret=0;
	socklen_t sl=0;
	uint8_t rkey=0x41, wkey=0x41;

	s=socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		exit(1);
	}

	param=1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&param, sizeof(param)) < 0) {
                perror("setsockopt");
		exit(1);
        }

	sin.sin_family=AF_INET;
	sin.sin_port=htons(PORT);
	sin.sin_addr.s_addr=0;

	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(s, 5) < 0) {
		perror("listen");
		exit(1);
	}

	printf("Waiting on port %d\n", PORT);

	sl=sizeof(cin);
	if ((c=accept(s, (struct sockaddr *)&cin, &sl)) < 0) {
		perror("accept");
		exit(1);
	}

	close(s);

	tty_raw();

	for (;;) {
again:
		memset(&fds[0], 0, sizeof(struct pollfd) * 2);
		fds[0].fd=0;
		fds[1].fd=c;
		fds[0].events=POLLIN;
		fds[1].events=POLLIN;
		pret=poll(&fds[0], 2, 10);
		if (errno == EINTR && pret < 0) goto again;

		if (pret < 0) {
			perror("poll");
			exit(1);
		}

		if (pret > 0) {
			/* stdin readable? */
			if (fds[0].revents & POLLIN) {
				memset(rbuf, 0, sizeof(rbuf));
				rret=read(fds[0].fd, rbuf, sizeof(rbuf) -1);
				if (rret < 0) {
					perror("read");
					exit(1);
				}
				if (rret > 0) {
					for (j=0 ; j < (size_t )rret ; j++) {
						rbuf[j] ^= rkey++;
					}
					if (write(c, rbuf, (size_t )rret) < 0) {
						perror("write");
						exit(1);
					}
				}
			}
			/* socket readable? */
			if (fds[1].revents & POLLIN) {
				memset(rbuf, 0, sizeof(rbuf));
				rret=read(fds[1].fd, rbuf, sizeof(rbuf) - 1);
				if (rret < 0) {
					perror("read");
					exit(1);
				}
				if (rret > 0) {
					for (j=0 ; j < (size_t )rret ; j++) {
						rbuf[j] ^= wkey++;
					}
					if (write(2, rbuf, (size_t)rret) < 0) {
						perror("write");
						exit(1);
					}
				}
			}
		}
		
	}

	exit(0);
}
