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
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#define SERVER_PORT 9875

static void do_child(int );

static void handle_sigchld(int signo) {
	int status=0;
	pid_t chld=0;

	chld=waitpid(-1, &status, WNOHANG);

	return;
}

int main(int argc, char ** argv) {
	struct sockaddr_in sin, cin;
	int s=-1, c=-1, param=0;
	socklen_t sl=0;
	pid_t chld=0;

	s=socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		exit(1);
	}

	signal(SIGCHLD, handle_sigchld);

	param=1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&param, sizeof(param)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	sin.sin_family=AF_INET;
	sin.sin_port=htons(SERVER_PORT);
	sin.sin_addr.s_addr=0;

	printf("Listening on port %u\n", SERVER_PORT);

	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		exit(1);
	}

	if (listen(s, 5) < 0) {
		perror("listen");
		exit(1);
	}

	while (1) {
		sl=sizeof(cin);
		if ((c=accept(s, (struct sockaddr *)&cin, &sl)) < 0) {
			perror("accept");
			continue;
		}

		chld=fork();
		if (chld < 0) {
			perror("fork");
			exit(1);
		}
		else if (chld == 0) {
			close(s);
			do_child(c);
			_exit(0);
		}
		else {
			close(c);
		}
	}

	exit(0);
}

static void do_child(int fd) {
	char host[128];
	unsigned int platform=0, sc_size=0;
	const char *fn=NULL, *plat=NULL;
	ssize_t rret=0;
	struct sockaddr_in sin;
	struct stat sb;
	off_t sfd_off=0;
	int sfd=0;
	socklen_t slen=0;

	slen=sizeof(sin);
	if (getpeername(fd, (struct sockaddr *)&sin, &slen) < 0) {
		perror("getpeername");
		goto error;
	}

	if (sin.sin_family == AF_INET) {
		sprintf(host, "%s:%u", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
	}
	else {
		printf("whoa, non inet4?\n");
		goto error;
	}

	rret=read(fd, &platform, sizeof(platform));
	if (rret < 0) {
		perror("read");
		close(fd);
		goto error;
	}

	switch (platform) {
		case 0:
			printf("what?\n");
			break;
		case 1:

			plat="linux-x86";
			fn="linux-x86.bin";
			break;

		case 2:

			plat="netbsd-x86";
			fn="netbsd-x86.bin";
			break;

		default:
			printf("Unknown platform %d\n", platform);
			goto error;
	}

	if (stat(fn, &sb) < 0) {
		fprintf(stderr, "Cant open %s: %s", fn, strerror(errno));
		goto error;
	}

	sc_size=(unsigned int)sb.st_size;
	printf("%s %s payload is %u bytes\n", host, plat, sc_size);
	if (write(fd, &sc_size, sizeof(sc_size)) < 0) {
		perror("write");
		goto error;
	}

	sfd=open(fn, O_RDONLY);
	if (sfd < 0) {
		fprintf(stderr, "Cant open %s: %s", fn, strerror(errno));
		goto error;
	}

	sfd_off=0;
	if (sendfile(fd, sfd, &sfd_off, sb.st_size) < 0) {
		perror("sendfile");
		goto error;
	}

error:
	printf("%s Closing\n", host);
	fflush(stdout);

	if (sfd) close(sfd);
	if (fd) close(fd);

	return;
}
