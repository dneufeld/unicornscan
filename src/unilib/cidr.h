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
#ifndef _CIDR_H
# define _CIDR_H

/*
 *	returns:
 *		> -1 address family AF_INET or AF_INET6 that sockaddr's are within
 *		-1: error condition with error message in error string pointer
 *	arguments:
 */

int cidr_get(
		const char *		/* network string			*/,
		struct sockaddr *	/* netid				*/,
		struct sockaddr *	/* netmask				*/,
		unsigned int *		/* parsed cidr mask (perhaps implied)	*/
	);

/*
 * increments the socket address, returns 1 if ok, -1 otherwise
 */
void cidr_inchost(struct sockaddr * /* host address to increment */);

void cidr_randhost(struct sockaddr * /* random host */, const struct sockaddr * /* network */, const struct sockaddr * /* mask */);

double	cidr_numhosts(const struct sockaddr * /* network */, const struct sockaddr * /* netmask */);

unsigned int cidr_getmask(const struct sockaddr * /* netmask */);

/*
 * returns 1 if host is within the network/netmask, 0 if it is outside,
 * and -1 if there is some sort of error with the arguments
 */
int cidr_within(
		const struct sockaddr * /* host		*/,
		const struct sockaddr * /* network	*/,
		const struct sockaddr * /* netmask	*/
	);
/*
 * returns a string describing the socket address structure
 */
char *cidr_saddrstr(const struct sockaddr * /* address */);

#endif /* _CIDR_H */
