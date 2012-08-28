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

#include <errno.h>

#include <settings.h>
#include <getconfig.h>
#include <packageinfo.h>

#include <unilib/xmalloc.h>
#include <unilib/output.h>
#include <unilib/xipc.h>
#include <unilib/drone.h>
#include <unilib/cidr.h>
#include <scan_progs/workunits.h>

int drone_setup(void) {
	uint8_t status=0, msg_type=0, ecount=0;
	size_t msg_len=0;
	uint8_t *ptr=NULL;
	uint32_t all_done=0;
	drone_t *c=NULL;
	union {
		uint8_t *ptr;
		drone_version_t *v;
	} d_u;
	int laggers=0;

	if (s->drone_str != NULL) {
		DBG(M_DRN, "setup drones `%s'", s->drone_str);

		if (drone_parselist((const char *)s->drone_str) < 0) {
			return -1;
		}
	}

	/* do stuff to figure out if there are working drones */
	DBG(M_DRN, "drone list is %d big, connecting to them.", s->dlh->size);

	do {
		uint8_t *dummy=NULL;

		if (s->dlh->head == NULL) {
			ERR("no drones?, thats not going to work, must have been a bad drone string");
			return -1;
		}

		for (c=s->dlh->head ; c != NULL ; c=c->next) {

			DBG(M_DRN, "this node %p status %s type %s uri %s socket %d (%d out of %d ready)",
				c, strdronestatus(c->status), strdronetype(c->type), c->uri, c->s, all_done, s->dlh->size
			);

			if (ecount > MAX_ERRORS) {
				ERR("too many errors, giving up on drones");
				return -1;
			}

			switch (c->status) {
				/* connect to it */
				case DRONE_STATUS_UNKNOWN:
					laggers=drone_connect();
					break;

				/* find out what it is */
				case DRONE_STATUS_CONNECTED:
					if (c->s < 0) {
						ERR("connected drone with bad socket?, marking dead");
						drone_updatestate(c, DRONE_STATUS_DEAD);
					}

					c->type=DRONE_TYPE_UNKNOWN;
					if (send_message(c->s, MSG_IDENT, MSG_STATUS_OK, dummy, 0) < 0) {
						ecount++;
						ERR("cant ident message node, marking as dead");
						if (ecount > MAX_ERRORS) {
							drone_updatestate(c, DRONE_STATUS_DEAD);
							break;
						}
					}
					else {
						if (get_singlemessage(c->s, &msg_type, &status, &d_u.ptr, &msg_len) != 1) {
							ERR("unexpected message response from fd %d, marking as dead", c->s);
							drone_updatestate(c, DRONE_STATUS_DEAD);
							break;
						}

						if (msg_len != sizeof(drone_version_t)) {
							ERR("drone on fd %d didnt identify its version, marking as dead", c->s);
							drone_updatestate(c, DRONE_STATUS_DEAD);
							break;
						}
						else if (d_u.v->magic != DRONE_MAGIC) {
							ERR("drone on fd %d isnt really a drone it seems, marking dead, magic was %08x",
								c->s, d_u.v->magic
							);
							drone_updatestate(c, DRONE_STATUS_DEAD);
							break;
						}

						VRB(1, "drone type %s on fd %d is version %u.%u",
							strdronetype(c->type), c->s, d_u.v->maj, d_u.v->min
						);

						if (d_u.v->maj != DRONE_MAJ || d_u.v->min != DRONE_MIN) {
							ERR("drone on fd %d has different version, marking as dead", c->s);
							drone_updatestate(c, DRONE_STATUS_DEAD);
							break;
						}

						switch (msg_type) {
							case MSG_IDENTSENDER:
								c->type=DRONE_TYPE_SENDER;
								s->senders++;
								break;

							case MSG_IDENTLISTENER:
								c->type=DRONE_TYPE_LISTENER;
								s->listeners++;
								break;

							default:
								ERR("unknown drone type from message %s", strmsgtype(msg_type));
								c->type=DRONE_TYPE_UNKNOWN;
								break;
						}

						if (send_message(c->s, MSG_ACK, MSG_STATUS_OK, dummy, 0) < 0) {
							ERR("cant ack ident message from node on fd %d, marking as dead", c->s);
							drone_updatestate(c, DRONE_STATUS_DEAD);
						}

						c->status=DRONE_STATUS_IDENT;
					}
					break;

				/* wait for it to say its ready */
				case DRONE_STATUS_IDENT:
					if (get_singlemessage(c->s, &msg_type, &status, &ptr, &msg_len) != 1) {
						ERR("unexpected message reply from drone on fd %d, marking as dead", c->s);
						drone_updatestate(c, DRONE_STATUS_DEAD);
					}
					else if (msg_type == MSG_READY) {

						c->status=DRONE_STATUS_READY;
						DBG(M_DRN, "drone on fd %d is ready", c->s);

						if (c->type == DRONE_TYPE_LISTENER) {
							union {
								listener_info_t *l;
								uint8_t *ptr;
							} l_u;

							if (msg_len != sizeof(listener_info_t)) {
								ERR("listener didnt send me the correct information, marking dead");
								drone_updatestate(c, DRONE_STATUS_DEAD);
							}
							l_u.ptr=ptr;

							/* XXX ADD VIP */
							s->vi[0]->mtu=l_u.l->mtu;
							memcpy(&s->vi[0]->myaddr, &l_u.l->myaddr, sizeof(struct sockaddr_storage));
							memcpy(&s->vi[0]->mymask, &l_u.l->mymask, sizeof(struct sockaddr_storage));
							memcpy(s->vi[0]->hwaddr, l_u.l->hwaddr, THE_ONLY_SUPPORTED_HWADDR_LEN);

							snprintf(s->vi[0]->hwaddr_s, sizeof(s->vi[0]->hwaddr_s) -1, "%02x:%02x:%02x:%02x:%02x:%02x", l_u.l->hwaddr[0], l_u.l->hwaddr[1], l_u.l->hwaddr[2], l_u.l->hwaddr[3], l_u.l->hwaddr[4], l_u.l->hwaddr[5]);
							snprintf(s->vi[0]->myaddr_s, sizeof(s->vi[0]->myaddr_s) -1, "%s", cidr_saddrstr((const struct sockaddr *)&l_u.l->myaddr));

							DBG(M_DRN, "listener info gave me the following address information `%s [%s]' with mtu %u", s->vi[0]->myaddr_s, s->vi[0]->hwaddr_s, s->vi[0]->mtu);
						}
					}
					else {
						ERR("drone isnt ready on fd %d, marking as dead", c->s);
						drone_updatestate(c, DRONE_STATUS_DEAD);
					}
					break;

				case DRONE_STATUS_READY:
					all_done++;
					break;

				case DRONE_STATUS_DEAD:
					all_done++;
					ERR("dead %s drone in list on fd %d", strdronetype(c->type), c->s);
					break;

				default:
					ecount++;
					ERR("%s drone on fd %d has an unknown status %s", strdronetype(c->type), c->s, strdronestatus(c->s));
					break;

			} /* switch node status */
		} /* step though list */

		if (laggers > 0) {
			usleep(10000);
		}

	} while (all_done < s->dlh->size);

	return 1;
}

void terminate_alldrones(void) {
        drone_t *c=NULL;
        uint8_t *ptr=NULL;

 	for (c=s->dlh->head ; c != NULL ; c=c->next) {
		DBG(M_DRN, "drone %s is state %s", strdronetype(c->type), strdronestatus(c->status));
		if (c->s > -1) {
			if (send_message(c->s, MSG_QUIT, MSG_STATUS_OK, ptr, 0) < 0) {
				ERR("cant tell %s %s drone on fd %d to terminate, marking dead", strdronestatus(c->status), strdronetype(c->type), c->s);
				drone_updatestate(c, DRONE_STATUS_DEAD);
				if (c->wid) {
					if (c->type == DRONE_TYPE_SENDER) {
						workunit_reject_sp(c->wid);
					}
					else if (c->type == DRONE_TYPE_LISTENER) {
						workunit_reject_lp(c->wid);
					}
				}
				c->wid=0;
			}
			else {
				if (c->wid) {
					if (c->type == DRONE_TYPE_SENDER) {
						workunit_reject_sp(c->wid);
					}
					else if (c->type == DRONE_TYPE_LISTENER) {
						workunit_reject_lp(c->wid);
					}
				}
				c->wid=0;
				drone_updatestate(c, DRONE_STATUS_DONE);
			}
		}
	}

	return;
}
