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
#ifndef QFIFO_H
 #define QFIFO_H

/* exported functions */

/* fifo */ void *fifo_init(void);
/* fifo */ void *lifo_init(void);
uint32_t fifo_push(void * /* fifo */ , void * /* data */);
void *fifo_pop(void * /* fifo */);
void fifo_destroy(void * /* fifo */);

uint32_t fifo_delete_first(void * /* fifo */, const void * /* data */, int (* /* compare */ )(const void *,const void *), int /* free data */);
uint32_t fifo_order(void * /* fifo */, int (* /* compare */ )(const void *, const void *), int /* direction */);
void *fifo_find(void * /* fifo */, const void * /* data */, int (* /* compare */ )(const void *, const void *));
void fifo_walk(void * /* fifo */, void (*)(void *));
uint32_t fifo_length(void * /* fifo */);

#endif
