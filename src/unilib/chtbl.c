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

#include <unilib/xmalloc.h>
#include <unilib/chtbl.h>

#ifdef DEBUG
# define __DBG(fmt, args...) \
	fprintf(stderr, "DEBUG[%s at %s:%d]: ", __FUNCTION__, __FILE__, __LINE__);\
	fprintf(stderr, fmt, ## args); \
	fprintf(stderr, "\n");
#else
# define __DBG(fmt, args...)
#endif

#define chead		chtbl_head_t
#define cnode		chtbl_node_t

#define CHTMAGIC	(uint32_t)0x4298ac32

#define MALLOC(x)	xmalloc(x)
#define FREE(x)		xfree(x)

typedef struct cnode {
	void *data;
	uint64_t key;
	struct cnode *next;
} cnode;

typedef struct chead {
	uint32_t magic;
	uint32_t tsize;
	uint32_t size;
	cnode **table;
} chead;

static uint32_t s_tbl[]={
0x00000002, 0x00000003, 0x00000005, 0x00000007, 0x0000000b,
0x0000000d, 0x00000011, 0x00000013, 0x00000017, 0x0000001d,
0x00000025, 0x00000029, 0x0000002f, 0x00000035, 0x0000003b,
0x00000043, 0x0000004f, 0x00000059, 0x00000065, 0x00000071,
0x0000007f, 0x00000095, 0x000000a7, 0x000000bf, 0x000000df,
0x000000fb, 0x00000119, 0x00000139, 0x0000015b, 0x00000185,
0x000001b1, 0x000001e7, 0x0000021d, 0x00000259, 0x000002a1,
0x000002ef, 0x00000347, 0x000003a9, 0x00000419, 0x00000493,
0x00000515, 0x000005a7, 0x00000647, 0x000006fb, 0x000007c3,
0x0000089f, 0x0000099b, 0x00000ab5, 0x00000be9, 0x00000d3d,
0x00000eb7, 0x00001069, 0x00001241, 0x0000144d, 0x00001693,
0x00001915, 0x00001bef, 0x00001f0d, 0x00002285, 0x00002665,
0x00002ab9, 0x00002f7d, 0x000034c9, 0x00003aa9, 0x00004133,
0x00004879, 0x00005093, 0x00005989, 0x0000637d, 0x00006e93,
0x00007aed, 0x000088a5, 0x000097d3, 0x0000a8b5, 0x0000bb91,
0x0000d069, 0x0000e791, 0x0001014b, 0x00011de5, 0x00013db3,
0x00016103, 0x00018841, 0x0001b3d9, 0x0001e44b, 0x00021a2b,
0x00025601, 0x00029873, 0x0002e247, 0x0003345b, 0x00038f83,
0x0003f4cd, 0x00046559, 0x0004e265, 0x00056d55, 0x000607b5,
0x0006b353, 0x000771fd, 0x000845c5, 0x00093121, 0x000a36af,
0x000b5943, 0x000c9c17, 0x000e02cf, 0x000f9157, 0x00114c35,
0x00133849, 0x00155afb, 0x0017ba75, 0x001a5d6b, 0x001d4b5f,
0x00208caf, 0x00242a95, 0x00282f55, 0x002ca661, 0x00319c75,
0x00371fa1, 0x003d3f9d, 0x00440dcd, 0x004b9d91, 0x0054046f,
0x005d5a47, 0x0067b9a9, 0x00734017, 0x00800e55, 0x008e48d9,
0x009e1811, 0x00afa909, 0x00c32da1, 0x00d8dd5f, 0x00f0f5f9,
0x010bbc11, 0x01297bc1, 0x014a89a5, 0x016f43c5, 0x01981279,
0x01c569f5, 0x01f7cb3d, 0x022fc561, 0x026df7e5, 0x02b31393,
0x02ffdceb, 0x03552e5d, 0x03b3fab5, 0x041d4f73, 0x04925851,
0x0514622b, 0x05a4def1, 0x0645698b, 0x06f7caa1, 0x00000000,
};

#define THASH(x, y) \
	((x) % (y))

/* exported */
void *chtinit(uint32_t exp_size) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t j=0;

	for (j=0; s_tbl[j] != 0; j++) {
		if (s_tbl[j] > exp_size) {
			exp_size=s_tbl[j];
			break;
		}
	}

	h_u.ptr=MALLOC(sizeof(chead));
	h_u.th->magic=CHTMAGIC;
	h_u.th->tsize=0;
	h_u.th->size=exp_size;
	h_u.th->table=(cnode **)MALLOC(sizeof(cnode *) * exp_size);
	for (j=0; j < exp_size; j++) {
		h_u.th->table[j]=(cnode *)NULL;
	}
	__DBG("init()'ed a table with expected size of %u", exp_size);

	return h_u.ptr;
}

uint32_t chtsize(void *lh) {
	union {
		void *ptr;
		chead *th;
	} h_u;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.th->magic == CHTMAGIC);

	return h_u.th->size;
}

void chtdestroy(void *lh) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t j=0;
	cnode *n=NULL, *save=NULL;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.th->magic == CHTMAGIC);

	if (h_u.th->tsize == 0) {
		return;
	}

	for (j=0; j < h_u.th->size; j++) {
		__DBG("freeing bucket %u\n", j);
		n=h_u.th->table[j];
		if (n == NULL) continue; /* nothing to see here, please move along */
		while (n->next != NULL) {
			save=n;
			n=n->next;
			__DBG("deleting node in chain");
			FREE(save);
			save=NULL;
		}
		__DBG("deleting last node in chain");
		FREE(n);
	}

	FREE(h_u.th->table);
	FREE(h_u.ptr);
	h_u.ptr=NULL;

	return;
}

uint32_t chtgetsize(void *th) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	return h_u.th->tsize;
}

int chtinsert(void *th, uint64_t key, void *data) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t offset=0;
	cnode *bucket=NULL, *newn=NULL, *prev=NULL;

	assert(data != NULL);
	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	offset=THASH(key, h_u.th->size);

	bucket=h_u.th->table[offset];

	while (bucket != NULL && key != bucket->key) {
		prev=bucket;
		bucket=bucket->next;
	}
	if (bucket != NULL && bucket->key == key) {
		return CHEXIT_KEYCOLLIDE;
	}

	newn=(cnode *)MALLOC(sizeof(cnode));
	newn->key=key;
	newn->data=data;

	if (!(prev)) {
		h_u.th->table[offset]=newn;
	}
	else {
		prev->next=newn;
	}
	newn->next=NULL;
	++h_u.th->tsize;

	return CHEXIT_SUCCESS;
}

int chtdelete(void *th, uint64_t key) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t offset=0;
	cnode *bucket=NULL, *prev=NULL;

	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	offset=THASH(key, h_u.th->size);
	bucket=h_u.th->table[offset];

	while (bucket != NULL && bucket->key != key) {
		prev=bucket;
		bucket=bucket->next;
	}
	if (bucket == NULL || bucket->key != key) {
		return CHEXIT_FAILURE;
	}
	if (prev != NULL) {
		prev->next=bucket->next;
	}
	else {
		h_u.th->table[offset]=bucket->next;
	}
	FREE(bucket->data);
	FREE(bucket);
	--h_u.th->tsize;

	return CHEXIT_SUCCESS;
}

void chtwalk(void *th, void (*wf)(uint64_t, void *), int ignore) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t j=0;
	cnode *n=NULL;

	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	if (h_u.th->tsize == 0) {
		return;
	}

	for (j=0; j < h_u.th->size; j++) {
		n=h_u.th->table[j];
		if (n == NULL) {
			continue; /* nothing to see here, please move along */
		}
		wf(n->key, n->data);
		for (n=n->next; n != NULL; n=n->next) {
			wf(n->key, n->data);
		}
	}

	return;
}

int chtfind(void *th, uint64_t key, void **udata) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t offset=0;
	cnode *bucket=NULL, *prev=NULL;

	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	offset=THASH(key, h_u.th->size);

	for (bucket=h_u.th->table[offset]; bucket != NULL && bucket->key != key; bucket=bucket->next) {
		prev=bucket;
	}

	if (bucket == NULL || bucket->key != key) {
		*udata=NULL;
		return CHEXIT_FAILURE;
	}

	*udata=bucket->data;
	return CHEXIT_SUCCESS;
}

#ifdef DEBUG
void chtstats(void *th) {
	union {
		void *ptr;
		chead *th;
	} h_u;
	uint32_t j=0;
	uint32_t clen=0;
	cnode *step=NULL;

	assert(th != NULL);
	h_u.ptr=th;
	assert(h_u.th->magic == CHTMAGIC);

	printf("load %f [%u items in %u slots]\n", (float)(h_u.th->tsize / h_u.th->size), h_u.th->tsize, h_u.th->size);

	for (j=0; j < h_u.th->size; j++) {
		if (h_u.th->table[j]) {
			step=h_u.th->table[j]; ++clen;
			while (step->next != NULL) {
				++clen;
				step=step->next;
			}
			printf("%u [%u] ", j, clen); clen=0;
		}
	}
}
#endif

#undef chead
#undef cnode
