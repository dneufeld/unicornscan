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
#include <unilib/rbtree.h>

#ifdef DEBUG
# define __DBG(fmt, args...) \
	fprintf(stderr, "DEBUG[%s at %s:%d]: ", __FUNCTION__, __FILE__, __LINE__);\
	fprintf(stderr, fmt, ## args); \
	fprintf(stderr, "\n");
#define DEBUG 1
#else
# define __DBG(fmt, args...)
#define DEBUG 0
#endif

#define rhead		rb_head_t
#define rnode		rb_node_t

#define RBMAGIC		(uint32_t)0xfee1dead
#define MALLOC(x)	xmalloc(x)
#define FREE(x)		xfree(x)

typedef enum { red_e, black_e } rbcolor_t;

typedef struct rnode {
	struct rnode *lchld;
	struct rnode *rchld;
	struct rnode *parent;
	rbcolor_t color;
	void *data;
	uint64_t key;
} rnode;

typedef struct rhead {
	uint32_t magic;
	uint32_t len;
	rnode *root;
} rhead;

static int   _rb_find(rhead *, uint64_t /* key */, rnode ** /* result */);

static int   _rb_insert(rhead *, uint64_t /* key */, rnode ** /* pointer to inserted node */);
static void  _rb_fix_insert(rhead *, rnode *);
static void  _rb_rotate_left(rhead *, rnode *);
static void  _rb_rotate_right(rhead *, rnode *);

static void  _rb_murder(rhead *, rnode **); /* this uses ** to set the pointer to null afterwards */
static int   _rb_snuffout(rhead *, rnode *);
static rnode *_rb_find_successor(rnode *n);

static int _rb_preo_walk(rnode *, int (*)(uint64_t, void *, void *), void *);
static int _rb_ino_walk(rnode *, int (*)(uint64_t, void *, void *), void *);
static int _rb_posto_walk(rnode *, int (*)(uint64_t, void *, void *), void *);

/* exported */
void *rbinit(uint32_t exp_size /* non op */) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;

	assert(exp_size > 0); /* for icc */

	h_u.ptr=MALLOC(sizeof(rhead));
	h_u.lh->magic=RBMAGIC;
	h_u.lh->root=NULL;
	h_u.lh->len=0;
	__DBG("setup head in rbinit");

	return h_u.ptr;
}

void rbdestroy(void *lh) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);

	if (h_u.lh->root != NULL) {
		_rb_murder(h_u.lh, &h_u.lh->root);
	}

	FREE(h_u.ptr);
	h_u.ptr=NULL;

	return;
}

int rbinsert(void *lh, uint64_t key, void *data) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;
	rnode *added=NULL;
	int ret=0;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);

	__DBG("rbinsert(lh, %llu, data)", key);
	if ((ret=_rb_insert(h_u.lh, key, &added)) < 0) {
		switch (ret) {
			case -1:
				__DBG("cant insert key %llu into list, duplicate key", key);
				return -1;
			default:
				__DBG("cant insert key %llu into list, unknown error `%d'", key, ret);
				return -1;
		}
	}

	assert(added != NULL);
	assert(added->data == NULL);
	added->data=data;

	if (DEBUG) {
		union {
			void *ptr;
			char *str;
		} d_u;
		d_u.ptr=added->data;
		__DBG("set node key %llu data to `%s'", key, d_u.str);
	}

	return 1;
}

uint32_t rbsize(void *lh) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);

	return h_u.lh->len;
}

int rbdelete(void *lh, uint64_t key) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;
	rnode *search=NULL;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);

	__DBG("in rbdelete(lh, %llu)", key);

	if (_rb_find(h_u.lh, key, &search) < 0) {
		return -1;
	}

	if (_rb_snuffout(h_u.lh, search) < 0) {
		return -1;
	}

	return 1;
}

int rbfind(void *lh, uint64_t key, void **udata) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;
	rnode *search=NULL;

	assert(udata != NULL);
	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);

	__DBG("rbfind(lh, %llu, data)", key);
	if (_rb_find(h_u.lh, key, &search) < 0) {
		*udata=NULL;
		return -1;
	}

	*udata=search->data;
	return 1;
}

uint32_t rbgetsize(void *lh) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);

	return h_u.lh->len;
}

int rbwalk(void *lh, int (*wf)(uint64_t /*node key*/, void * /*data ptr*/, void * /* cbdata */), int wt, void *cbdata) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;

	assert(lh != NULL);
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);
	assert(wf != NULL);

	switch (wt) {
		case RBORD_PREO:
			return _rb_preo_walk(h_u.lh->root, wf, cbdata);

		case RBORD_INO:
			return _rb_ino_walk(h_u.lh->root, wf, cbdata);

		case RBORD_POSTO:
			return _rb_posto_walk(h_u.lh->root, wf, cbdata);

		default:
			return _rb_ino_walk(h_u.lh->root, wf, cbdata);
	}

	return -1; /* not possible */
}

int _rb_find(rhead *h, uint64_t key, rnode **node) {
	rnode *walk=NULL;

	assert(h != NULL);
	assert(h->magic == RBMAGIC);
	assert(node != NULL);

	__DBG("in _rb_find(lh, %llu, node)", key);

	if (h->root == NULL) {
		*node=NULL;
		__DBG("_rb_find() returning -1");
		return -1;
	}

	for (walk=h->root; walk != NULL; ) {
		if (key == walk->key)  {
			*node=walk;
			return 1;
		}

		if (key > walk->key) {
			__DBG("_rfind Steping to right");
			walk=walk->rchld;
		}
		else {
			__DBG("_rfind Steping to left");
			walk=walk->lchld;
		}
	}

	*node=NULL;
	return -1;
}

static int _rb_insert(rhead *h, uint64_t key, rnode **result) {
	rnode *walk=NULL, *parent=NULL, *add=NULL;

	assert(h != NULL);
	assert(h->magic == RBMAGIC);
	assert(result != NULL);

	__DBG("in _rb_insert(h, %llu, result)", key);

	if (h->root == NULL) {
		h->root=(rnode *)MALLOC(sizeof(rnode));
		h->root->parent=NULL;
		h->root->data=NULL;
		h->root->rchld=NULL;
		h->root->lchld=NULL;
		h->root->color=black_e;
		h->root->key=key;
		h->len=1;
		__DBG("Adding root node at %p with key %llu [%llu]", h->root, key, h->root->key);
		*result=h->root;
		return 1;
	}

	walk=h->root;
	parent=NULL;

	while (walk != NULL) {
		if (key == walk->key)  {
			return -1;
		}
		else if (key > walk->key) {
			__DBG("Steping to right");
			parent=walk;
			walk=walk->rchld;
		}
		else {
			__DBG("Steping to left");
			parent=walk;
			walk=walk->lchld;
		}
	}

	assert(parent != NULL);

	/* we are at the insertion point */
	add=(rnode *)MALLOC(sizeof(rnode));
	add->data=NULL;
	add->rchld=NULL;
	add->lchld=NULL;
	add->color=red_e;
	add->key=key;

	/* reconnect this parent to child */
	if (parent->key > add->key) {
		__DBG("Adding new node key %llu at %p to LEFT of parent key %llu at %p", add->key, add, parent->key, parent);
		parent->lchld=add;
	}
	else {
		__DBG("Adding new node key %llu at %p to RIGHT of parent key %llu at %p", add->key, add, parent->key, parent);
		parent->rchld=add;
	}
	add->parent=parent;
	__DBG("parent %p\n", (void *)parent);

	h->len++;

	/* root node is always black, we are red, things are good */
	if (add->parent == h->root) {
		assert(h->root->color == black_e);
		*result=add;
		__DBG("new node is already red and root node is already black, nothing to color");
		return 1;
	}

	_rb_fix_insert(h, add);

	*result=add;
	return 1;
}


static void _rb_fix_insert(rhead *h, rnode *node) {
	rnode *parent=NULL, *grandparent=NULL;

	assert(h != NULL); assert(node != NULL);
	assert(h->magic == RBMAGIC);

	__DBG("_rb_fix_insert(head, node)");
	/* ok so we have to play balance now
	 *
	 * here are the rules:
	 * 1) every node red or black
	 * 2) every leaf node is black
	 * 3) the children of a red node are always black
	 * 4) every direct path from a node to a descendant leaf node contains the same number of black nodes.
	 * 
	 * #3 implies that on any path from the root to a leaf, red nodes must not be adjacent.
	 * However, any number of black nodes may appear in a sequence.
	 */

	/* this indicates an error somewhere else */
	assert(node->color == red_e);

/*
	1. If the parent of the new node is black, tree properties are maintained. Stop.
	2. If the color of the parent is red, we break rule 3. Consider some subcases:
		1. If the color of the parent's sibling is red (ie the uncle is red):
		   We can safely change the color of that level of the tree to black, and change
		   the color of the parent of the parent of the inserted node to red. This
		   preserves rule 4, so it is OK, but we must then CONTINUE up the tree, to
		   see if THAT node's parent is red.
		2. If the color of the uncle is black:
		   Now we can't simply change our parent's node to black, because that would
		   break rule 4.. What we can do is the following:
			1. If we are closer to the uncle than our sibling:
			   Rotate on our parent away from uncle, and set our pointer to our old
			   parent (so we are now far from our uncle), and drop down to the following
			   case.
			2. If we are father from the uncle than our sibling:
			   Now we can rotate towards the uncle at the uncle's parent (our grandparent).
			   We can then safely change the old grandparent's color to red and our parent's
			   color to black to preserve rule 4. STOP.
	Lastly, always recolor root black 
*/

	/* this is what our families would be like if we were plants or something */
	parent=node->parent;
	assert(parent != NULL);

	/*
	 * while we are not the root, and the color of our parent is red , we have work todo
	 */
	while (1) {
		assert(node != NULL);
		if (node == h->root) {
			__DBG("Breaking cause node is root node");
			break;
		}
		if (node->parent->color == black_e) {
			__DBG("breaking cause node parent color is black");
			break;
		}
		/*
		 * we have broken rule number 3
		 */
		parent=node->parent; /* we can spin multiple times, so reset this */
		grandparent=parent->parent;

		assert(grandparent != NULL);

		if (grandparent == h->root) {
			__DBG("our grandparent is the root node");
		}

		__DBG("COLORS: us %s [%llu] parent %s [%llu] grandparent %s [%llu] ", (node->color == black_e ? "black" : "red"),
			node->key,
			(parent->color == black_e ? "black" : "red"),
			parent->key,
			(grandparent->color == black_e ? "black" : "red"),
			grandparent->key
		);

		/* if our parent is the left child of our grandparent */
		if (parent == grandparent->lchld) {
			rnode *bob=NULL;

			__DBG("our parent is the left child of the grandparent");
			/* bob is our uncle, but we never call him... */
			bob=grandparent->rchld;

			if (bob && bob->color == red_e) {
				__DBG("setting parent to black far uncle to black and grandparent to red and becoming grandparent");
				parent->color=black_e;
				bob->color=black_e;
				grandparent->color=red_e;
				/* whew, now we need to continue up the tree with the grandparent */
				node=grandparent;
			}
			else {
				if (node == parent->rchld) {
					node=parent; /* turn into parent */
					/* rotate left */
					__DBG("rotating self");
					_rb_rotate_left(h, node);
				}
				/* make sure we didnt just move up */
				parent=node->parent;
				grandparent=parent->parent;

				__DBG("setting parent to black and grandparent to red and rotating grandparent");
				parent->color=black_e;
				grandparent->color=red_e;
				/* rotate our granparent right */
				_rb_rotate_right(h, grandparent);
			}
		}
		else {
			rnode *bob=NULL;

			__DBG("our parent is the right child of the grandparent");
			/* bob is our uncle, but we never call him... */
			bob=grandparent->lchld;

			if (bob && bob->color == red_e) {
				__DBG("setting parent to black far uncle to black and grandparent to red and becoming grandparent");
				parent->color=black_e;
				bob->color=black_e;
				grandparent->color=red_e;
				/* whew, now we need to continue up the tree with the grandparent */
				node=grandparent;
			}
			else {
				if (node == parent->lchld) {
					__DBG("becoming parent");
					node=parent; /* turn into parent */
					/* rotate left */
					__DBG("rotating self");
					_rb_rotate_right(h, node);
				}
				/* make sure we didnt just move up */
				parent=node->parent;
				grandparent=parent->parent;

				__DBG("setting parent to black and grandparent to red, and rotating grandparent");
				parent->color=black_e;
				grandparent->color=red_e;
				/* rotate our granparent left */
				_rb_rotate_left(h, grandparent);
			}
		}

		__DBG("going once more");
	}

	if (h->root->color == red_e) {
		__DBG("recoloring root node to black");
		h->root->color=black_e;
	}
	h->root->parent=NULL;

	return;
}

static int _rb_preo_walk(rnode *n, int (*wf)(uint64_t, void *, void *), void *cbdata) {
	int ret=0;

	if (n != NULL) {
		ret=wf(n->key, n->data, cbdata);
		if (ret < 1) {
			return ret;
		}
		ret=_rb_preo_walk(n->lchld, wf, cbdata);
		ret=_rb_preo_walk(n->rchld, wf, cbdata);
	}
	return 1;
}

static int _rb_ino_walk(rnode *n, int (*wf)(uint64_t, void *, void *), void *cbdata) {
	int ret=0;

	if (n != NULL) {
		ret=_rb_ino_walk(n->lchld, wf, cbdata);
		ret=wf(n->key, n->data, cbdata);
		if (ret < 1) {
			return ret;
		}
		ret=_rb_ino_walk(n->rchld, wf, cbdata);
	}
	return 1;
}

static int _rb_posto_walk(rnode *n, int (*wf)(uint64_t, void *, void *), void *cbdata) {
	int ret=0;

	if (n != NULL) {
		ret=_rb_posto_walk(n->lchld, wf, cbdata);
		ret=_rb_posto_walk(n->rchld, wf, cbdata);
		ret=wf(n->key, n->data, cbdata);
		if (ret < 1) {
			return ret;
		}
	}
	return 1;
}

static void _rb_murder(rhead *h, rnode **n) {
	assert(h != NULL);
	assert(h->magic == RBMAGIC);
	assert(n != NULL);

	if ((*n)->rchld != NULL) {
		_rb_murder(h, &(*n)->rchld);
	}
	if ((*n)->lchld != NULL) {
		_rb_murder(h, &(*n)->lchld);
	}

	FREE((*n));

	/* this is to prevent mistakes ;] */
	*n=NULL;

	return;
}

static int _rb_snuffout(rhead *h, rnode *n) {
	rnode *del=NULL, *t=NULL;
	int ret=0;

	assert(h != NULL); assert(n != NULL);
	assert(h->magic == RBMAGIC);

	if ((ret=_rb_find(h, n->key, &del)) < 0) {
		__DBG("Can't find key %llu, status %d", n->key, ret);
		return -1;
	}

	if (n->rchld == NULL || n->lchld == NULL) {
		del=n;
	}
	else {
		del=_rb_find_successor(n);
	}

	if (del->lchld != NULL) {
		t=del->lchld;
	}
	else {
		t=del->rchld;
	}

	t->parent=del->parent;

	if (del->color == black_e) {
		assert(0);
	}

	FREE(del->data);
	FREE(del);

	return 1;
}

static void _rb_rotate_left(rhead *h, rnode *n) {
	rnode *flipper=NULL;

	__DBG("### rotating left ###");
	assert(n != NULL); assert(h != NULL);
	assert(h->magic == RBMAGIC);
	assert(n->rchld != NULL);

	flipper=n->rchld;
	n->rchld=flipper->lchld;
	if (flipper->lchld != NULL) {
		flipper->lchld->parent=n;
	}
	flipper->parent=n->parent;
	if (n->parent == NULL) {
		h->root=flipper;
	}
	else {
		if (n == n->parent->lchld) {
			n->parent->lchld=flipper;
		}
		else {
			n->parent->rchld=flipper;
		}
	}
	flipper->lchld=n;
	n->parent=flipper;

	return;
}

static void _rb_rotate_right(rhead *h, rnode *n) {
	rnode *flipper=NULL;

	assert(n != NULL); assert(h != NULL);
	assert(h->magic == RBMAGIC);
	assert(n->lchld != NULL);

	__DBG("### rotating right ###");
	flipper=n->lchld;
	n->lchld=flipper->rchld;
	if (flipper->rchld != NULL) {
		flipper->rchld->parent=n;
	}
	flipper->parent=n->parent;
	if (n->parent == NULL) {
		h->root=flipper;
	}
	else {
		if (n == n->parent->rchld) {
			n->parent->rchld=flipper;
		}
		else {
			n->parent->lchld=flipper;
		}
	}
	flipper->rchld=n;
	n->parent=flipper;

	return;
}

static rnode *_rb_find_successor(rnode *n) {
	rnode *walk=NULL;

	assert(n != NULL);

	__DBG("in _rb_find_successor(node->key = %llu)", n->key);

	if (n->rchld == NULL) {
		rnode *tmp=NULL;

		walk=n->parent;
		tmp=n;
		while (walk != NULL) {
			if (tmp != walk->rchld) break;
			tmp=walk;
			walk=walk->parent;
		}
	}
	else {
		walk=n->rchld;
		while (walk->lchld != NULL) {
			walk=walk->lchld;
		}
	}

	return walk;
}

/* XXX */

#ifdef DEBUG
void rbverify(void *lh) {
	union {
		void *ptr;
		rhead *lh;
	} l_u;

	assert(lh != NULL);
	l_u.ptr=lh;
	assert(l_u.lh->magic == RBMAGIC);

	if (l_u.lh->root == NULL) {
		return;
	}

	if (l_u.lh->root->parent != NULL) {
		fprintf(stderr, "root parent not NULL");
	}

	printf("total members %u\n", l_u.lh->len);

	return;
}

void rbdumptree(void *lh, rnode *n) {
	union {
		void *ptr;
		rhead *lh;
	} h_u;

	if (lh == NULL) {
		return;
	}
	h_u.ptr=lh;
	assert(h_u.lh->magic == RBMAGIC);

	if (n == NULL) {
		if (h_u.lh->root == NULL) {
			return;
		}
		n=h_u.lh->root;
	}

	printf("Node key %llx is %s\n", (long long unsigned)n->key, (n->color == black_e ? "Black" : "Red"));

	if (n->rchld != NULL) {
		rbdumptree(lh, n->rchld);
	}
	if (n->lchld != NULL) {
		rbdumptree(lh, n->lchld);
	}

	return;
}
#endif
