#ifndef TRIE_H
#define TRIE_H

#include <stdint.h>

struct trie {
	size_t tr_nmemb;
	struct trie **tr_members;
	void *tr_data;
	uint8_t tr_key; /* [1] */
};

#define TR_POISON1 ((void *)0x46524545)
#define TR_POISON2 ((void *)0x46524547)
#define TR_POISON3 ((void *)0x46524548)

void tr_print(struct trie * /* root */, float /* xstart */, float /* xwidth */, float /* x */, float /* y */);
void tr_destroy(struct trie *);
int tr_insert(struct trie *, const char *, void *);
int tr_search(struct trie *, const char *);
int (*tr_compar)(const void *, const void *);

#endif /* TRIE_H */
