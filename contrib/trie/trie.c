#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> /* ditch me */
#include <err.h>
#include "stats.h"
#include "trie.h"

static int charcmp(const void *a, const void *b);
static int tr_nodecmp(const void *a, const void *b);

int main(int argc, char *argv[]) {
		
	struct trie *t = NULL;
	char keybuf[1024], databuf[1024];
	size_t i;

	tr_compar = charcmp;

	t = malloc(sizeof(struct trie));
	if (!t)
		err(1, "malloc");

	memset(t, 0, sizeof(struct trie));

	stats_init();
	while (fgets(keybuf, 1023, stdin)) {

		keybuf[strlen(keybuf)-1] = '\0'; /* FIXME \r\n */
		
		snprintf(databuf, 1023, "%s is the data as well", keybuf);
	
		stats_depth_0();
		int ret = tr_insert(t, keybuf, strdup(databuf));
		if (ret != 0)
			err(1, "tr_insert");
	}

	stats_dump();

	for (i = 1; i < (size_t)argc; i++) {
		tr_search(t, argv[i]);
	}

	printf("<?xml version='1.0' standalone='no'?>\n"
                "<svg:svg width='100%%' height='100%%' version='1.1' xmlns:svg='http://www.w3.org/2000/svg'>\n");

	t->tr_key='*';
	tr_print(t, 0.0, canvas_width, 512.0, 32.0);
	printf("</svg:svg>\n");

	tr_destroy(t);
	stats_fini();

	return (0);
}

int tr_insert(struct trie *t, const char *s, void *data) {


	struct trie tmp, *tmpp = &tmp,
		*memb = NULL;


	if (*s == '\0') {
		if (t->tr_data) {
			printf("node already exists: %c: '%s'\n", t->tr_key, (char *)data);
			return (-1); /* Node already exists */
		}


		t->tr_data = data;

		return (0);
	}

	tmp.tr_key = *s;

	if (!t) {
		t = (struct trie *)malloc(sizeof(struct trie));
		if (!t)
			err(1, "malloc");

		memset(t, 0, sizeof(struct trie));

		/* the head member does not have a tr_key and
		   no data should be associated with it	*/
	} 

	if (t->tr_nmemb) {

		memb = bsearch(&tmpp, t->tr_members, t->tr_nmemb,
				sizeof(struct trie *), tr_nodecmp);
		
		stats_depth_down();

		if (memb && *(struct trie **)memb) { /* recurse here */
			return (tr_insert(*(struct trie **)memb, ++s, data));
		}
	}


	t->tr_nmemb++;
	t->tr_members = (struct trie **)realloc(t->tr_members, 
				t->tr_nmemb * sizeof(struct trie)); /* int ovrflw */


	memb = malloc(sizeof(struct trie));
	if (!memb)
		err(1, "malloc");

	memset(memb, 0, sizeof(struct trie));
	memb->tr_key = *s;

	t->tr_members[t->tr_nmemb - 1] = memb;

	if (t->tr_nmemb > 1)
		qsort(t->tr_members, t->tr_nmemb, sizeof(struct trie *), tr_nodecmp);

	stats_depth_bottom();

	return (tr_insert(memb, ++s, data));
}

int tr_search(struct trie *t, const char *s) {

	struct trie tmp, *tmpp = &tmp,
		*memb = NULL;

	if (*s == '\0') {
		if (!t->tr_data) {
			printf("NOTFOUND: No entry for key\n");
			return (-1); /* No entry for key */
		}
		
		printf("\nFound '%s'\n", (char *)t->tr_data);

		return 0;
	}

	tmp.tr_key = *s;

	if (t->tr_nmemb) {
		memb = bsearch(&tmpp, t->tr_members, t->tr_nmemb,
				sizeof(struct trie *), tr_nodecmp);

		if (memb && *(struct trie **)memb) {
			return (tr_search(*(struct trie **)memb, ++s));
		}

		printf("NOTFOUND: no member found for '%c'\n", *s);
		return (-1);
	}

	printf("NOTFOUND: No entry for key (no more members)\n");

	return (-1);
}

void tr_destroy(struct trie *t) {

	size_t i;

	for (i = 0; i < t->tr_nmemb; i++) {
		tr_destroy(t->tr_members[i]);
		t->tr_members[i] = TR_POISON1;
	}
	
	if (t->tr_nmemb) {
		free(t->tr_members);
		t->tr_members = TR_POISON2;
	}

	if (t->tr_data) {
		free(t->tr_data);
		t->tr_data = TR_POISON3;
	}

	free(t);
}

void tr_print(struct trie *t, float xstart, float xwidth, float x, float y) {
	
	size_t i;
	char style[] = "font-size:18px;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;text-align:center;line-height:125%;writing-mode:lr-tb;text-anchor:middle;fill:black;fill-opacity:1;stroke:none;stroke-width:1px;stroke-linecap:butt;stroke-linejoin:miter;stroke-opacity:1;font-family:Arial";
//"font-size:18px";
	size_t nchild;
	float xi = 0.0;

//	printf("<svg:circle cx='%f' cy='%f' r='16px' fill='white' stroke='black' stroke-width='1' />\n", x, y-4);

//	printf("<svg:text x='%f' y='%f' style='%s' >%c</svg:text>\n", x, y, style, t->tr_key);

	for (nchild=0, i = 0; i < t->tr_nmemb; i++) {
		nchild++;
	}
	printf("<!-- children: %d\n -->\n", nchild);
	printf("<!-- xstart: %f\n -->\n", xstart);
	printf("<!-- xwidth: %f\n -->\n", xwidth);
	printf("<!-- x,y: %f,%f\n -->\n", x,y);

	if (nchild)
		xwidth /= nchild;

	for (i = 0; i < t->tr_nmemb; i++) {
		xi = xstart + xwidth/2.0;
		printf("<!-- xwidth/nchild/2: %f\n -->\n", (xwidth/nchild)/2.0);
		printf("<!-- children: %f\n -->\n", xi);

		printf("<svg:line x1='%f' y1='%f' x2='%f' y2='%f' "
			"style='stroke:rgb(99,99,99);stroke-width:2'/>\n",
			x, y+8+4, xi, y+64);

		tr_print(t->tr_members[i], xstart, xwidth, xi, y+64);
		xstart += xwidth;
	}
}

/* parameters:
	a: ptr to a single character
	b: ptr to a struct trie
   returns:
	an integer less than, equal to, or greater than zero if the key
	of node 'a' is found, respectively, to be less than, to match, or
	be greater than they key of node 'b'.
   purpose:
	used as a qsort callback 
*/
static int tr_nodecmp(const void *a, const void *b) {

	union {
		const void *p;
		const struct trie **t;
	} u1 = { .p = a }, u2 = { .p = b };

	return (tr_compar(&(*u1.t)->tr_key, &(*u2.t)->tr_key));
}

/* parameters:
	a: ptr to a single char
	b: ptr to a single char
*/
static int charcmp(const void *a, const void *b) {

	union {
		const void *p;
		const uint8_t *c;
	} u1  = { .p = a }, u2 = { .p = b };

	if (u1.c[0] > u2.c[0])
		return (1);

	if (u1.c[0] < u2.c[0])
		return (-1);

	return (0);
}
