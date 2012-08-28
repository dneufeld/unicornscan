#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <curl.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

#define MIME_HEADER "Content-Type: text/html\r\n\r\n"
#define HTML_HEADER "<html><head><title>cgi</title></head><body>"
#define HTML_TRAILER "</body></html>"

void display_query_string(const char *);

int main(int argc, char ** argv) {
	char *ptr=NULL, *envptr=NULL;

	write(1, MIME_HEADER, strlen(MIME_HEADER));

	write(1, HTML_HEADER, strlen(HTML_HEADER));

	envptr=getenv("QUERY_STRING");
	if (envptr) {
		ptr=curl_unescape(envptr, strlen(envptr));

		display_query_string(ptr);
	}
	else {
		printf("No QUERY_STRING<br/>\n");
	}

	write(1, HTML_TRAILER, strlen(HTML_TRAILER));

	fsync(1);

	exit(0);
}

void display_query_string(const char *instr) {
	char outstr[1024], *outptr=NULL;
	size_t j;

	if (instr == NULL) {
		write(1, "NO QUERY STRING<br/>\n", 21);
		return;
	}

	memset(outstr, 0, sizeof(outstr));

	outptr=&outstr[0];

	/* there are still overflows out there that look like this */

	for (j=0 ; j < MIN(strlen(instr), sizeof(outstr) -1) ; j++) {
		if (instr[j] == '>' || instr[j] == '<') {
			switch (instr[j]) {
				case '>':
					strcat(outptr, "&gt;");
					outptr += 4;
					break;
				case '<':
					strcat(outptr, "&lt;");
					outptr += 4;
					break;
			}
		}
		else {
			*outptr=instr[j];
			outptr++;
		}
	}

	*outptr='\0';

	printf("Query String &quot;<i>%s</i>&quot; <br/>\n", outstr);
	fflush(stdout);

	return;
}
