#include <stdio.h>

#include "shellcode.h"

int main(int argc, char **argv) {
	printf("size is %d\n", SHELLCODE_LEN);

	exit(0);
}
