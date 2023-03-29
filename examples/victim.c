#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

int load_secret();

int main(int argc, char** argv) {
	int secret;
	Dl_info info;
	if (argc > 1 && dladdr(dlopen, &info)) {
		printf("> dlopen addr: %p\n", info.dli_saddr);
	}
	puts("> working...");
	srand(42);
	while (1) {
		printf("> generating secret ");
		fflush(stdout);
		for (int i = 0; i < 20; i++) {
			usleep(200 * 1000);
			printf(".");
			fflush(stdout);
		}
		secret = load_secret();
		printf(" saved!\n");
	}
}

int load_secret() {
	return rand();
}
