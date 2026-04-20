#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

int main() {
	printf("Welcome to the standard library tester\n");
	printf("Please upload the standard library you would like to test and we will see if it passes!\n");
	printf("We can only handle one function at a time so make sure it's not too big!\n");
	setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin", 1);
	fflush(0);
	char buffer[1024];
	int read = 0;
	int i = 0;
	while(fgets(buffer+i, sizeof(buffer), stdin) && buffer[(strlen(buffer)-2)] != '}') { i = strlen(buffer); }
	FILE *f = fopen("/tmp/libnew.c", "w");
	fprintf(f, "%s", buffer);
	fclose(f);

	system("/usr/bin/gcc -fPIC -shared -o /tmp/libnew.so /tmp/libnew.c -ldl");
	system("/usr/bin/gcc -L/tmp -Wl,-rpath,/tmp test.c -lnew -o /tmp/test");
	// Remember not to overwrite flag.txt
	printf("RUNNING NOW\n");
	system("/tmp/test");
	fflush(0);
}
