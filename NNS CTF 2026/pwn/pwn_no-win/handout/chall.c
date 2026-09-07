#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[64];

    setvbuf(stdout, NULL, _IONBF, 0);
    puts("no win(), so good luck");
    printf("> ");
    read(STDIN_FILENO, buf, 512);

    return 0;
}
