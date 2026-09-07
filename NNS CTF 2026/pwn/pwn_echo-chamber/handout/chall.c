#include <stdio.h>

int main(void) {
    char flag[128], input[128];

    setbuf(stdout, NULL);
    fgets(flag, sizeof(flag), fopen("/flag.txt", "r"));

    for (int i = 0; i < 16; i++) {
        printf("> ");
        if (!fgets(input, sizeof(input), stdin))
            break;
        printf(input);
    }
}
