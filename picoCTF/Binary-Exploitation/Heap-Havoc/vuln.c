#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

struct internet {
    int priority;
    char *name;
    void (*callback)();
};

void winner() {
    FILE *fp;
    char flag[256];

    fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        perror("Error opening flag.txt");
        exit(1);
    }

    if (fgets(flag, sizeof(flag), fp) != NULL) {
        printf("FLAG: %s\n", flag);
    } else {
        printf("Error reading flag\n");
    }

    fclose(fp);
}

int main(int argc, char **argv) {
    struct internet *i1, *i2, *i3;
    printf("Enter two names separated by space:\n");
    fflush(stdout);   
    if (argc != 3) {
        printf("Usage: ./vuln <name1> <name2>\n", argv[0]);
        fflush(stdout);  
        return 1;
    }

i1 = malloc(sizeof(struct internet));
i1->priority = 1;
i1->name = malloc(8);
i1->callback = NULL;

i2 = malloc(sizeof(struct internet));
i2->priority = 2;
i2->name = malloc(8);
i2->callback = NULL;

strcpy(i1->name, argv[1]);  
strcpy(i2->name, argv[2]); 

if (i1->callback) i1->callback();
if (i2->callback) i2->callback();

    printf("No winners this time, try again!\n");
}
