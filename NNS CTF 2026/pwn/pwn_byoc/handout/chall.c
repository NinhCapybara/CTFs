#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    void *code = mmap(NULL, 200, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    write(STDOUT_FILENO, "> ", 2);
    read(STDIN_FILENO, code, 200);
    ((void (*)(void))code)();
}
