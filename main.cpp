#include <cerrno>
#include <cstdio>
#include <unistd.h>
#include <sys/syscall.h>

int main() {

    printf("Hello World!\n");
    const char msg[] = "hi\n";

    long ret = syscall(SYS_write, 1, msg, sizeof(msg) - 1);
    if (ret == -1) {
        std::perror("syscall(SYS_write) failed");
        return 1;
    }

    return 0;
}