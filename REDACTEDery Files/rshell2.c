#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0); setgid(0);
    execl("/bin/sh", "sh", NULL);
    // If exec fails:
    perror("exec");
    return 1;
}
