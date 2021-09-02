#include <stdio.h>
#include <seccomp.h>

int main() {
    scmp_filter_ctx seccomp;

    seccomp = seccomp_init(SCMP_ACT_ALLOW);

    // Make the `openat(2)` syscall always "succeed".
    seccomp_rule_add(seccomp, SCMP_ACT_ERRNO(0), SCMP_SYS(openat), 0);

    // Install the filter.
    seccomp_load(seccomp);

    FILE *file = fopen("test.txt", "r");

    // Do something with the file and then perform the cleanup.
    // <...>

    return 0;
}
