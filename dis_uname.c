#include <stdio.h>
#include <sys/utsname.h>
#include <seccomp.h>

void main() {
    puts("What's up?");

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(uname), 0);
    seccomp_load(ctx);

    struct utsname unameData;
    uname(&unameData);
    printf("%s \n", unameData.sysname);
}
