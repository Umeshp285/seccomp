#include <stdio.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

void main() {
    FILE *filePoint;

    filePoint = fopen("test1.txt", "a");


    if(filePoint == NULL) {
        puts("File can not be opened");
        exit(1);
    }

    fputs("qwe\n", filePoint);

    fclose(filePoint);

    filePoint = fopen("test1.txt", "a");

    if(filePoint == NULL) {
        puts("File can not be opened");
        exit(1);
    }

    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

    fputs("xyz", filePoint);

    fclose(filePoint);
}
