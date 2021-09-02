#include <stdio.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <sys/prctl.h>

void main() {
    FILE *filePoint;
	
    int rc = -1;
    filePoint = fopen("test2.txt", "a");

    if(filePoint == NULL) {
        puts("File can not be opened");
        exit(1);
    }

    fputs("qwe\n", filePoint);

    fclose(filePoint);

    filePoint = fopen("test2.txt", "a");

    if(filePoint == NULL) {
        puts("File can not be opened");
        exit(1);
    }

//	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

   if(prctl(PR_SET_NO_NEW_PRIVS, 1,0,0,0)){
	
	   printf("prctl failed\n");
	   perror("prctl");
	   exit(EXIT_FAILURE);
   }

      // prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

   scmp_filter_ctx ctx;
  	ctx  = seccomp_init(SCMP_ACT_ALLOW);
	if(ctx == NULL)
	{	
		printf("ctx failed\n");
	}
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fstat), 0);
    if(rc < 0)
    {
	    printf("rc failed\n");
    }
    rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    if(rc < 0)
    {
	    printf("write rc failed\n");
    }
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(close), 0);
    if(rc < 0)
    {
	    printf("close rc failed\n");
    }
    rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(exit_group), 0);
    if(rc < 0)
    {
	    printf("exit-grp rc failed\n");
    }
    seccomp_load(ctx);
    
    fputs("xyz", filePoint);

    fclose(filePoint);
}
