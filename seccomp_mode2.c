#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

void main(void)
{
	/* initialize the libseccomp context */
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);/* allow exiting */
	printf("Adding rule : Allow exit_group\n");
	
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);/* allow getting the current pid */
	
	printf("Adding rule : Allow getpid\n");
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

	//printf("Adding rule : Deny getpid\n");
	//seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);

	/* allow changing data segment size, as required by glibc */
	printf("Adding rule : Allow brk\n");

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
	
	/* allow writing up to 512 bytes to fd 1 */

	printf("Adding rule : Allow write upto 512 bytes to FD 1\n");

	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,SCMP_A0(SCMP_CMP_EQ, 1),

	SCMP_A2(SCMP_CMP_LE, 512));/* if writing to any other fd, return -EBADF */

	printf("Adding rule : Deny write to any FD except 1 \n");

	seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,

	SCMP_A0(SCMP_CMP_NE, 1));

	/* load and enforce the filters */
	printf("Load rules and enforce \n");
	seccomp_load(ctx);
	seccomp_release(ctx);
	printf("this process is %d\n", getpid());

}
