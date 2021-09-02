#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

int main(int argc, char **argv)
{
	int output = open("output.txt", O_WRONLY);
	const char *val = "test";
	
	printf("Calling prctl() to set seccomp strict mode…\n");

	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
	
	printf("Writing to an already open file…\n");

	write(output, val, strlen(val)+1);
	
	printf("Trying to open file for reading…\n");

	int input = open("output.txt", O_RDONLY);
	
	printf("You will not see this message — the process will be killed first\n");
}
