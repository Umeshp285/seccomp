 #include <fcntl.h>
       #include <seccomp.h>
       #include <sys/stat.h>
       #include <sys/types.h>
	#include<stddef.h>
       #define BUF_SIZE    256

       int main(int argc, char *argv[])
       {
            int rc = -1;
            scmp_filter_ctx ctx;
            struct scmp_arg_cmp arg_cmp[] = { SCMP_A0(SCMP_CMP_EQ, 2) };
            int fd;
            unsigned char buf[BUF_SIZE];

            ctx = seccomp_init(SCMP_ACT_KILL);
            if (ctx == NULL)
                 goto out;

            /* ... */

            fd = open("file.txt", 0);

            /* ... */

            rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
            if (rc < 0)
                 goto out;

            rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 3,
                            SCMP_A0(SCMP_CMP_EQ, fd),
                            SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)buf),
                            SCMP_A2(SCMP_CMP_LE, BUF_SIZE));

	     if (rc < 0)
                 goto out;

            rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                            SCMP_CMP(0, SCMP_CMP_EQ, fd));
            if (rc < 0)
                 goto out;

            rc = seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                                  arg_cmp);
            if (rc < 0)
                 goto out;

            rc = seccomp_load(ctx);
            if (rc < 0)
                 goto out;

            /* ... */

       out:
            seccomp_release(ctx);
            return -rc;
       }

