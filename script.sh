#!/bin/bash

# simle example - checking the system calls
#gcc uname.c -l seccomp && ./a.out

# system calls used by application
#strace -c ./a.out

# Disable the uname syscall by seccomp
gcc dis_uname.c -l seccomp && ./a.out

#strace ./a.out 2>&1 | tail -3

