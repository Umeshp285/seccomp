#include <stddef.h>
#include <features.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <unistd.h>
#include <time.h>
#include <netdb.h>
#include <alloca.h>
#include <signal.h>
#include <errno.h>

#include <sys/prctl.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
# define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
# define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
# define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};
#endif
#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#define syscall_nr (offsetof(struct seccomp_data, nr))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#else
# error "Platform does not support seccomp filter yet"
#endif

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

static int install_syscall_filter(void) {
  /* Linux allows a process to restrict itself (and potential children)
   * in what syscalls can be issued.  The mechanism is called
   * seccomp-filter or "seccomp mode 2".  It works by reusing the
   * Berkeley Packet Filter, which is meant for PCAP-style packet
   * filtering expressions like "only TCP packets, please".  But it is
   * really a bytecode that has to be passed inside an array, and each
   * instruction is constructed using scary looking macros.  The basics
   * are not so bad, however.  We have two registers, one accumulator
   * and one index register (which is not used in this part of the
   * code), and instead of a network packet we are operating on a
   * certain struct with the syscall info, which is called seccomp_data
   * (reproduced above). */
  struct sock_filter filter[] = {
    /* validate architecture to avoid x32-on-x86_64 syscall aliasing shenanigans */

    /* BPF_LD = load, BPF_W = word, BPF_ABS = absolute offset */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
    /* BPF_JMP+BPF_JEQ+BPF_K = compare accumulator to constant (in our
     * case, ARCH_NR), and skip the next instruction if equal */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
    /* "return SECCOMP_RET_KILL", tell seccomp to kill the process */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

    /* load the syscall number */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* and now a list of allowed syscalls */
    ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
    ALLOW_SYSCALL(sigreturn),
#endif
    ALLOW_SYSCALL(exit_group),
    ALLOW_SYSCALL(exit),

#ifdef __NR_socketcall
    ALLOW_SYSCALL(socketcall),
#else
    ALLOW_SYSCALL(socket),
    ALLOW_SYSCALL(sendto),
    ALLOW_SYSCALL(recvfrom),
#endif

    ALLOW_SYSCALL(poll),

    /* so we can further restrict allowed syscalls */
    ALLOW_SYSCALL(prctl),

    /* so gethostbyname can open /etc/resolv.conf */
    ALLOW_SYSCALL(open),
    ALLOW_SYSCALL(read),
    ALLOW_SYSCALL(mmap),
#ifdef __NR_mmap2
    ALLOW_SYSCALL(mmap2),
#endif
    ALLOW_SYSCALL(munmap),
    ALLOW_SYSCALL(lseek),
#ifdef __NR__llseek
    ALLOW_SYSCALL(_llseek),
#endif
    ALLOW_SYSCALL(close),

    /* for our time keeping */
    ALLOW_SYSCALL(gettimeofday),	// x86_64 uses a vsyscall for this, so this filter will never trigger

    /* for when buffer writes the output; since we only write to stdout, filter for fd==1 */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_write, 0, 4),
    /* it's write(2).  Load first argument into accumulator */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, args[0])),
    /* if it's 1 (stdout), skip 1 instruction */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 1, 0),
    /* "return SECCOMP_RET_KILL", tell seccomp to kill the process */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
    /* "return SECCOMP_RET_ALLOW", tell seccomp to allow the syscall */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),

    /* if none of these syscalls matched, kill the process */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter
  };

  /* see linux/Documentation/prctl/no_new_privs.txt */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    /* if this fails, we are running on an ancient kernel without
     * seccomp support; nothing we can do about it, really. */
    return -1;
  }

  /* see linux/Documentation/prctl/seccomp_filter.txt */
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    /* if this happens, we are running on a kernel without seccomp
     * filters support; nothing we can do about it, really. */
    return -1;
  }
  return 0;
}

#define DISALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

static int seccomp_denyfile() {
  struct sock_filter filter[] = {
    DISALLOW_SYSCALL(open),
    DISALLOW_SYSCALL(mmap),
#ifdef __NR_mmap2
    DISALLOW_SYSCALL(mmap2),
#endif
    DISALLOW_SYSCALL(munmap),
    DISALLOW_SYSCALL(lseek),
#ifdef __NR__llseek
    DISALLOW_SYSCALL(_llseek),
#endif
    DISALLOW_SYSCALL(close),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter
  };
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

static int seccomp_denysocket() {
  struct sock_filter filter[] = {
#ifndef __NR_socketcall
    DISALLOW_SYSCALL(setsockopt),
    DISALLOW_SYSCALL(socket),
#endif
    DISALLOW_SYSCALL(prctl),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter
  };
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main(int argc,char* argv[]) {
  /* If it fails, the kernel does not support seccomp filter.
   * We'll just continue */
  install_syscall_filter();

  seccomp_denyfile();

  seccomp_denysocket();
  seccomp_denysocket();	/* should kill the process, but doesn't */

  return 0;
}

