#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

typedef enum {
  TYPE_INT,
  TYPE_STR,
  TYPE_PTR,
  TYPE_NULL,
} type;

typedef struct {
  long num;
  const char *name;
  type args[7];
} s_entry;
s_entry syscall_table[] = {
    {0, "read", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {1, "write", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {2, "open", {TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {3, "close", {TYPE_INT, TYPE_NULL}},
    {4, "stat", {TYPE_STR, TYPE_PTR, TYPE_NULL}},
    {5, "fstat", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {6, "lstat", {TYPE_STR, TYPE_PTR, TYPE_NULL}},
    {7, "poll", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {8, "lseek", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {9,
     "mmap",
     {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {10, "mprotect", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {11, "munmap", {TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {12, "brk", {TYPE_PTR, TYPE_NULL}},
    {13, "rt_sigaction", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {14, "rt_sigprocmask", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {15, "rt_sigreturn", {TYPE_NULL}},
    {16, "ioctl", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {17, "pread64", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {18, "pwrite64", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {19, "readv", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {20, "writev", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {21, "access", {TYPE_STR, TYPE_INT, TYPE_NULL}},
    {22, "pipe", {TYPE_PTR, TYPE_NULL}},
    {23,
     "select",
     {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {24, "sched_yield", {TYPE_NULL}},
    {25,
     "mremap",
     {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {26, "msync", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {27, "mincore", {TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {28, "madvise", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {29, "shmget", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {30, "shmat", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {31, "shmctl", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {32, "dup", {TYPE_INT, TYPE_NULL}},
    {33, "dup2", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {34, "pause", {TYPE_NULL}},
    {35, "nanosleep", {TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {36, "getitimer", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {37, "alarm", {TYPE_INT, TYPE_NULL}},
    {38, "setitimer", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {39, "getpid", {TYPE_NULL}},
    {40, "sendfile", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {41, "socket", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {42, "connect", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {43, "accept", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {44,
     "sendto",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {45,
     "recvfrom",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {46, "sendmsg", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {47, "recvmsg", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {48, "shutdown", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {49, "bind", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {50, "listen", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {51, "getsockname", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {52, "getpeername", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {53, "socketpair", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {54,
     "setsockopt",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {55,
     "getsockopt",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {56,
     "clone",
     {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {57, "fork", {TYPE_NULL}},
    {58, "vfork", {TYPE_NULL}},
    {59, "execve", {TYPE_STR, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {60, "exit", {TYPE_INT, TYPE_NULL}},
    {61, "wait4", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {62, "kill", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {63, "uname", {TYPE_PTR, TYPE_NULL}},
    {64, "semget", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {65, "semop", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {66, "semctl", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {67, "shmdt", {TYPE_PTR, TYPE_NULL}},
    {68, "msgget", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {69, "msgsnd", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {70,
     "msgrcv",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {71, "msgctl", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {72, "fcntl", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {73, "flock", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {74, "fsync", {TYPE_INT, TYPE_NULL}},
    {75, "fdatasync", {TYPE_INT, TYPE_NULL}},
    {76, "truncate", {TYPE_STR, TYPE_INT, TYPE_NULL}},
    {77, "ftruncate", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {78, "getdents", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {79, "getcwd", {TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {80, "chdir", {TYPE_STR, TYPE_NULL}},
    {81, "fchdir", {TYPE_INT, TYPE_NULL}},
    {82, "rename", {TYPE_STR, TYPE_STR, TYPE_NULL}},
    {83, "mkdir", {TYPE_STR, TYPE_INT, TYPE_NULL}},
    {84, "rmdir", {TYPE_STR, TYPE_NULL}},
    {85, "creat", {TYPE_STR, TYPE_INT, TYPE_NULL}},
    {86, "link", {TYPE_STR, TYPE_STR, TYPE_NULL}},
    {87, "unlink", {TYPE_STR, TYPE_NULL}},
    {88, "symlink", {TYPE_STR, TYPE_STR, TYPE_NULL}},
    {89, "readlink", {TYPE_STR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {90, "chmod", {TYPE_STR, TYPE_INT, TYPE_NULL}},
    {91, "fchmod", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {92, "chown", {TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {93, "fchown", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {94, "lchown", {TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {95, "umask", {TYPE_INT, TYPE_NULL}},
    {96, "gettimeofday", {TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {97, "getrlimit", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {98, "getrusage", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {99, "sysinfo", {TYPE_PTR, TYPE_NULL}},
    {100, "times", {TYPE_PTR, TYPE_NULL}},
    {104, "set_tid_address", {TYPE_PTR, TYPE_NULL}},
    {157, "arch_prctl", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {158, "adjtimex", {TYPE_PTR, TYPE_NULL}},
    {159, "setrlimit", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {160, "chroot", {TYPE_STR, TYPE_NULL}},
    {162, "sync", {TYPE_NULL}},
    {165, "getpriority", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {168, "poll", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {171, "sysfs", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {175, "mq_open", {TYPE_STR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {176, "mq_unlink", {TYPE_STR, TYPE_NULL}},
    {177,
     "mq_timedsend",
     {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {178,
     "mq_timedreceive",
     {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {179, "mq_notify", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {180, "mq_getsetattr", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {181, "kexec_load", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {186,
     "waitid",
     {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {187,
     "add_key",
     {TYPE_STR, TYPE_STR, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {188, "request_key", {TYPE_STR, TYPE_STR, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {189,
     "keyctl",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {191, "ioprio_set", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {192, "ioprio_get", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {193, "inotify_init", {TYPE_NULL}},
    {194, "inotify_add_watch", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {195, "inotify_rm_watch", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {197, "openat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {198, "mkdirat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {199, "mknodat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {200,
     "fchownat",
     {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {201, "futimesat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_NULL}},
    {202, "newfstatat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {203, "unlinkat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {204, "renameat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_STR, TYPE_NULL}},
    {205,
     "linkat",
     {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {206, "symlinkat", {TYPE_STR, TYPE_INT, TYPE_STR, TYPE_NULL}},
    {207, "readlinkat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {208, "fchmodat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {209, "faccessat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {210,
     "pselect6",
     {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {211,
     "ppoll",
     {TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {212, "unshare", {TYPE_INT, TYPE_NULL}},
    {213, "set_robust_list", {TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {214, "get_robust_list", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {215,
     "splice",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {216, "tee", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {217,
     "sync_file_range",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {218, "vmsplice", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {219,
     "move_pages",
     {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {220, "utimensat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {221,
     "epoll_pwait",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {222, "signalfd", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {223, "timerfd_create", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {224, "eventfd", {TYPE_INT, TYPE_NULL}},
    {225, "fallocate", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {226,
     "timerfd_settime",
     {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {227, "timerfd_gettime", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {228, "accept4", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {229, "signalfd4", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {230, "eventfd2", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {231, "epoll_create1", {TYPE_INT, TYPE_NULL}},
    {232, "dup3", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {233, "pipe2", {TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {234, "inotify_init1", {TYPE_INT, TYPE_NULL}},
    {235, "preadv", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {236, "pwritev", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {237,
     "rt_tgsigqueueinfo",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {238,
     "perf_event_open",
     {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {239,
     "recvmmsg",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {240, "fanotify_init", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {241,
     "fanotify_mark",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_STR, TYPE_NULL}},
    {242, "prlimit64", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {243,
     "name_to_handle_at",
     {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {244, "open_by_handle_at", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {245, "clock_adjtime", {TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {246, "syncfs", {TYPE_INT, TYPE_NULL}},
    {247, "sendmmsg", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {248, "setns", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {249, "getcpu", {TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {250,
     "process_vm_readv",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {251,
     "process_vm_writev",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {252,
     "kcmp",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {253, "finit_module", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {254, "sched_setattr", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {255, "sched_getattr", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {256,
     "renameat2",
     {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {257, "seccomp", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {258, "getrandom", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {259, "memfd_create", {TYPE_STR, TYPE_INT, TYPE_NULL}},
    {260,
     "kexec_file_load",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_STR, TYPE_INT, TYPE_NULL}},
    {261, "bpf", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {262,
     "execveat",
     {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_PTR, TYPE_INT, TYPE_NULL}},
    {263, "userfaultfd", {TYPE_INT, TYPE_NULL}},
    {264, "membarrier", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {265, "mlock2", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {266,
     "copy_file_range",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {267,
     "preadv2",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {268,
     "pwritev2",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {269, "pkey_mprotect", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
    {270, "pkey_alloc", {TYPE_INT, TYPE_INT, TYPE_NULL}},
    {271, "pkey_free", {TYPE_INT, TYPE_NULL}},
    {272,
     "statx",
     {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_NULL}},
    {273,
     "io_pgetevents",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_NULL}},
    {274, "rseq", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_NULL}},
};
void get_string(pid_t pid, unsigned long addr, char *buf, size_t max_len) {
  size_t i = 0;
  union {
    long val;
    char chars[sizeof(long)];
  } data;

  while (i < max_len) {
    errno = 0;
    data.val = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
    if (errno != 0)
      break;

    for (int j = 0; j < sizeof(long) && i < max_len; ++j, ++i) {
      buf[i] = data.chars[j];
      if (data.chars[j] == '\0')
        return;
    }
  }
  buf[max_len - 1] = '\0';
}

void print_arg(pid_t pid, unsigned long val, type t) {
  if (t == TYPE_INT) {
    printf("%ld", val);
  } else if (t == TYPE_STR) {
    char str[256];
    get_string(pid, val, str, sizeof(str));
    printf("\"");
    for (int i = 0; str[i] != '\0'; i++) {
      unsigned char c = str[i];
      switch (c) {
      case '\n':
        printf("\\n");
        break;
      case '\t':
        printf("\\t");
        break;
      case '\r':
        printf("\\r");
        break;
      case '\\':
        printf("\\\\");
        break;
      case '\"':
        printf("\\\"");
        break;
      default:
        if (c < 32 || c > 126) {
          printf("\\x%02x", c);
        } else {
          putchar(c);
        }
        break;
      }
    }
    printf("\"");
  } else {
    printf("0x%lx", val);
  }
}

s_entry *get_syscall(long snum) {
  for (size_t i = 0; i < sizeof(syscall_table) / sizeof(s_entry); ++i) {
    if (syscall_table[i].num == snum) {
      return &syscall_table[i];
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program>\n", argv[0]);
    return 1;
  }

  pid_t pid = fork();
  if (pid == -1) {
    perror("fork failed");
    return -1;
  }

  if (pid == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve(argv[1], argv + 1, NULL);
    perror("execlp failed");
    _exit(1);
  } else {
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

    int in_syscall = 0;
    struct user_regs_struct regs;
    const char *name = NULL;
    long ret;
    s_entry *entry = NULL;

    while (1) {
      waitpid(pid, &status, 0);
      if (WIFEXITED(status))
        break;

      ptrace(PTRACE_GETREGS, pid, NULL, &regs);

      if (!in_syscall) {
        entry = get_syscall(regs.orig_rax);
        if (entry) {

          printf("\n\x1b[32mregs: rdi=%llx rsi=%llx rdx=%llx r10=%llx r8=%llx "
                 "r9=%llx\n\x1b[0m",
                 regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
          printf("\x1b[91m%s(", entry->name);
          unsigned long args[] = {regs.rdi, regs.rsi, regs.rdx,
                                  regs.r10, regs.r8,  regs.r9};
          for (int i = 0; i < 7; ++i) {
            if (entry->args[i] == TYPE_NULL)
              break;
            if (i > 0)
              printf(", ");
            print_arg(pid, args[i], entry->args[i]);
          }
          fflush(stdout);
        }
        in_syscall = 1;
      } else {
        if (entry) {
          printf(") = %lld\n\x1b[0m", regs.rax);
        }
        in_syscall = 0;
      }
      ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }
  }

  return 0;
}
