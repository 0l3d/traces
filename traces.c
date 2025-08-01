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
  type args[6];
} s_entry;
s_entry syscall_table[] = {
    {0, "read", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {1, "write", {TYPE_INT, TYPE_STR, TYPE_INT}},
    {2, "open", {TYPE_STR, TYPE_INT, TYPE_INT}},
    {3, "close", {TYPE_INT}},
    {4, "stat", {TYPE_STR, TYPE_PTR}},
    {5, "fstat", {TYPE_INT, TYPE_PTR}},
    {6, "lstat", {TYPE_STR, TYPE_PTR}},
    {7, "poll", {TYPE_PTR, TYPE_INT, TYPE_INT}},
    {8, "lseek", {TYPE_INT, TYPE_INT, TYPE_INT}},
    {9, "mmap", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT}},
    {10, "mprotect", {TYPE_PTR, TYPE_INT, TYPE_INT}},
    {11, "munmap", {TYPE_PTR, TYPE_INT}},
    {12, "brk", {TYPE_PTR}},
    {13, "rt_sigaction", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {14, "rt_sigprocmask", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {15, "rt_sigreturn", {}},
    {16, "ioctl", {TYPE_INT, TYPE_INT, TYPE_PTR}},
    {17, "pread64", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {18, "pwrite64", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT}},
    {19, "readv", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {20, "writev", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {21, "access", {TYPE_STR, TYPE_INT}},
    {22, "pipe", {TYPE_PTR}},
    {23, "select", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_PTR}},
    {24, "sched_yield", {}},
    {25, "mremap", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {26, "msync", {TYPE_PTR, TYPE_INT, TYPE_INT}},
    {27, "mincore", {TYPE_PTR, TYPE_INT, TYPE_PTR}},
    {28, "madvise", {TYPE_PTR, TYPE_INT, TYPE_INT}},
    {29, "shmget", {TYPE_INT, TYPE_INT, TYPE_INT}},
    {30, "shmat", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {31, "shmctl", {TYPE_INT, TYPE_INT, TYPE_PTR}},
    {32, "dup", {TYPE_INT}},
    {33, "dup2", {TYPE_INT, TYPE_INT}},
    {34, "pause", {}},
    {35, "nanosleep", {TYPE_PTR, TYPE_PTR}},
    {36, "getitimer", {TYPE_INT, TYPE_PTR}},
    {37, "alarm", {TYPE_INT}},
    {38, "setitimer", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {39, "getpid", {}},
    {40, "sendfile", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT}},
    {41, "socket", {TYPE_INT, TYPE_INT, TYPE_INT}},
    {42, "connect", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {43, "accept", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {44,
     "sendto",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT}},
    {45,
     "recvfrom",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {46, "sendmsg", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {47, "recvmsg", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {48, "shutdown", {TYPE_INT, TYPE_INT}},
    {49, "bind", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {50, "listen", {TYPE_INT, TYPE_INT}},
    {51, "getsockname", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {52, "getpeername", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {53, "socketpair", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {54, "setsockopt", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT}},
    {55, "getsockopt", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {56, "clone", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_INT}},
    {57, "fork", {}},
    {58, "vfork", {}},
    {59, "execve", {TYPE_STR, TYPE_PTR, TYPE_PTR}},
    {60, "exit", {TYPE_INT}},
    {61, "wait4", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR}},
    {62, "kill", {TYPE_INT, TYPE_INT}},
    {63, "uname", {TYPE_PTR}},
    {64, "semget", {TYPE_INT, TYPE_INT, TYPE_INT}},
    {65, "semop", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {66, "semctl", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {67, "shmdt", {TYPE_PTR}},
    {68, "msgget", {TYPE_INT, TYPE_INT}},
    {69, "msgsnd", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {70, "msgrcv", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT}},
    {71, "msgctl", {TYPE_INT, TYPE_INT, TYPE_PTR}},
    {72, "fcntl", {TYPE_INT, TYPE_INT, TYPE_PTR}},
    {73, "flock", {TYPE_INT, TYPE_INT}},
    {74, "fsync", {TYPE_INT}},
    {75, "fdatasync", {TYPE_INT}},
    {76, "truncate", {TYPE_STR, TYPE_INT}},
    {77, "ftruncate", {TYPE_INT, TYPE_INT}},
    {78, "getdents", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {79, "getcwd", {TYPE_PTR, TYPE_INT}},
    {80, "chdir", {TYPE_STR}},
    {81, "fchdir", {TYPE_INT}},
    {82, "rename", {TYPE_STR, TYPE_STR}},
    {83, "mkdir", {TYPE_STR, TYPE_INT}},
    {84, "rmdir", {TYPE_STR}},
    {85, "creat", {TYPE_STR, TYPE_INT}},
    {86, "link", {TYPE_STR, TYPE_STR}},
    {87, "unlink", {TYPE_STR}},
    {88, "symlink", {TYPE_STR, TYPE_STR}},
    {89, "readlink", {TYPE_STR, TYPE_PTR, TYPE_INT}},
    {90, "chmod", {TYPE_STR, TYPE_INT}},
    {91, "fchmod", {TYPE_INT, TYPE_INT}},
    {92, "chown", {TYPE_STR, TYPE_INT, TYPE_INT}},
    {93, "fchown", {TYPE_INT, TYPE_INT, TYPE_INT}},
    {94, "lchown", {TYPE_STR, TYPE_INT, TYPE_INT}},
    {95, "umask", {TYPE_INT}},
    {96, "gettimeofday", {TYPE_PTR, TYPE_PTR}},
    {97, "getrlimit", {TYPE_INT, TYPE_PTR}},
    {98, "getrusage", {TYPE_INT, TYPE_PTR}},
    {99, "sysinfo", {TYPE_PTR}},
    {100, "times", {TYPE_PTR}},
    {104, "set_tid_address", {TYPE_PTR}},
    {157, "arch_prctl", {TYPE_INT, TYPE_PTR}},
    {158, "adjtimex", {TYPE_PTR}},
    {159, "setrlimit", {TYPE_INT, TYPE_PTR}},
    {160, "chroot", {TYPE_STR}},
    {162, "sync", {}},
    {165, "getpriority", {TYPE_INT, TYPE_INT}},
    {168, "poll", {TYPE_PTR, TYPE_INT, TYPE_INT}},
    {171, "sysfs", {TYPE_INT, TYPE_STR, TYPE_INT}},
    {175, "mq_open", {TYPE_STR, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {176, "mq_unlink", {TYPE_STR}},
    {177, "mq_timedsend", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {178,
     "mq_timedreceive",
     {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {179, "mq_notify", {TYPE_INT, TYPE_PTR}},
    {180, "mq_getsetattr", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {181, "kexec_load", {TYPE_INT, TYPE_INT, TYPE_PTR}},
    {186, "waitid", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR}},
    {187, "add_key", {TYPE_STR, TYPE_STR, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {188, "request_key", {TYPE_STR, TYPE_STR, TYPE_STR, TYPE_INT}},
    {189, "keyctl", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT}},
    {191, "ioprio_set", {TYPE_INT, TYPE_INT, TYPE_INT}},
    {192, "ioprio_get", {TYPE_INT, TYPE_INT}},
    {193, "inotify_init", {}},
    {194, "inotify_add_watch", {TYPE_INT, TYPE_STR, TYPE_INT}},
    {195, "inotify_rm_watch", {TYPE_INT, TYPE_INT}},
    {197, "openat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT}},
    {198, "mkdirat", {TYPE_INT, TYPE_STR, TYPE_INT}},
    {199, "mknodat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT}},
    {200, "fchownat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_INT}},
    {201, "futimesat", {TYPE_INT, TYPE_STR, TYPE_PTR}},
    {202, "newfstatat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_INT}},
    {203, "unlinkat", {TYPE_INT, TYPE_STR, TYPE_INT}},
    {204, "renameat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_STR}},
    {205, "linkat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_STR, TYPE_INT}},
    {206, "symlinkat", {TYPE_STR, TYPE_INT, TYPE_STR}},
    {207, "readlinkat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_INT}},
    {208, "fchmodat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT}},
    {209, "faccessat", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT}},
    {210,
     "pselect6",
     {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_PTR, TYPE_PTR}},
    {211, "ppoll", {TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_INT}},
    {212, "unshare", {TYPE_INT}},
    {213, "set_robust_list", {TYPE_PTR, TYPE_INT}},
    {214, "get_robust_list", {TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {215,
     "splice",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {216, "tee", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT}},
    {217, "sync_file_range", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT}},
    {218, "vmsplice", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {219,
     "move_pages",
     {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {220, "utimensat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_INT}},
    {221, "epoll_pwait", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {222, "signalfd", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {223, "timerfd_create", {TYPE_INT, TYPE_INT}},
    {224, "eventfd", {TYPE_INT}},
    {225, "fallocate", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT}},
    {226, "timerfd_settime", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {227, "timerfd_gettime", {TYPE_INT, TYPE_PTR}},
    {228, "accept4", {TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_INT}},
    {229, "signalfd4", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {230, "eventfd2", {TYPE_INT, TYPE_INT}},
    {231, "epoll_create1", {TYPE_INT}},
    {232, "dup3", {TYPE_INT, TYPE_INT, TYPE_INT}},
    {233, "pipe2", {TYPE_PTR, TYPE_INT}},
    {234, "inotify_init1", {TYPE_INT}},
    {235, "preadv", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {236, "pwritev", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {237, "rt_tgsigqueueinfo", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {238,
     "perf_event_open",
     {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT}},
    {239, "recvmmsg", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {240, "fanotify_init", {TYPE_INT, TYPE_INT}},
    {241, "fanotify_mark", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_STR}},
    {242, "prlimit64", {TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR}},
    {243,
     "name_to_handle_at",
     {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_PTR, TYPE_INT}},
    {244, "open_by_handle_at", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {245, "clock_adjtime", {TYPE_INT, TYPE_PTR}},
    {246, "syncfs", {TYPE_INT}},
    {247, "sendmmsg", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {248, "setns", {TYPE_INT, TYPE_INT}},
    {249, "getcpu", {TYPE_PTR, TYPE_PTR, TYPE_PTR}},
    {250,
     "process_vm_readv",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {251,
     "process_vm_writev",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {252, "kcmp", {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT, TYPE_INT}},
    {253, "finit_module", {TYPE_INT, TYPE_STR, TYPE_INT}},
    {254, "sched_setattr", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {255, "sched_getattr", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {256, "renameat2", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_STR, TYPE_INT}},
    {257, "seccomp", {TYPE_INT, TYPE_INT, TYPE_PTR}},
    {258, "getrandom", {TYPE_PTR, TYPE_INT, TYPE_INT}},
    {259, "memfd_create", {TYPE_STR, TYPE_INT}},
    {260,
     "kexec_file_load",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_STR, TYPE_INT}},
    {261, "bpf", {TYPE_INT, TYPE_PTR, TYPE_INT}},
    {262, "execveat", {TYPE_INT, TYPE_STR, TYPE_PTR, TYPE_PTR, TYPE_INT}},
    {263, "userfaultfd", {TYPE_INT}},
    {264, "membarrier", {TYPE_INT, TYPE_INT}},
    {265, "mlock2", {TYPE_PTR, TYPE_INT, TYPE_INT}},
    {266,
     "copy_file_range",
     {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT}},
    {267, "preadv2", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT}},
    {268, "pwritev2", {TYPE_INT, TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT}},
    {269, "pkey_mprotect", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT}},
    {270, "pkey_alloc", {TYPE_INT, TYPE_INT}},
    {271, "pkey_free", {TYPE_INT}},
    {272, "statx", {TYPE_INT, TYPE_STR, TYPE_INT, TYPE_INT, TYPE_PTR}},
    {273,
     "io_pgetevents",
     {TYPE_INT, TYPE_INT, TYPE_INT, TYPE_PTR, TYPE_PTR, TYPE_PTR}},
    {274, "rseq", {TYPE_PTR, TYPE_INT, TYPE_INT, TYPE_INT}},
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
          for (int i = 0; i < 6; ++i) {
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
