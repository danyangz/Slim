#ifndef _SLIM_KERN_SYSCALL_INTERCEPT_
#define _SLIM_KERN_SYSCALL_INTERCEPT_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#else
#include <linux/signal.h>
#endif

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/filter.h>

#include <linux/hashtable.h>
#include <linux/tracepoint.h>
#include <trace/events/sched.h>

struct FilterEntry {
    pid_t pid;
    uintptr_t files;
    int num_fds;
    int *fds;
    struct hlist_node hash_list ;
};

// syscalls
extern void *sys_fork_ptr;
extern void *sys_clone_ptr;
extern void *sys_vfork_ptr;

extern void *sys_getsockname_ptr;
extern void *sys_getpeername_ptr;
extern void *sys_connect_ptr;
extern void *sys_bind_ptr;
extern void *sys_dup_ptr;
extern void *sys_dup2_ptr;
extern void *sys_dup3_ptr;

extern void *sys_exit_ptr;
extern void *sys_close_ptr;

unsigned long **acquire_syscall_table(void);

asmlinkage long my_fork(void);
asmlinkage long my_vfork(void);
#ifdef CONFIG_CLONE_BACKWARDS
asmlinkage long my_clone(unsigned long, unsigned long, int __user *, int,
	       int __user *);
#else
#ifdef CONFIG_CLONE_BACKWARDS3
asmlinkage long my_clone(unsigned long, unsigned long, int, int __user *,
			  int __user *, int);
#else
asmlinkage long my_clone(unsigned long, unsigned long, int __user *,
	       int __user *, int);
#endif
#endif

asmlinkage long my_getsockname(int, struct sockaddr __user *, int __user *);
asmlinkage long my_getpeername(int, struct sockaddr __user *, int __user *);
asmlinkage long my_connect(int, struct sockaddr __user *, int);
asmlinkage long my_bind(int, struct sockaddr __user *, int);
asmlinkage long my_dup(unsigned int fildes);
asmlinkage long my_dup2(unsigned int oldfd, unsigned int newfd);
asmlinkage long my_dup3(unsigned int oldfd, unsigned int newfd, int flags);

asmlinkage long my_close(unsigned int fd);
asmlinkage long my_exit(int error_code);

void start_intercept(void);
void stop_intercept(void);

int blacklist_contains(pid_t pid, int fd);
int add_blacklist_fd(pid_t pid, int fd);
int remove_blacklist_fd(pid_t pid, int fd);
int remove_pid(pid_t pid);

#endif /* _SLIM_KERN_SYSCALL_INTERCEPT_ */
