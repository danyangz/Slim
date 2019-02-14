#include "syscall_intercept.h"

DEFINE_HASHTABLE(filter_entries, 16);

#define STORE_SYSCALLPTR(table, name) sys_ ## name ## _ptr = (void *)table[__NR_ ## name]
#define REPLACE_SYSCALL(table, name) table[__NR_ ## name] = (void *)my_ ## name
#define RECOVER_SYSCALLPTR(table, name) table[__NR_ ## name] = sys_ ## name ## _ptr

rwlock_t map_lock;

void *sys_fork_ptr = NULL;
void *sys_clone_ptr = NULL;
void *sys_vfork_ptr = NULL;

void *sys_getsockname_ptr = NULL;
void *sys_getpeername_ptr = NULL;
void *sys_connect_ptr = NULL;
void *sys_bind_ptr = NULL;
void *sys_dup_ptr = NULL;
void *sys_dup2_ptr = NULL;
void *sys_dup3_ptr = NULL;

void *sys_close_ptr = NULL;
void *sys_exit_ptr = NULL;

unsigned long **acquire_syscall_table(void)
{
    return (unsigned long **)kallsyms_lookup_name("sys_call_table");
}

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	pte->pte = pte->pte &~_PAGE_RW;

}

void clone_trace(void *data, struct task_struct *self, struct task_struct *target);

void task_free_trace(void *data, struct task_struct *self);

void start_intercept(void) {
    unsigned long **syscall_table = acquire_syscall_table();
    void *ptr = (void *)kallsyms_lookup_name("__tracepoint_sched_process_fork");
    if (!ptr) {
	printk(KERN_ERR "unable to locate tracepoint");
    }
    tracepoint_probe_register(ptr, clone_trace, NULL);
    
    ptr = (void *)kallsyms_lookup_name("__tracepoint_sched_process_free");
    if (!ptr) {
	printk(KERN_ERR "unable to locate tracepoint");
    }
    tracepoint_probe_register(ptr, task_free_trace, NULL);
    
    printk(KERN_INFO "tracepoint: 0x%p\n", ptr);
    rwlock_init(&map_lock);
    //disable_page_protection();
    set_addr_rw((unsigned long)syscall_table);
    
    STORE_SYSCALLPTR(syscall_table, getsockname);
    STORE_SYSCALLPTR(syscall_table, getpeername);
    STORE_SYSCALLPTR(syscall_table, connect);
    STORE_SYSCALLPTR(syscall_table, bind);
    STORE_SYSCALLPTR(syscall_table, dup);
    STORE_SYSCALLPTR(syscall_table, dup2);
    STORE_SYSCALLPTR(syscall_table, dup3);

    STORE_SYSCALLPTR(syscall_table, close);
    STORE_SYSCALLPTR(syscall_table, exit);

    // now replace the syscall
    REPLACE_SYSCALL(syscall_table, getsockname);
    REPLACE_SYSCALL(syscall_table, getpeername);
    REPLACE_SYSCALL(syscall_table, connect);
    REPLACE_SYSCALL(syscall_table, bind);
    REPLACE_SYSCALL(syscall_table, dup);
    REPLACE_SYSCALL(syscall_table, dup2);
    REPLACE_SYSCALL(syscall_table, dup3);

    REPLACE_SYSCALL(syscall_table, close);
    REPLACE_SYSCALL(syscall_table, exit);

    printk(KERN_INFO "starting intercept\n");
    
    //enable_page_protection();
    set_addr_ro((unsigned long)syscall_table);
}

void stop_intercept(void) {
    void **syscall_table = (void **)acquire_syscall_table();
    //disable_page_protection();
    void *ptr = (void *)kallsyms_lookup_name("__tracepoint_sched_process_free");
    tracepoint_probe_unregister(ptr, task_free_trace, NULL);
    ptr = (void *)kallsyms_lookup_name("__tracepoint_sched_process_fork");
    tracepoint_probe_unregister(ptr, clone_trace, NULL);
    tracepoint_synchronize_unregister();
    set_addr_rw((unsigned long)syscall_table);

    RECOVER_SYSCALLPTR(syscall_table, getsockname);
    RECOVER_SYSCALLPTR(syscall_table, getpeername);
    RECOVER_SYSCALLPTR(syscall_table, connect);
    RECOVER_SYSCALLPTR(syscall_table, bind);
    RECOVER_SYSCALLPTR(syscall_table, dup);
    RECOVER_SYSCALLPTR(syscall_table, dup2);
    RECOVER_SYSCALLPTR(syscall_table, dup3);

    RECOVER_SYSCALLPTR(syscall_table, close);
    RECOVER_SYSCALLPTR(syscall_table, exit);
    
    //enable_page_protection();
    set_addr_ro((unsigned long)syscall_table);
}

void free_filterentry(struct FilterEntry *ptr) {
    if (ptr->fds != NULL) {
	kfree(ptr->fds);
    }
    kfree(ptr);
}

struct FilterEntry *copy_filterentry(struct FilterEntry *ptr) {
    struct FilterEntry *res;
    int i;
    if (!ptr) {
	goto fail;
    }
    res = kmalloc(sizeof(struct FilterEntry), GFP_KERNEL);
    if (!res) {
	goto fail;
    }
    res->pid = ptr->pid;
    res->files = ptr->files;
    res->num_fds = ptr->num_fds;
    res->fds = kmalloc(sizeof(int) * ptr->num_fds, GFP_KERNEL);
    if (!res->fds) {
	goto fail2;
    }

    for (i = 0; i < res->num_fds; i++) {
	res->fds[i] = ptr->fds[i];
    }

    return res;
 fail2:
    kfree(res);
 fail:
    return NULL;
}

int blacklist_contains(pid_t pid, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    struct task_struct *task = NULL;
    uintptr_t files = NULL;
    int i;
    int found = 0;
    read_lock_irq(&map_lock);
    
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task == NULL) {
	return -1;
    }
    files = (uintptr_t)(task->files);

    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }

    if (hit != NULL) {
	for (i = 0; i < hit->num_fds; i++) {
	    if (hit->fds[i] == fd) {
		found = 1;
		break;
	    }
	}
    }
    
    read_unlock_irq(&map_lock);
    return found;
}

int add_blacklist_fd(pid_t pid, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    struct task_struct *task = NULL;
    uintptr_t files = NULL;
    int *fds = NULL;
    int *old_fds = NULL;
    int i;
    write_lock_irq(&map_lock);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task == NULL) {
	return -1;
    }
    files = (uintptr_t)task->files;
    
    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }
    if (hit == NULL) {
	hit = kmalloc(sizeof(struct FilterEntry), GFP_KERNEL);
	if (!hit) {
	    goto fail;
	}
	hit->pid = pid;
        hit->files = files;
	hit->num_fds = 1;
	fds = kmalloc(sizeof(int) * hit->num_fds, GFP_KERNEL);
	if (!fds) {
	    goto fail;
	}
	fds[0] = fd;
	hit->fds = fds;
	hash_add(filter_entries, &(hit->hash_list), hit->files);
    } else {
	hit->num_fds += 1;
	fds = kmalloc(sizeof(int) * hit->num_fds, GFP_KERNEL);
	if (!fds) {
	    goto fail;
	}
	for (i = 0; i < hit->num_fds - 1; i++) {
	    fds[i] = hit->fds[i];
	}
	fds[hit->num_fds - 1] = fd;
	old_fds = hit->fds;
	hit->fds = fds;
	kfree(old_fds);
    }
    write_unlock_irq(&map_lock);
    return 0;
 fail:
    write_unlock_irq(&map_lock);
    return -1;
}

int add_blacklist_if_present(pid_t pid, int old_fd, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    struct task_struct *task = NULL;
    uintptr_t files = NULL;
    int *fds = NULL;
    int *old_fds = NULL;
    int found = 0;
    int i;
    write_lock_irq(&map_lock);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task == NULL) {
	return -1;
    }
    files = (uintptr_t)task->files;

    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }
    if (hit == NULL) {
	goto fail;
    } else {
	for (i = 0; i < hit->num_fds; i++) {
	    if (hit->fds[i] == old_fd) {
		found = 1;
		break;
	    }
	}
	if (!found) {
	    goto fail;
	}
	hit->num_fds += 1;
	fds = kmalloc(sizeof(int) * hit->num_fds, GFP_KERNEL);
	if (!fds) {
	    goto fail;
	}
	for (i = 0; i < hit->num_fds - 1; i++) {
	    fds[i] = hit->fds[i];
	}
	fds[hit->num_fds - 1] = fd;
	old_fds = hit->fds;
	hit->fds = fds;
	kfree(old_fds);
    }
    write_unlock_irq(&map_lock);
    return 0;
 fail:
    write_unlock_irq(&map_lock);
    return -1;
}

int remove_blacklist_fd(pid_t pid, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    struct task_struct *task = NULL;
    uintptr_t files = NULL;
    int i, last;
    write_lock_irq(&map_lock);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task == NULL) {
	return -1;
    }
    files = (uintptr_t)task->files;
    
    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }
    if (hit != NULL) {
	if (hit->num_fds <= 1) {
	    hit->num_fds = 0;
	} else {
	    last = hit->num_fds - 1;
	    int old_last = last;
	    for (i = 0; i <= last; i++) {
		while (i <= last && hit->fds[last] == fd) {
		    last--;
		}

		if (i > last) {
		    break;
		}

		if (hit->fds[i] == fd) {
		    hit->fds[i] = hit->fds[last];
		    last--;
		}
	    }
	    hit->num_fds = last + 1;
	    printk(KERN_INFO "removing: %d %d\n", old_last, last);
	}
    }
    write_unlock_irq(&map_lock);
    return 0;
}

// copy_pid assumes that the locking is done by caller
int copy_pid(pid_t old_pid, pid_t new_pid) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    struct task_struct *task = NULL;
    uintptr_t old_files;
    uintptr_t new_files;
    // first remove new_pid

    task = pid_task(find_vpid(old_pid), PIDTYPE_PID);
    if (task == NULL) {
	return -1;
    }
    old_files = (uintptr_t)task->files;
    task = pid_task(find_vpid(new_pid), PIDTYPE_PID);
    if (task == NULL) {
	return -1;
    }
    new_files = (uintptr_t)task->files;
    
    hash_for_each_possible(filter_entries, entry, hash_list, new_files) {
	if (entry->files == new_files) {
	    hit = entry;
	    break;
	}
    }

    if (hit != NULL) {
	hash_del(&hit->hash_list);
	free_filterentry(hit);
    }
    
    hash_for_each_possible(filter_entries, entry, hash_list, old_files) {
	if (entry->files == old_files) {
	    hit = entry;
	    break;
	}
    }
    if (hit != NULL) {
	entry = copy_filterentry(hit);
	if (!entry) {
	    return -1;
	}
	entry->pid = new_pid;
        entry->files = new_files;
	hash_add(filter_entries, &(entry->hash_list), entry->files);
    }
    return 0;
}

int blacklist_files_contains(struct task_struct *task, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    uintptr_t files = NULL;
    int i;
    int found = 0;
    read_lock_irq(&map_lock);
    
    files = (uintptr_t)(task->files);

    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }

    if (hit != NULL) {
	for (i = 0; i < hit->num_fds; i++) {
	    if (hit->fds[i] == fd) {
		found = 1;
		break;
	    }
	}
    }
    
    read_unlock_irq(&map_lock);
    return found;
}

int add_blacklist_files_fd(struct task_struct *task, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    uintptr_t files = 0;
    int *fds = NULL;
    int *old_fds = NULL;
    int i;
    write_lock_irq(&map_lock);

    files = (uintptr_t)task->files;
    
    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }
    if (hit == NULL) {
	hit = kmalloc(sizeof(struct FilterEntry), GFP_KERNEL);
	if (!hit) {
	    goto fail;
	}
        hit->files = files;
	hit->num_fds = 1;
	fds = kmalloc(sizeof(int) * hit->num_fds, GFP_KERNEL);
	if (!fds) {
	    goto fail;
	}
	fds[0] = fd;
	hit->fds = fds;
	hash_add(filter_entries, &(hit->hash_list), hit->files);
    } else {
	hit->num_fds += 1;
	fds = kmalloc(sizeof(int) * hit->num_fds, GFP_KERNEL);
	if (!fds) {
	    goto fail;
	}
	for (i = 0; i < hit->num_fds - 1; i++) {
	    fds[i] = hit->fds[i];
	}
	fds[hit->num_fds - 1] = fd;
	old_fds = hit->fds;
	hit->fds = fds;
	kfree(old_fds);
    }
    write_unlock_irq(&map_lock);
    return 0;
 fail:
    write_unlock_irq(&map_lock);
    return -1;
}

int add_blacklist_files_if_present(struct task_struct *task, int old_fd, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    uintptr_t files = NULL;
    int *fds = NULL;
    int *old_fds = NULL;
    int found = 0;
    int i;
    write_lock_irq(&map_lock);

    files = (uintptr_t)task->files;

    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }
    if (hit == NULL) {
	goto fail;
    } else {
	for (i = 0; i < hit->num_fds; i++) {
	    if (hit->fds[i] == old_fd) {
		found = 1;
		break;
	    }
	}
	if (!found) {
	    goto fail;
	}
	hit->num_fds += 1;
	fds = kmalloc(sizeof(int) * hit->num_fds, GFP_KERNEL);
	if (!fds) {
	    goto fail;
	}
	for (i = 0; i < hit->num_fds - 1; i++) {
	    fds[i] = hit->fds[i];
	}
	fds[hit->num_fds - 1] = fd;
	old_fds = hit->fds;
	hit->fds = fds;
	kfree(old_fds);
    }
    write_unlock_irq(&map_lock);
    return 0;
 fail:
    write_unlock_irq(&map_lock);
    return -1;
}

int remove_blacklist_files_fd(struct task_struct *task, int fd) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    uintptr_t files = NULL;
    int i, last;
    write_lock_irq(&map_lock);

    files = (uintptr_t)task->files;
    
    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    break;
	}
    }
    if (hit != NULL) {
	if (hit->num_fds <= 1) {
	    hit->num_fds = 0;
	} else {
	    last = hit->num_fds - 1;
	    int old_last = last;
	    for (i = 0; i <= last; i++) {
		while (i <= last && hit->fds[last] == fd) {
		    last--;
		}

		if (i > last) {
		    break;
		}

		if (hit->fds[i] == fd) {
		    hit->fds[i] = hit->fds[last];
		    last--;
		}
	    }
	    hit->num_fds = last + 1;
	    printk(KERN_INFO "removing: %d %d\n", old_last, last);
	}
    }
    write_unlock_irq(&map_lock);
    return 0;
}

// copy_pid assumes that the locking is done by caller
int copy_files(struct task_struct *old_task, struct task_struct *new_task) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    struct task_struct *task = NULL;
    uintptr_t old_files;
    uintptr_t new_files;
    // first remove new_pid

    old_files = (uintptr_t)old_task->files;
    new_files = (uintptr_t)new_task->files;
    
    hash_for_each_possible(filter_entries, entry, hash_list, new_files) {
	if (entry->files == new_files) {
	    hit = entry;
	    break;
	}
    }

    if (hit != NULL) {
	hash_del(&hit->hash_list);
	free_filterentry(hit);
    }
    
    hash_for_each_possible(filter_entries, entry, hash_list, old_files) {
	if (entry->files == old_files) {
	    hit = entry;
	    break;
	}
    }
    if (hit != NULL) {
	entry = copy_filterentry(hit);
	if (!entry) {
	    return -1;
	}
        entry->files = new_files;
	hash_add(filter_entries, &(entry->hash_list), entry->files);
    }
    return 0;
}

int remove_pid(pid_t pid) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    struct task_struct *task = NULL;
    uintptr_t files;
    write_lock_irq(&map_lock);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task == NULL) {
	return -1;
    }
    printk(KERN_ERR "got task_struct : %p\n", task);
    files = (uintptr_t)task->files;
    
    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    printk(KERN_ERR "Found struct files: %p for %d\n", (void *)files, pid);
	    break;
	}
    }

    if (hit != NULL) {
	hash_del(&hit->hash_list);
	free_filterentry(hit);
    }
    write_unlock_irq(&map_lock);
    return 0;
}

int remove_files(uintptr_t files) {
    struct FilterEntry *entry;
    struct FilterEntry *hit = NULL;
    write_lock_irq(&map_lock);
    
    hash_for_each_possible(filter_entries, entry, hash_list, files) {
	if (entry->files == files) {
	    hit = entry;
	    printk(KERN_ERR "Found struct files: %p\n", (void *)files);
	    break;
	}
    }

    if (hit != NULL) {
	hash_del(&hit->hash_list);
	free_filterentry(hit);
    }
    write_unlock_irq(&map_lock);
    return 0;
}

void clone_trace(void *data, struct task_struct *self, struct task_struct *target) {
    pid_t my_pid = task_pid_nr(self);
    pid_t child_pid = task_pid_nr(target);
    pid_t child_vpid = task_pid_vnr(target);
    //printk(KERN_INFO "copy_process: %d %d %d\n", my_pid, child_pid, child_vpid);
    write_lock_irq(&map_lock);
    copy_files(self, target);
    write_unlock_irq(&map_lock);
}

void task_free_trace(void *data, struct task_struct *self) {
    pid_t my_pid = task_pid_nr(self);
    remove_files((uintptr_t)self->files);
}

long my_fork(void) {
    long ret;
    long (*real_fork)(void) = (long (*)(void))sys_fork_ptr;

    ret = real_fork();

    printk(KERN_INFO "return once\n");
    return ret;
}

long my_vfork(void) {
    long ret;
    long (*real_vfork)(void) = (long (*)(void))sys_vfork_ptr;
    ret = real_vfork();
    printk(KERN_ERR "vfork called\n");
    return ret;
}

#ifdef CONFIG_CLONE_BACKWARDS
long my_clone(unsigned long arg1, unsigned long arg2, int __user * arg3, int arg4,
	      int __user *arg5) {
    long ret;
    long (*real_clone)(unsigned long, unsigned long, int __user *, int,
		       int __user *) = (long (*)(unsigned long, unsigned long, int __user *, int,
						 int __user *))sys_clone_ptr;
    write_lock_irq(&map_lock);
    ret = real_clone(arg1, arg2, arg3, arg4, arg5);
    copy_pid(task_pid_nr(current), (pid_t)ret);
    printk(KERN_INFO "clone 0: %ld\n", ret);
    write_unlock_irq(&map_lock);
    return ret;
}
#else
#ifdef CONFIG_CLONE_BACKWARDS3
long my_clone(unsigned long arg1, unsigned long arg2, int arg3, int __user * arg4,
	      int __user *arg5, int arg6) {
    long ret;
    long (*real_clone)(unsigned long, unsigned long, int, int __user *, int __user *,
		       int) = (long (*)(unsigned long, unsigned long, int, int __user *, int __user *,
					int))sys_clone_ptr;
    write_lock_irq(&map_lock);
    ret = real_clone(arg1, arg2, arg3, arg4, arg5, arg6);
    copy_pid(task_pid_nr(current), (pid_t)ret);
    printk(KERN_INFO "clone 1: %ld\n", ret);
    write_unlock_irq(&map_lock);
    return ret;
}
#else
long my_clone(unsigned long arg1, unsigned long arg2, int __user *arg3,
	      int __user *arg4, int arg5) {
    long ret;
    long (*real_clone)(unsigned long, unsigned long, int __user *, int __user *,
		       int) = (long (*)(unsigned long, unsigned long, int __user *, int __user *,
					int))sys_clone_ptr;
    unsigned long flags;
    write_lock_irqsave(&map_lock, flags);
    ret = real_clone(arg1, arg2, arg3, arg4, arg5);
    copy_pid(task_pid_nr(current), (pid_t)ret);
    //printk(KERN_ERR "clone 2: %ld\n", ret);
    if (ret != 0) {
	write_unlock_irqrestore(&map_lock, flags);
    }
    return ret;
}
#endif
#endif


long my_connect(int fd, struct sockaddr __user *addr, int flags) {
    pid_t pid;
    long ret;
    long (*real_connect)(int, struct sockaddr __user *, int) =
	(long (*)(int, struct sockaddr __user *, int))sys_connect_ptr;
    pid = task_pid_nr(current);
    ret = blacklist_files_contains(current, fd);
    if (ret) {
	printk(KERN_ERR "connect filtered: %d %d\n", pid, fd);
	return -EBADF;
    } else {
	return real_connect(fd, addr, flags);
    }
}

long my_bind(int fd, struct sockaddr __user *addr, int flags) {
    pid_t pid;
    long ret;
    long (*real_bind)(int, struct sockaddr __user *, int) =
	(long (*)(int, struct sockaddr __user *, int))sys_bind_ptr;
    pid = task_pid_nr(current);
    ret = blacklist_files_contains(current, fd);
    if (ret) {
	printk(KERN_ERR "bind filtered: %d %d\n", pid, fd);
	return -EBADF;
    } else {
	return real_bind(fd, addr, flags);
    }
}

long my_dup(unsigned int fd) {
    pid_t pid;
    unsigned int new_fd;
    long (*real_dup)(unsigned int) = (long (*)(unsigned int))sys_dup_ptr;
    pid = task_pid_nr(current);
    new_fd = real_dup(fd);
    if (new_fd > 0) {
	add_blacklist_files_if_present(current, fd, new_fd);
    }
    return new_fd;
}

long my_dup2(unsigned int oldfd, unsigned int newfd) {
    pid_t pid;
    unsigned int new_fd;
    long (*real_dup2)(unsigned int, unsigned int) = (long (*)(unsigned int, unsigned int))sys_dup2_ptr;
    pid = task_pid_nr(current);
    new_fd = real_dup2(oldfd, newfd);
    if (new_fd >= 0) {
	add_blacklist_files_if_present(current, oldfd, new_fd);
    }
    return new_fd;
}

long my_dup3(unsigned int oldfd, unsigned int newfd, int flags) {
    pid_t pid;
    unsigned new_fd;
    long (*real_dup3)(unsigned int, unsigned int, int) =
	(long (*)(unsigned int, unsigned int, int))sys_dup3_ptr;
    pid = task_pid_nr(current);
    new_fd = real_dup3(oldfd, newfd, flags);
    if (new_fd >= 0) {
	add_blacklist_files_if_present(current, oldfd, new_fd);
    }
    return new_fd;
}

long my_close(unsigned int fd) {
    pid_t pid;
    long (*real_close)(unsigned int) = (long (*)(unsigned int))sys_close_ptr;
    pid = task_pid_nr(current);
    remove_blacklist_files_fd(current, fd);
    return real_close(fd);
}

long my_exit(int error_code) {
    pid_t pid;
    long (*real_exit)(int) = (long (*)(int))sys_exit_ptr;
    pid = task_pid_nr(current);
    remove_files((uintptr_t)current->files);
    return real_exit(error_code);
}

long my_getsockname(int fd, struct sockaddr __user *addr, int __user *ptr) {
    pid_t pid = task_pid_nr(current);
    long ret;
    long (*real_getsockname)(int, struct sockaddr __user *, int __user *) =
	(long (*)(int, struct sockaddr __user *, int __user *))sys_getsockname_ptr;
    ret = blacklist_files_contains(current, fd);
    if (ret) {
	printk(KERN_ERR "getsockname filtered: %d %d\n", pid, fd);
	return -EBADF;
    } else {
	return real_getsockname(fd, addr, ptr);
    }
}

long my_getpeername(int fd, struct sockaddr __user *addr, int __user *ptr) {
    pid_t pid = task_pid_nr(current);
    long ret;
    long (*real_getpeername)(int, struct sockaddr __user *, int __user *) =
	(long (*)(int, struct sockaddr __user *, int __user *))sys_getpeername_ptr;
    ret = blacklist_files_contains(current, fd);
    if (ret) {
	printk(KERN_ERR "getpeername filtered: %d %d\n", pid, fd);
	return -EBADF;
    } else {
	return real_getpeername(fd, addr, ptr);
    }
}
