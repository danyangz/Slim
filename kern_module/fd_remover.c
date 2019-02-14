#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
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
#include <linux/pid_namespace.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/filter.h>

#include "fd_helpers.h"
#include "syscall_intercept.h"
#include "cmd.h"

#define procfs_name "fd_remover"

#define filter_procfs_name "filter_manage"

#define fd_inspector_procfs_name "fd_inspector"

DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

static int fd_remover_show(struct seq_file *m, void *v) {
    printk("fd_remover opend\n");
    return 0;
}

static int fd_remover_open(struct inode *inode, struct file *file) {
    return single_open(file, fd_remover_show, NULL);
}

/* These two are copied from kernel source (static functions) */

static inline void __clear_open_fd(unsigned int fd, struct fdtable *fdt)
{
	__clear_bit(fd, fdt->open_fds);
	__clear_bit(fd / BITS_PER_LONG, fdt->full_fds_bits);
}

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__clear_open_fd(fd, fdt);
	if (fd < files->next_fd)
		files->next_fd = fd;
}


/*! \brief removes all fd's of task that is referencing "file"
 *  most code is copied from __close_fd
 */
static int remove_file_ref(struct task_struct *task, struct file *to_remove) {
    struct files_struct *files;
    struct file *file;
    struct fdtable *fdt;
    int fd;
    int ret;

    task_lock(task);
    files = task->files;
    spin_lock(&files->file_lock);

    fdt = files_fdtable(files);
    for (fd = 0; fd < fdt->max_fds; fd++) {
	if (fd >= fdt->max_fds)
	    continue;
	file = fdt->fd[fd];
	if (!file)
	    continue;

	if(likely(file != to_remove)) {
	    continue;
	}

	rcu_assign_pointer(fdt->fd[fd], NULL);
	__put_unused_fd(files, fd);
	ret = filp_close(file, files);
	if (ret < 0) {
	    continue;
	}
    }
    spin_unlock(&files->file_lock);
    task_unlock(task);
    return 0;
}

/*! \brief A test function that prints the process tree of process "task"
 */
static void list_children(struct task_struct *task, int depth) {
    struct task_struct *p;
    struct list_head *list_ptr;
    printk("reaching task: 0x%llx\n", (__u64)task);
    printk("accessing proc: %d %d %s\n", depth, task->pid, task->comm);
    list_for_each(list_ptr, &(task->children)) {
	p = list_entry(list_ptr, struct task_struct, sibling);
	list_children(p, depth + 1);
    }
}

static void remove_fd_from_pstree(struct task_struct *task, struct file *file) {
    struct task_struct *p;
    struct list_head *list_ptr;
    remove_file_ref(task, file);
    list_for_each(list_ptr, &(task->children)) {
	p = list_entry(list_ptr, struct task_struct, sibling);
	remove_fd_from_pstree(p, file);
    }
}

static int fd_remover_release(struct inode *inode, struct file *file) {
    printk("fd_remover released\n");
    return single_release(inode, file);
}

static ssize_t proc_read(struct file *file, char __user *buf, size_t size, loff_t *off) {
    printk("read called\n");
    return 0;
}

static ssize_t proc_write(struct file *file, const char __user *buf, size_t size, loff_t *off) {
    struct Cmd cmd;
    struct task_struct *task;
    struct file *to_remove;
    if (size != sizeof(struct Cmd)) {
	return size;
    }
    copy_from_user((void *)&cmd, buf, sizeof(struct Cmd));
    task = pid_task(find_vpid(cmd.pid), PIDTYPE_PID);
    list_children(task, 0);
    to_remove = fget_raw(cmd.fd);
    remove_fd_from_pstree(task, to_remove);
    if (to_remove != NULL) {
	fput(to_remove);
    }
    return size;
}

static const struct file_operations fd_remover_fops = {
    .owner = THIS_MODULE,
    .open = fd_remover_open,
    .read = proc_read,
    .write = proc_write,
    .llseek = seq_lseek,
    .release = fd_remover_release,
};


//========================================================

#define FILTER_OP_ATTACH     0
#define FILTER_OP_ADD_FD     1
#define FILTER_OP_REMOVE_FD  2
#define FILTER_OP_CLEAR      3

static int filter_open_show(struct seq_file *m, void *v) {
    printk("filter_manager opend\n");
    return 0;
}

static int filter_open(struct inode *inode, struct file *file) {
    return single_open(file, filter_open_show, NULL);
}

static ssize_t filter_read(struct file *file, char __user *buf, size_t size, loff_t *off) {
    printk("read called\n");
    return 0;
}

static ssize_t filter_write(struct file *file, const char __user *buf, size_t size, loff_t *off) {
    struct FilterOp op;
    struct task_struct *task;
    if (size != sizeof(struct FilterOp)) {
	return size;
    }
    copy_from_user((void *)&op, buf, sizeof(struct FilterOp));
    task = pid_task(find_vpid(op.pid), PIDTYPE_PID);
    if (op.op == FILTER_OP_ADD_FD) {
	add_blacklist_fd(op.pid, op.fd);
    } else if (op.op == FILTER_OP_REMOVE_FD) {
	remove_blacklist_fd(op.pid, op.fd);
    } else if (op.op == FILTER_OP_CLEAR) {
	remove_pid(op.pid);
    }
    /*
    if (op.op == FILTER_OP_ATTACH) {
	spin_lock_irq(&task->sighand->siglock);
	printk("attaching filter to pid %d\n", op.pid);
	attach_filter(task, 0, (char *)op.prog);
	spin_unlock_irq(&task->sighand->siglock);
    }
    */
    return size;
}

static int filter_release(struct inode *inode, struct file *file) {
    printk("filter_manager released\n");
    return single_release(inode, file);
}

static const struct file_operations filter_manage_fops = {
    .owner = THIS_MODULE,
    .open = filter_open,
    .read = filter_read,
    .write = filter_write,
    .llseek = seq_lseek,
    .release = filter_release,
};

//========================================================

static int dup_open_show(struct seq_file *m, void *v) {
    printk("filter_manager opend\n");
    return 0;
}

static int dup_open(struct inode *inode, struct file *file) {
    return single_open(file, dup_open_show, NULL);
}

static ssize_t dup_read(struct file *file, char __user *buf, size_t size, loff_t *off) {
    printk("read called\n");
    return 0;
}

static inline void __set_open_fd(unsigned int fd, struct fdtable *fdt)
{
    __set_bit(fd, fdt->open_fds);
    fd /= BITS_PER_LONG;
    if (!~fdt->open_fds[fd])
	__set_bit(fd, fdt->full_fds_bits);
}

static inline void __set_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
    __set_bit(fd, fdt->close_on_exec);
}

static inline void __clear_close_on_exec(unsigned int fd, struct fdtable *fdt)
{
    if (test_bit(fd, fdt->close_on_exec))
	__clear_bit(fd, fdt->close_on_exec);
}

int do_dup2(struct files_struct *files,
	    struct file *file, unsigned fd, unsigned flags)
    __releases(&files->file_lock)
{
    struct file *tofree;
    struct fdtable *fdt;

    /*
     * We need to detect attempts to do dup2() over allocated but still
     * not finished descriptor.  NB: OpenBSD avoids that at the price of
     * extra work in their equivalent of fget() - they insert struct
     * file immediately after grabbing descriptor, mark it larval if
     * more work (e.g. actual opening) is needed and make sure that
     * fget() treats larval files as absent.  Potentially interesting,
     * but while extra work in fget() is trivial, locking implications
     * and amount of surgery on open()-related paths in VFS are not.
     * FreeBSD fails with -EBADF in the same situation, NetBSD "solution"
     * deadlocks in rather amusing ways, AFAICS.  All of that is out of
     * scope of POSIX or SUS, since neither considers shared descriptor
     * tables and this condition does not arise without those.
     */
    fdt = files_fdtable(files);
    tofree = fdt->fd[fd];
    if (!tofree && fd_is_open(fd, fdt))
	goto Ebusy;
    get_file(file);
    rcu_assign_pointer(fdt->fd[fd], file);
    __set_open_fd(fd, fdt);
    if (flags & O_CLOEXEC)
	__set_close_on_exec(fd, fdt);
    else
	__clear_close_on_exec(fd, fdt);
    spin_unlock(&files->file_lock);

    if (tofree)
	filp_close(tofree, files);

    return fd;

 Ebusy:
    spin_unlock(&files->file_lock);
    printk(KERN_ERR "dup2 failed ebusy\n");
    return -EBUSY;
}

static ssize_t dup_write(struct file *f, const char __user *buf, size_t size, loff_t *off) {
    struct files_struct *dst_files;
    struct files_struct *src_files;
    struct file *file;
    struct fdtable *fdt;
    struct task_struct *task_dst;
    struct task_struct *task_src;
    int eq;
    int err = -EBADF;
    struct DupOp op;
    if (size != sizeof(struct DupOp)) {
	return size;
    }
    copy_from_user((void *)&op, buf, sizeof(struct DupOp));
    struct pid_namespace *pid_ns = task_active_pid_ns(current);
    task_dst = pid_task(find_vpid(op.pid_dst), PIDTYPE_PID);
    task_src = pid_task(find_vpid(op.pid_src), PIDTYPE_PID);

    if (task_dst == NULL) {
	printk(KERN_ERR "oops: can not find task_struct for pid: %d\n", op.pid_dst);
	return -1;
    }

    if (task_src == NULL) {
	printk(KERN_ERR "oops: can not find task_struct for pid: %d\n", op.pid_src);
	return -1;
    }

    eq = (task_dst == task_src);

    task_lock(task_dst);
    if (!eq) {
	task_lock(task_src);
    }
    dst_files = task_dst->files;
    src_files = task_src->files;
    if (!eq) {
	spin_lock(&src_files->file_lock);
    }
    spin_lock(&dst_files->file_lock);
    fdt = files_fdtable(src_files);
    err = expand_files(dst_files, op.fd_dst);
    file = fcheck_files(src_files, op.fd_src);
    if (unlikely(!file)) {
	printk(KERN_ERR "badfd 1\n");
	goto Ebadf;
    }
    if (unlikely(err < 0)) {
	if (err == -EMFILE) {
	    printk(KERN_ERR "badfd 2\n");
	    goto Ebadf;
	}
	goto out_unlock;
    }
    err = do_dup2(dst_files, file, op.fd_dst, 0);
    if (err < 0) {
	goto out;
    }
    if (!eq) {
	spin_unlock(&src_files->file_lock);
	task_unlock(task_src);
    }
    task_unlock(task_dst);
    return size;
 Ebadf:
    err = -EBADF;
 out_unlock:
    spin_unlock(&dst_files->file_lock);
 out:
    if (!eq) {
	spin_unlock(&src_files->file_lock);
	task_unlock(task_src);
    }
    task_unlock(task_dst);
    return err;
}

static int dup_release(struct inode *inode, struct file *file) {
    printk("dup_helper released\n");
    return single_release(inode, file);
}

static const struct file_operations dup_fops = {
    .owner = THIS_MODULE,
    .open = dup_open,
    .read = dup_read,
    .write = dup_write,
    .llseek = seq_lseek,
    .release = dup_release,
};


static int fd_inspector_show(struct seq_file *m, void *v) {
    printk("fd_inspector opened\n");
    return 0;
}

static int fd_inspector_open(struct inode *inode, struct file *file) {
    return single_open(file, fd_remover_show, NULL);
}

static int fd_inspector_release(struct inode *inode, struct file *file) {
    printk("fd_inspector released\n");
    return single_release(inode, file);
}

static ssize_t fd_inspector_read(struct file *file, char __user *buf, size_t size, loff_t *off) {
    printk("read called\n");
    return 0;
}

static ssize_t fd_inspector_write(struct file *file, const char __user *buf, size_t size, loff_t *off) {
    struct InspectCmd cmd;
    struct task_struct *task;
    struct file *to_inspect;
    if (size != sizeof(cmd)) {
	return -1;
    }
    copy_from_user((void *)&cmd, buf, sizeof(cmd));
    task = current;
    to_inspect = fget(cmd.fd);
    if (to_inspect == NULL) {
	return -1;
    }
    int ret = -1;
    if (cmd.op == GET_CNT) {
	int cnt = file_count(to_inspect);
	printk(KERN_INFO "got refcnt for %d: %d\n", cmd.fd, cnt);
	ret = cnt - 1;
    }
    fput(to_inspect);
    return ret;
}

static const struct file_operations fd_inspector_fops = {
    .owner = THIS_MODULE,
    .open = fd_inspector_open,
    .read = fd_inspector_read,
    .write = fd_inspector_write,
    .llseek = seq_lseek,
    .release = fd_inspector_release,
};

static int __init fd_remover_init(void)
{
    proc_create(procfs_name, 0, NULL, &fd_remover_fops);
    proc_create(filter_procfs_name, 0, NULL, &filter_manage_fops);
    proc_create(fd_inspector_procfs_name, 0, NULL, &fd_inspector_fops);
    proc_create("dup2_helper", 0, NULL, &dup_fops);
    start_intercept();
    printk(KERN_INFO "Slim KernModule Loaded\n");
    printk(KERN_INFO "syscall table: 0x%lx\n", (long)acquire_syscall_table());
    return 0;	/* everything is ok */
}

static void __exit fd_remover_exit(void)
{
    remove_proc_entry(procfs_name, NULL);
    remove_proc_entry(filter_procfs_name, NULL);
    remove_proc_entry(fd_inspector_procfs_name, NULL);
    remove_proc_entry("dup2_helper", NULL);
    stop_intercept();
    printk(KERN_INFO "Slim KernModule Removed\n");
}

MODULE_LICENSE("GPL");
module_init(fd_remover_init);
module_exit(fd_remover_exit);
