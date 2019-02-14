#include "fd_helpers.h"

#define BITBIT_NR(nr)	BITS_TO_LONGS(BITS_TO_LONGS(nr))
#define BITBIT_SIZE(nr)	(BITBIT_NR(nr) * sizeof(long))


static void *alloc_fdmem(size_t size)
{
	/*
	 * Very large allocations can stress page reclaim, so fall back to
	 * vmalloc() if the allocation size will be considered "large" by the VM.
	 */
	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
		void *data = kmalloc(size, GFP_KERNEL|__GFP_NOWARN|__GFP_NORETRY);
		if (data != NULL)
			return data;
	}
	return vmalloc(size);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,5,0))
unsigned int sysctl_nr_open __read_mostly = 1024*1024;
#else
int sysctl_nr_open __read_mostly = 1024*1024;
#endif

static void __free_fdtable(struct fdtable *fdt);

static void free_fdtable_rcu(struct rcu_head *rcu)
{
    __free_fdtable(container_of(rcu, struct fdtable, rcu));
}

/*
 * Copy 'count' fd bits from the old table to the new table and clear the extra
 * space if any.  This does not copy the file pointers.  Called with the files
 * spinlock held for write.
 */
static void copy_fd_bitmaps(struct fdtable *nfdt, struct fdtable *ofdt,
			    unsigned int count)
{
    unsigned int cpy, set;

    cpy = count / BITS_PER_BYTE;
    set = (nfdt->max_fds - count) / BITS_PER_BYTE;
    memcpy(nfdt->open_fds, ofdt->open_fds, cpy);
    memset((char *)nfdt->open_fds + cpy, 0, set);
    memcpy(nfdt->close_on_exec, ofdt->close_on_exec, cpy);
    memset((char *)nfdt->close_on_exec + cpy, 0, set);

    cpy = BITBIT_SIZE(count);
    set = BITBIT_SIZE(nfdt->max_fds) - cpy;
    memcpy(nfdt->full_fds_bits, ofdt->full_fds_bits, cpy);
    memset((char *)nfdt->full_fds_bits + cpy, 0, set);
}

/*
 * Copy all file descriptors from the old table to the new, expanded table and
 * clear the extra space.  Called with the files spinlock held for write.
 */
static void copy_fdtable(struct fdtable *nfdt, struct fdtable *ofdt)
{
    unsigned int cpy, set;

    BUG_ON(nfdt->max_fds < ofdt->max_fds);

    cpy = ofdt->max_fds * sizeof(struct file *);
    set = (nfdt->max_fds - ofdt->max_fds) * sizeof(struct file *);
    memcpy(nfdt->fd, ofdt->fd, cpy);
    memset((char *)nfdt->fd + cpy, 0, set);

    copy_fd_bitmaps(nfdt, ofdt, ofdt->max_fds);
}

static void __free_fdtable(struct fdtable *fdt)
{
    kvfree(fdt->fd);
    kvfree(fdt->open_fds);
    kfree(fdt);
}

static struct fdtable *alloc_fdtable(unsigned int nr)
{
    struct fdtable *fdt;
    void *data;

    /*
     * Figure out how many fds we actually want to support in this fdtable.
     * Allocation steps are keyed to the size of the fdarray, since it
     * grows far faster than any of the other dynamic data. We try to fit
     * the fdarray into comfortable page-tuned chunks: starting at 1024B
     * and growing in powers of two from there on.
     */
    nr /= (1024 / sizeof(struct file *));
    nr = roundup_pow_of_two(nr + 1);
    nr *= (1024 / sizeof(struct file *));
    /*
     * Note that this can drive nr *below* what we had passed if sysctl_nr_open
     * had been set lower between the check in expand_files() and here.  Deal
     * with that in caller, it's cheaper that way.
     *
     * We make sure that nr remains a multiple of BITS_PER_LONG - otherwise
     * bitmaps handling below becomes unpleasant, to put it mildly...
     */
    if (unlikely(nr > sysctl_nr_open))
	nr = ((sysctl_nr_open - 1) | (BITS_PER_LONG - 1)) + 1;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL_ACCOUNT);
#else
    fdt = kmalloc(sizeof(struct fdtable), GFP_KERNEL);
#endif
    if (!fdt)
	goto out;
    fdt->max_fds = nr;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    data = kvmalloc_array(nr, sizeof(struct file *), GFP_KERNEL_ACCOUNT);
    if (!data)
	goto out_fdt;
    fdt->fd = data;

    data = kvmalloc(max_t(size_t,
			  2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES),
		    GFP_KERNEL_ACCOUNT);
#else
    data = alloc_fdmem(nr * sizeof(struct file *));
    if (!data)
        goto out_fdt;
    fdt->fd = data;
    data = alloc_fdmem(max_t(size_t,
			  2 * nr / BITS_PER_BYTE + BITBIT_SIZE(nr), L1_CACHE_BYTES));

#endif
    if (!data)
	goto out_arr;
    fdt->open_fds = data;
    data += nr / BITS_PER_BYTE;
    fdt->close_on_exec = data;
    data += nr / BITS_PER_BYTE;
    fdt->full_fds_bits = data;

    return fdt;

 out_arr:
    kvfree(fdt->fd);
 out_fdt:
    kfree(fdt);
 out:
    return NULL;
}

static int expand_fdtable(struct files_struct *files, unsigned int nr)
    __releases(files->file_lock)
    __acquires(files->file_lock)
{
    struct fdtable *new_fdt, *cur_fdt;

    spin_unlock(&files->file_lock);
    new_fdt = alloc_fdtable(nr);

    /* make sure all __fd_install() have seen resize_in_progress
     * or have finished their rcu_read_lock_sched() section.
     */
    if (atomic_read(&files->count) > 1)
	synchronize_sched();

    spin_lock(&files->file_lock);
    if (!new_fdt)
	return -ENOMEM;
    /*
     * extremely unlikely race - sysctl_nr_open decreased between the check in
     * caller and alloc_fdtable().  Cheaper to catch it here...
     */
    if (unlikely(new_fdt->max_fds <= nr)) {
	__free_fdtable(new_fdt);
	return -EMFILE;
    }
    cur_fdt = files_fdtable(files);
    BUG_ON(nr < cur_fdt->max_fds);
    copy_fdtable(new_fdt, cur_fdt);
    rcu_assign_pointer(files->fdt, new_fdt);
    if (cur_fdt != &files->fdtab)
	call_rcu(&cur_fdt->rcu, free_fdtable_rcu);
    /* coupled with smp_rmb() in __fd_install() */
    smp_wmb();
    return 1;
}

int expand_files(struct files_struct *files, unsigned int nr)
    __releases(files->file_lock)
    __acquires(files->file_lock)
{
    struct fdtable *fdt;
    int expanded = 0;

 repeat:
    fdt = files_fdtable(files);

    /* Do we need to expand? */
    if (nr < fdt->max_fds)
	return expanded;

    /* Can we expand? */
    if (nr >= sysctl_nr_open)
	return -EMFILE;

    if (unlikely(files->resize_in_progress)) {
	spin_unlock(&files->file_lock);
	expanded = 1;
	wait_event(files->resize_wait, !files->resize_in_progress);
	spin_lock(&files->file_lock);
	goto repeat;
    }

    /* All good, so we try */
    files->resize_in_progress = true;
    expanded = expand_fdtable(files, nr);
    files->resize_in_progress = false;

    wake_up_all(&files->resize_wait);
    return expanded;
}
