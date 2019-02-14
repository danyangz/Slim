#ifndef _FD_HELPERS_
#define _FD_HELPERS_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/version.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#else
#include <linux/vmalloc.h>
#include <linux/signal.h>
#endif

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/filter.h>


int expand_files(struct files_struct *files, unsigned int nr);

#endif /* _FD_HELPERS_ */
