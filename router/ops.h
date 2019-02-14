#ifndef _OP_H_
#define _OP_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

struct Cmd {
    pid_t pid;
    int fd;
};

#define FILTER_OP_ATTACH     0
#define FILTER_OP_ADD_FD     1
#define FILTER_OP_REMOVE_FD  2
#define FILTER_OP_CLEAR      3

struct FilterOp {
    pid_t pid;
    int op;
    int fd;
    struct sock_fprog *prog;
};

struct DupOp {
    pid_t pid_dst;
    int fd_dst;
    pid_t pid_src;
    int fd_src;
};

#endif /* _OP_H_ */
