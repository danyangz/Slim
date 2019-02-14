#ifndef _SLIM_KERNMOD_CMDS_
#define _SLIM_KERNMOD_CMDS_

struct Cmd {
    pid_t pid;
    int fd;
};

struct FilterOp {
    pid_t pid;
    int op;
    int fd;
    struct sock_fprog __user *prog;
};

enum InspectOp {
    GET_CNT,
};

struct InspectCmd {
    enum InspectOp op;
    int fd;
};

struct DupOp {
    pid_t pid_dst;
    int fd_dst;
    pid_t pid_src;
    int fd_src;
};

struct QueueOp {
    int is_dequeue;
    pid_t pid;
};

#endif /* _SLIM_KERNMOD_CMDS_ */
