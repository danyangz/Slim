#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

enum InspectOp {
    GET_CNT,
};

struct InspectCmd {
    enum InspectOp op;
    int fd;
};

int get_cnt(int to_inspect) {
    int fd = open("/proc/fd_inspector", O_RDWR);
    struct InspectCmd cmd;
    cmd.op = GET_CNT;
    cmd.fd = to_inspect;
    if (fd < 0) {
	printf("open failed: %s\n", strerror(errno));
	return -1;
    }
    int ret = write(fd, (void *)&cmd, sizeof(cmd));
    close(fd);
    return ret;
}

void print_refcnt(int fd) {
    printf("refcnt of %d is %d\n", fd, get_cnt(fd));
}

int main(int argc, char *argv[]) {
    int to_inspect = open("user-test.c", O_RDONLY);
    print_refcnt(to_inspect);

    int pid = fork();
    if (pid != 0) {
	print_refcnt(to_inspect);
	int to_2 = dup(to_inspect);
	print_refcnt(to_inspect);
	print_refcnt(to_2);
	close(to_inspect);
	print_refcnt(to_2);
	close(to_2);
	print_refcnt(to_inspect);
    } else {
	wait(NULL);
    }
    return 0;
}
