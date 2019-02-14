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

int main(int argc, char *argv[]) {
    int fd, to_remove;
    struct Cmd cmd;
    pid_t pid;
    int num_forks = 0;

    if (argc != 2) {
	printf("Usage: %s <num-forks>\n", argv[0]);
	return -1;
    }

    num_forks = atoi(argv[1]);

    to_remove = open("user-test.c", O_RDONLY);
    pid = fork();
    if (pid != 0) {
	// parent
	sleep(5);
	printf("parent finished sleeping\n");
	cmd.pid = pid;
	cmd.fd = to_remove;
	fd = open("/proc/fd_remover", O_RDWR);
	if (fd < 0) {
	    printf("open failed: %s\n", strerror(errno));
	    return -1;
	}
	
	write(fd, (void *)&cmd, sizeof(struct Cmd));
    } else {
	// child
	int i;
	for (i = 0; i < num_forks; i++) {
	    fork();
	}
	while (1) {
	    char buf[256];
	    int ret = lseek(to_remove, 0, SEEK_SET);
	    if (ret < 0 && errno == EBADF) {
		break;
	    }
	    ret = read(to_remove, buf, 128);
	    if (ret < 0 && errno == EBADF) {
		break;
	    }
	}
	printf("child_return\n");
    }
    return 0;
}
