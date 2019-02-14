obj-m += slim_kern.o

slim_kern-objs += fd_remover.o fd_helpers.o syscall_intercept.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
