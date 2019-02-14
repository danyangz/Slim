// #define SECURITY
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <cassert>

#include "log.h"
#include "types.h"

#ifdef SECURITY
#include "crypto.hpp"

static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

#endif

extern "C" {
#include "ops.h"
}

using std::cout;
using std::endl;

using std::string;

int sock;
string pathname = "SlimRouter";
uint32_t host_ip;

sem_t semaphore;

class SlimKern {
    static const string kern_dup_path;
    static const string kern_filter_path;
    static const string kern_revoke_path;

    int dup_fd;
    int revoke_fd;
    int filter_fd;

    void send_cmd_to_kern(int fd, void *ptr, size_t size) {
	     int ret = write(fd, ptr, size);
       if (ret < 0) {
         assert(false && "oops");
	      }
    }

public:
    SlimKern() {
        dup_fd = open(kern_dup_path.c_str(), O_RDWR);
        revoke_fd = open(kern_revoke_path.c_str(), O_RDWR);
        filter_fd = open(kern_filter_path.c_str(), O_RDWR);

        if (dup_fd < 0 || revoke_fd < 0 || filter_fd < 0) {
	           assert(false && "oops: open kernel module failed");
	      }
    }

    ~SlimKern() {
	     close(dup_fd);
	     close(revoke_fd);
	     close(filter_fd);
    }

    void add_filter_fd(pid_t pid, int fd) {
	struct FilterOp op;
	op.op = FILTER_OP_ADD_FD;
	op.pid = pid;
	op.fd = fd;
	send_cmd_to_kern(filter_fd, (void *)&op, sizeof(op));
    }

    void remove_filter_fd(pid_t pid, int fd) {
	struct FilterOp op;
	op.op = FILTER_OP_REMOVE_FD;
	op.pid = pid;
	op.fd = fd;
	send_cmd_to_kern(filter_fd, (void *)&op, sizeof(op));
    }

    void dup2(pid_t pid_src, int src, pid_t pid_dst, int dst) {
	struct DupOp op;
	op.pid_dst = pid_dst;
	op.fd_dst = dst;
	op.pid_src = pid_src;
	op.fd_src = src;
	send_cmd_to_kern(dup_fd, (void *)&op, sizeof(op));
    }

    void revoke(pid_t pid, int fd) {
	struct Cmd op;
	op.pid = pid;
	op.fd = fd;
	send_cmd_to_kern(revoke_fd, (void *)&op, sizeof(op));
    }
};

const string SlimKern::kern_dup_path = "/proc/dup2_helper";
const string SlimKern::kern_filter_path = "/proc/filter_manage";
const string SlimKern::kern_revoke_path = "/proc/fd_remover";

#ifdef SECURITY
SlimKern kern_mod;
AESgcm cipher(gcm_key, gcm_iv, 128, sizeof(gcm_iv));
#endif

struct HandlerArgs {
    int client_sock;
    int count;
    sem_t *sem;
};

int send_fd(int sock, int fd)
{
    ssize_t     size;
    struct msghdr   msg;
    struct iovec    iov;
    union {
        struct cmsghdr  cmsghdr;
        char        control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr  *cmsg;
    char buf[2];

    iov.iov_base = buf;
    iov.iov_len = 2;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (fd != -1) {
        msg.msg_control = cmsgu.control;
        msg.msg_controllen = sizeof(cmsgu.control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof (int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        //printf ("passing fd %d\n", fd);
        *((int *) CMSG_DATA(cmsg)) = fd;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        //printf ("not passing fd\n");
    }

    size = sendmsg(sock, &msg, 0);

    if (size < 0) {
        perror ("sendmsg");
    }
    return size;
}

int recv_fd(int sock)
{
    ssize_t size;
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr cmsghdr;
        char control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr *cmsg;
    char buf[2];
    int fd = -1;

    iov.iov_base = buf;
    iov.iov_len = 2;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgu.control;
    msg.msg_controllen = sizeof(cmsgu.control);
    size = recvmsg (sock, &msg, 0);
    if (size < 0) {
        perror ("recvmsg");
        return -1;
    }
    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
        if (cmsg->cmsg_level != SOL_SOCKET) {
            fprintf (stderr, "invalid cmsg_level %d\n",
                    cmsg->cmsg_level);
            return -1;
        }
        if (cmsg->cmsg_type != SCM_RIGHTS) {
            fprintf (stderr, "invalid cmsg_type %d\n",
                    cmsg->cmsg_type);
            return -1;
        }
        int *fd_p = (int *)CMSG_DATA(cmsg);
        fd = *fd_p;
        // printf ("received fd %d\n", fd);
    } else {
        fd = -1;
    }

    return(fd);
}

void HandleRequest(struct HandlerArgs *args)
{
    LOG_TRACE("Start to handle the request from client sock " << args->client_sock << ".");
    int client_sock = args->client_sock;

    char *req_body = NULL;
    char *rsp = NULL;

    req_body = (char*)malloc(0xff);
    rsp = (char*)malloc(0xff);


    while (true) {
        int n = 0, size = 0;
        int host_fd = -1;

        struct FfrRequestHeader header;

        LOG_TRACE("Start to read from sock " << client_sock);

        if ((n = read(client_sock, &header, sizeof(header))) < sizeof(header))
        {
            if (n < 0)
                LOG_ERROR("Failed to read the request header. Read bytes: " << n << " Size of Header: " << sizeof(header));

            goto kill;

        } else {
            LOG_TRACE("Get request cmd " << header.func);
        }

        switch(header.func)
        {
            case SOCKET_SOCKET:
            {
                LOG_DEBUG("SOCKET_SOCKET");

                if (read(client_sock, req_body, sizeof(struct SOCKET_SOCKET_REQ)) < sizeof(struct SOCKET_SOCKET_REQ)) {
                    LOG_ERROR("Failed to read the request body.");
                    goto kill;
                }

                ((struct SOCKET_SOCKET_RSP *)rsp)->ret = socket(
                    // ((SOCKET_SOCKET_REQ*)req_body)->domain,
                    // for now we always use IPv4 for host socket
                    AF_INET,
                    ((SOCKET_SOCKET_REQ*)req_body)->type,
                    ((SOCKET_SOCKET_REQ*)req_body)->protocol);

                size = sizeof(struct SOCKET_SOCKET_RSP);
                if (((struct SOCKET_SOCKET_RSP *)rsp)->ret < 0) {
                    LOG_ERROR("Return error (" << ((struct SOCKET_SOCKET_RSP *)rsp)->ret  << ") in SOCKET_SOCKET");
                    ((struct SOCKET_SOCKET_RSP *)rsp)->ret = -errno;
                }
            }
            break;

            case SOCKET_BIND:
            {
                LOG_DEBUG("SOCKET_BIND");
#ifdef SECURITY
                host_fd = dup(0);
                unsigned int ucred_len;
                struct ucred ucred;
                ucred_len = sizeof(struct ucred);
                if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                    printf("getsockopt failed\n");
                    return;
                }
                kern_mod.dup2(ucred.pid, header.host_fd, getpid(), host_fd);
#else
                host_fd = recv_fd(client_sock);
#endif
                if (host_fd < 0) {
                    LOG_ERROR("Failed to read host fd.");
                    goto kill;
                }

                struct sockaddr_in host_addr;
                host_addr.sin_family = AF_INET;
                host_addr.sin_addr.s_addr = host_ip;
                host_addr.sin_port = 0;

                ((struct SOCKET_BIND_RSP *)rsp)->ret = bind(
                    host_fd,
                    (struct sockaddr *)&host_addr,
                    sizeof(host_addr));
                if (((struct SOCKET_BIND_RSP *)rsp)->ret < 0) {
                    LOG_ERROR("Return error (" << ((struct SOCKET_BIND_RSP *)rsp)->ret  << ") in SOCKET_BIND errno:" << errno);
                    ((struct SOCKET_BIND_RSP *)rsp)->ret = -errno;
                }
                size = sizeof(struct SOCKET_BIND_RSP);
            }
            break;

            case SOCKET_ACCEPT:
            {
                LOG_DEBUG("SOCKET_ACCEPT");
#ifdef SECURITY
                host_fd = dup(0);
                unsigned int ucred_len;
                struct ucred ucred;
                ucred_len = sizeof(struct ucred);
                if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                    printf("getsockopt failed\n");
                    return;
                }
                kern_mod.dup2(ucred.pid, header.host_fd, getpid(), host_fd);
#else
                host_fd = recv_fd(client_sock);
#endif
                if (host_fd < 0) {
                    LOG_ERROR("Failed to read host fd.");
                    goto kill;
                }

                struct sockaddr_in host_addr;
                socklen_t host_addrlen = sizeof(host_addr);

                // clear the non-blocking flag
                int original_flags = fcntl(host_fd, F_GETFL);
                fcntl(host_fd, F_SETFL, original_flags & ~O_NONBLOCK);

                ((struct SOCKET_ACCEPT_RSP *)rsp)->ret = accept(
                    host_fd,
                    (struct sockaddr *)&host_addr,
                    &host_addrlen);

                if (((struct SOCKET_ACCEPT_RSP *)rsp)->ret < 0) {
                    LOG_ERROR("Return error (" << ((struct SOCKET_ACCEPT_RSP *)rsp)->ret  << ") in SOCKET_ACCEPT");
                    ((struct SOCKET_ACCEPT_RSP *)rsp)->ret = -errno;
                }

                fcntl(host_fd, F_SETFL, original_flags);
                size = sizeof(struct SOCKET_ACCEPT_RSP);
            }
            break;

            case SOCKET_ACCEPT4:
            {
                LOG_DEBUG("SOCKET_ACCEPT4");

                if (read(client_sock, req_body, sizeof(struct SOCKET_ACCEPT4_REQ)) < sizeof(struct SOCKET_ACCEPT4_REQ)) {
                    LOG_ERROR("Failed to read the request body.");
                    goto kill;
                }
#ifdef SECURITY
                host_fd = dup(0);
                unsigned int ucred_len;
                struct ucred ucred;
                ucred_len = sizeof(struct ucred);
                if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                    printf("getsockopt failed\n");
                    return;
                }
                kern_mod.dup2(ucred.pid, header.host_fd, getpid(), host_fd);
#else
                host_fd = recv_fd(client_sock);
#endif
                if (host_fd < 0) {
                    LOG_ERROR("Failed to read host fd.");
                    goto kill;
                }

                struct sockaddr_in host_addr;
                socklen_t host_addrlen = sizeof(host_addr);

                // clear the non-blocking flag
                int original_flags = fcntl(host_fd, F_GETFL);
                fcntl(host_fd, F_SETFL, original_flags & ~O_NONBLOCK);

                ((struct SOCKET_ACCEPT4_RSP *)rsp)->ret = accept4(
                    host_fd,
                    (struct sockaddr *)&host_addr,
                    &host_addrlen,
                    ((SOCKET_ACCEPT4_REQ*)req_body)->flags);

                if (((struct SOCKET_ACCEPT4_RSP *)rsp)->ret < 0) {
                    LOG_ERROR("Return error (" << ((struct SOCKET_ACCEPT4_RSP *)rsp)->ret  << ") in SOCKET_ACCEPT4 errno:" << errno);
                    ((struct SOCKET_ACCEPT4_RSP *)rsp)->ret = -errno;
                }

                fcntl(host_fd, F_SETFL, original_flags);
                size = sizeof(struct SOCKET_ACCEPT4_RSP);
            }
            break;

            case SOCKET_GETSOCKNAME:
            {
#ifdef SECURITY
                LOG_DEBUG("SOCKET_GETSOCKNAME");
                host_fd = dup(0);
                unsigned int ucred_len;
                struct ucred ucred;
                ucred_len = sizeof(struct ucred);
                if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                    printf("getsockopt failed\n");
                    return;
                }
                kern_mod.dup2(ucred.pid, header.host_fd, getpid(), host_fd);
                socklen_t addrlen = sizeof(struct sockaddr_in);
                struct sockaddr_in addr;
                ((struct SOCKET_GETSOCKNAME_RSP *)rsp)->ret = getsockname(
                    host_fd, (struct sockaddr *)&addr, &addrlen);

                unsigned char a,b,c,d,e,f;
                a = addr.sin_addr.s_addr & 0xff;
                b = (addr.sin_addr.s_addr >> 8) & 0xff;
                c = (addr.sin_addr.s_addr >> 16) & 0xff;
                d = (addr.sin_addr.s_addr >> 24) & 0xff;
                e = (addr.sin_port) >> 8 & 0xff;
                f = addr.sin_port & 0xff;
                unsigned char pp[6] = {a,b,c,d,e,f};
                std::vector<unsigned char> tmp = cipher.encrypt(pp, 6);
                ((struct SOCKET_GETSOCKNAME_RSP *)rsp)->host_addr.sin_addr.s_addr = 
                    tmp[0] | tmp[1] << 8 | tmp[2] << 16 | tmp[3] << 24;
                ((struct SOCKET_GETSOCKNAME_RSP *)rsp)->host_addr.sin_port = tmp[4] << 8 | tmp[5];
                ((struct SOCKET_GETSOCKNAME_RSP *)rsp)->host_addrlen = addrlen;

                size = sizeof(struct SOCKET_GETSOCKNAME_RSP);
                if (((struct SOCKET_GETSOCKNAME_RSP *)rsp)->ret < 0) {
                    LOG_ERROR("Return error (" << ((struct SOCKET_CONNECT_RSP *)rsp)->ret  << ") in SOCKET_CONNECT");
                      ((struct SOCKET_GETSOCKNAME_RSP *)rsp)->ret = -errno;
                }
#endif
            }
            break;

            case SOCKET_CONNECT:
            {
                LOG_DEBUG("SOCKET_CONNECT");

                if (read(client_sock, req_body, sizeof(struct SOCKET_CONNECT_REQ)) < sizeof(struct SOCKET_CONNECT_REQ)) {
                    LOG_ERROR("Failed to read the request body.");
                    goto kill;
                }
#ifdef SECURITY
                host_fd = dup(0);
                unsigned int ucred_len;
                struct ucred ucred;
                ucred_len = sizeof(struct ucred);
                if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                    printf("getsockopt failed\n");
                    return;
                }
                kern_mod.dup2(ucred.pid, header.host_fd, getpid(), host_fd);
#else
                host_fd = recv_fd(client_sock);
#endif
                if (host_fd < 0) {
                    LOG_ERROR("Failed to read host fd.");
                    goto kill;
                }

#ifdef SECURITY
                struct sockaddr_in host_addr;
                struct sockaddr_in *addr;
                socklen_t host_addrlen = sizeof(struct sockaddr_in);
                unsigned char a,b,c,d,e,f;
                addr = &(((SOCKET_CONNECT_REQ*)req_body)->host_addr);
                a = addr->sin_addr.s_addr & 0xff;
                b = (addr->sin_addr.s_addr >> 8) & 0xff;
                c = (addr->sin_addr.s_addr >> 16) & 0xff;
                d = (addr->sin_addr.s_addr >> 24) & 0xff;
                e = (addr->sin_port) >> 8 & 0xff;
                f = addr->sin_port & 0xff;
                unsigned char pp[6] = {a,b,c,d,e,f};
                std::vector<unsigned char> tmp = cipher.decrypt(pp, 6);
                host_addr.sin_family = AF_INET;
                host_addr.sin_addr.s_addr = tmp[0] | tmp[1] << 8 | tmp[2] << 16 | tmp[3] << 24;
                host_addr.sin_port = tmp[4] << 8 | tmp[5];

                ((struct SOCKET_CONNECT_RSP *)rsp)->ret = connect(
                    host_fd,
                    (struct sockaddr *)&host_addr,
                    host_addrlen);
#else
                ((struct SOCKET_CONNECT_RSP *)rsp)->ret = connect(
                    host_fd,
                    (struct sockaddr *)&((SOCKET_CONNECT_REQ*)req_body)->host_addr,
                    ((SOCKET_CONNECT_REQ*)req_body)->host_addrlen);
#endif
                size = sizeof(struct SOCKET_CONNECT_RSP);
                if (((struct SOCKET_CONNECT_RSP *)rsp)->ret < 0) {
                    LOG_ERROR("Return error (" << ((struct SOCKET_CONNECT_RSP *)rsp)->ret  << ") in SOCKET_CONNECT");
                    ((struct SOCKET_CONNECT_RSP *)rsp)->ret = -errno;
                }
            }
            break;

            default:
                break;
        }
	

        if (header.func == SOCKET_SOCKET || header.func == SOCKET_ACCEPT || header.func == SOCKET_ACCEPT4) {
            if (((struct SOCKET_SOCKET_RSP *)rsp)->ret >= 0) {
#ifdef SECURITY
                unsigned int ucred_len;
                struct ucred ucred;
                ucred_len = sizeof(struct ucred);
                if (getsockopt(client_sock, SOL_SOCKET, SO_PEERCRED, &ucred, &ucred_len) == -1) {
                    printf("getsockopt failed\n");
                    return;
                }
                if (header.func == SOCKET_SOCKET) {
                    kern_mod.add_filter_fd(ucred.pid, header.host_fd);
                    kern_mod.dup2(getpid(), ((struct SOCKET_SOCKET_RSP *)rsp)->ret, ucred.pid, header.host_fd);
                }
                else {
                    kern_mod.add_filter_fd(ucred.pid, header.con_fd);
                    kern_mod.dup2(getpid(), ((struct SOCKET_SOCKET_RSP *)rsp)->ret, ucred.pid, header.con_fd);
                }
#else
                if (send_fd(client_sock, ((struct SOCKET_SOCKET_RSP *)rsp)->ret) < 0) {
                    LOG_ERROR("failed to send_fd for socket.");
                }
#endif
                close(((struct SOCKET_SOCKET_RSP *)rsp)->ret);
            }
        }

	LOG_TRACE("write rsp " << size << " bytes to sock " << client_sock);
        if ((n = write(client_sock, rsp, size)) < size)
        {
            LOG_ERROR("Error in writing bytes" << n);
            /*if (req_body != NULL)
                free(req_body);

            if(rsp != NULL)
                free(rsp);*/

            goto kill;
        }

        if (host_fd >= 0) {
            close(host_fd);
        }
        if (header.func == SOCKET_SOCKET || header.func == SOCKET_BIND ||
            header.func == SOCKET_ACCEPT || header.func == SOCKET_ACCEPT4 ||
            header.func == SOCKET_CONNECT) {
                break;
            }
    }

kill:
    close(client_sock);
    free(args);
    free(rsp);
    free(req_body);
    sem_post(args->sem);
}

int start(char *ip) {
    LOG_INFO("SlimRouter Starting... ");

    char c;
    register int i, len;
    struct sockaddr_un saun;

    host_ip = inet_addr(ip);

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        LOG_ERROR("Cannot create Unix domain socket.");
        exit(1);
    }

    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, pathname.c_str());

    unlink(pathname.c_str());
    len = sizeof(saun.sun_family) + strlen(saun.sun_path);

    if (bind(sock, (const sockaddr*)&saun, len) < 0) {
        LOG_ERROR("Cannot bind Unix domain socket.");
        exit(1);
    }

    if (listen(sock, 128) < 0) {
        LOG_ERROR("Cannot listen Unix domain socket.");
        exit(1);
    }

    int client_sock;
    int fromlen = sizeof(struct sockaddr_un);
    struct sockaddr_un fsaun;
    memset(&fsaun, 0, sizeof fsaun);

    int count = 0;

    LOG_DEBUG("Accepting new clients... ");
    sem_init(&semaphore, 0, 50000);
    while (1)
    {
        if ((client_sock = accept(sock, (sockaddr*)&fsaun, (socklen_t*)&fromlen)) < 0) {
            LOG_ERROR("Failed to accept." << errno);
            exit(1);
        }
        LOG_TRACE("New client with sock " << client_sock << ".");

        // Start a thread to handle the request.
        pthread_t *pth = (pthread_t *) malloc(sizeof(pthread_t));
        struct HandlerArgs *args = (struct HandlerArgs *) malloc(sizeof(struct HandlerArgs));
        args->client_sock = client_sock;
	args->sem = &semaphore;
	sem_wait(args->sem);
        int ret = pthread_create(pth, NULL, (void* (*)(void*))HandleRequest, args);
        LOG_TRACE("result of pthread_create --> " << ret);
	pthread_detach(*pth);
        count ++;
    }

    return 0;
}

int main (int argc, char **argv) {
    start(argv[1]);
}
