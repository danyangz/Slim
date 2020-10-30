// #define SECURITY
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>

#include "indexer.h"
#include "types.h"

#define USE_GLOBAL_LOCK 1

#define _ADD_REF(x) &##x
#define ADD_REF(x) _ADD_REF(x)

#ifdef USE_GLOBAL_LOCK
#define RET_W_UNLOCK(lock_name, ret_val) do {           \
        pthread_mutex_unlock(ADD_REF(lock_name));       \
        return ret_val;                                 \
    } while (0)
#else
#define RET_W_UNLOCK(lock_name, ret_val) do {           \
        return ret_val;                                 \
    } while (0)
#endif

#ifdef USE_GLOBAL_LOCK
static pthread_mutex_t giant_lock = PTHREAD_MUTEX_INITIALIZER;
#define GLOBAL_LOCK do {                        \
        pthread_mutex_lock(&giant_lock);        \
    } while (0)
#define GLOBAL_UNLOCK do {                      \
        pthread_mutex_unlock(&giant_lock);      \
    } while (0)
#else
#define GLOBAL_LOCK do {} while (0)
#define GLOBAL_UNLOCK do {} while (0)
#endif

#ifdef SLIM_DEBUG
static uint8_t debug_flag = 1;
#else
static uint8_t debug_flag = 0;
#endif

int fd_to_epoll_fd[65536];
struct epoll_event epoll_events[65536];

struct epoll_calls {
    int (*epoll_ctl) (int epfd, int op, int fd, struct epoll_event *event);
};

struct socket_calls {
    int (*socket)(int domain, int type, int protocol);
    int (*bind)(int socket, const struct sockaddr *addr, socklen_t addrlen);
    int (*listen)(int socket, int backlog);
    int (*accept)(int socket, struct sockaddr *addr, socklen_t *addrlen);
    int (*accept4)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    int (*connect)(int socket, const struct sockaddr *addr, socklen_t addrlen);
    int (*getpeername)(int socket, struct sockaddr *addr, socklen_t *addrlen);
    int (*getsockname)(int socket, struct sockaddr *addr, socklen_t *addrlen);
    int (*setsockopt)(int socket, int level, int optname,
              const void *optval, socklen_t optlen);
    int (*getsockopt)(int socket, int level, int optname,
              void *optval, socklen_t *optlen);
    int (*fcntl)(int socket, int cmd, ... /* arg */);
    int (*close)(int socket);
};

static struct epoll_calls real_epoll;
static struct socket_calls real_socket;

static struct index_map idm;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

static char* unix_socket_path;
static uint32_t prefix_ip = 0;
static uint32_t prefix_mask = 0;

int connect_router();

enum fd_type {
    fd_normal,
    fd_fsocket
};

struct fd_info {
    enum fd_type type;
    int overlay_fd;
    int host_fd;
};

static void fd_store(int app_fd, int overlay_fd, int host_fd, enum fd_type type)
{
    struct fd_info *fdi = idm_at(&idm, app_fd);
    if (overlay_fd >= 0) {
        fdi->overlay_fd = overlay_fd;
    }
    if (host_fd >= 0) {
        fdi->host_fd = host_fd;
    }
    if (fdi->type >= 0) {
        fdi->type = type;
    }
    if (debug_flag) {
        printf("fd_store(%d, %d, %d, %d)\n", app_fd, overlay_fd, host_fd, type);
        fflush(stdout);
    }
}

static inline void log_error(char* info) {
    if (debug_flag) {
        printf("%s", info);
        printf("errno: %d\n", errno);
        fflush(stdout);
    }
    return;
}

static inline enum fd_type fd_get_type(int app_fd)
{
    struct fd_info *fdi;
    fdi = idm_lookup(&idm, app_fd);
    if (fdi) {
        return fdi->type;
    }
    return fd_normal;
}

static inline int fd_get_host_fd(int app_fd)
{
    struct fd_info *fdi;
    fdi = idm_lookup(&idm, app_fd);
    if (fdi) {
        return fdi->host_fd;
    }
    return -1;
}

static inline int fd_get_overlay_fd(int app_fd)
{
    struct fd_info *fdi;
    fdi = idm_lookup(&idm, app_fd);
    if (fdi) {
        return fdi->overlay_fd;
    }
    return -1;
}

static inline int fd_get_host_bind_addr(int app_fd, struct sockaddr_in* addr)
{
    int host_fd = fd_get_host_fd(app_fd);
#ifdef SECURITY
    int n, unix_sock = connect_router();

    struct FfrRequestHeader req_header;
    req_header.func = SOCKET_GETSOCKNAME;
    req_header.body_size = 0;
    req_header.host_fd = host_fd;
    if ((n = write(unix_sock, &req_header, sizeof(req_header))) < sizeof(req_header)) {
        printf("bind() write header fails.\n");
        real_socket.close(unix_sock);
        return -1;
      }

    int bytes = 0, rsp_size = sizeof(struct SOCKET_GETSOCKNAME_RSP);
    struct SOCKET_GETSOCKNAME_RSP rsp;
    while(bytes < rsp_size) {
      n = read(unix_sock, (char*)&rsp + bytes, rsp_size - bytes);
      if (n < 0) {
        log_error("getsockname() read fails.\n");
        real_socket.close(unix_sock);
        return -1;
      }
      bytes = bytes + n;
    }
    if (rsp.ret < 0) {
      log_error("getsockname() fails on router.\n");
      return -1;
    }
    real_socket.close(unix_sock);
    int ret = rsp.ret;
    *addr = rsp.host_addr;
#else
    socklen_t addrlen = sizeof(struct sockaddr_in);
    int ret = real_socket.getsockname(host_fd, (struct sockaddr*)addr, &addrlen);
#endif

    if (debug_flag) {
        printf("host bind address: %s:%hu\n", inet_ntoa(addr->sin_addr), htons(addr->sin_port));
    }

    return ret;
}

static inline bool is_on_overlay(const struct sockaddr_in* addr) {

    if (debug_flag) {
        struct in_addr addr_tmp;
        addr_tmp.s_addr = prefix_ip;
        struct in_addr mask_tmp;
        mask_tmp.s_addr = prefix_mask;
        printf("is %s ", inet_ntoa(addr->sin_addr));
        printf("on overlay %s", inet_ntoa(addr_tmp));
        printf("/%s?\n", inet_ntoa(mask_tmp));
        fflush(stdout);
    }
    if (addr->sin_family == AF_INET6) {
        const uint8_t *bytes = ((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr;
        bytes += 12;
        struct in_addr addr4 = { *(const in_addr_t *)bytes };
        return ((addr4.s_addr & prefix_mask) == (prefix_ip & prefix_mask));;
    }
    return ((addr->sin_addr.s_addr & prefix_mask) == (prefix_ip & prefix_mask));
}

void getenv_options(void)
{
    const char* path = "/slim/router/";
    const char* router_name = "SlimRouter";

    unix_socket_path = (char*)malloc(strlen(path)+strlen(router_name) + 1);
    memset(unix_socket_path, 0, strlen(path)+strlen(router_name) + 1);
    strcpy(unix_socket_path, path);
    strcat(unix_socket_path, router_name);

    const char* prefix = getenv("VNET_PREFIX");
    if (prefix) {
        uint8_t a, b, c, d, bits;
        if (sscanf(prefix, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits) == 5) {
            if (bits <= 32) {
                prefix_ip = htonl(
                    (a << 24UL) |
                    (b << 16UL) |
                    (c << 8UL) |
                    (d));
                prefix_mask = htonl((0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL);
            }
        }
    }
    if (prefix_ip == 0 && prefix_mask == 0) {
        printf("WARNING: VNET_PREFIX is not set. Using 0.0.0.0/0.\n");
        printf("All connections are treated as virtual network connections.\n");
    }

    return;
}

static void init_preload(void)
{
    static int init;
    // quick check without lock
    if (init) {
        return;
    }

    pthread_mutex_lock(&mut);
    if (init) {
        goto out;
    }

    real_socket.socket = dlsym(RTLD_NEXT, "socket");
    real_socket.bind = dlsym(RTLD_NEXT, "bind");
    real_socket.listen = dlsym(RTLD_NEXT, "listen");
    real_socket.accept = dlsym(RTLD_NEXT, "accept");
    real_socket.accept4 = dlsym(RTLD_NEXT, "accept4");
    real_socket.connect = dlsym(RTLD_NEXT, "connect");
    real_socket.getpeername = dlsym(RTLD_NEXT, "getpeername");
    real_socket.getsockname = dlsym(RTLD_NEXT, "getsockname");
    real_socket.setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    real_socket.getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    real_socket.fcntl = dlsym(RTLD_NEXT, "fcntl");
    real_socket.close = dlsym(RTLD_NEXT, "close");

    real_epoll.epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");

    getenv_options();
    init = 1;
out:
    pthread_mutex_unlock(&mut);
}


int send_fd(int unix_sock, int fd)
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
        int *fd_p = (int *) CMSG_DATA(cmsg);
        *fd_p = fd;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        //printf ("not passing fd\n");
    }

    size = sendmsg(unix_sock, &msg, 0);

    if (size < 0) {
        log_error ("recvmsg error");
    }
    return size;
}

int recv_fd(int unix_sock)
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
    size = recvmsg (unix_sock, &msg, 0);
    if (size < 0) {
        log_error ("recvmsg error");
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

int connect_router() {
    if (debug_flag) {
        printf("connect router...\n");
        fflush(stdout);
    }
    int unix_sock = real_socket.socket(AF_UNIX, SOCK_STREAM, 0);
    if (unix_sock < 0) {
        log_error("Cannot create unix socket.\n");
        return -1;
    }
    struct sockaddr_un saun;
    memset(&saun, 0, sizeof(saun));
    saun.sun_family = AF_UNIX;
    strcpy(saun.sun_path, unix_socket_path);
    int len = sizeof(saun.sun_family) + strlen(saun.sun_path);
    if (real_socket.connect(unix_sock, (struct sockaddr*)&saun, len) < 0) {
        log_error("Cannot connect router. try again\n");
        real_socket.close(unix_sock);
    }
    return unix_sock;
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    GLOBAL_LOCK;
    if (debug_flag) {
        printf("epoll_ctl(%d, %d, %d)\n", epfd, op, fd);
        fflush(stdout);
    }

    switch (op) {
        case EPOLL_CTL_ADD:
            fd_to_epoll_fd[fd] = epfd;
            epoll_events[fd] = *event;
            break;
        case EPOLL_CTL_DEL:
            fd_to_epoll_fd[fd] = 0;
    }
    GLOBAL_UNLOCK;
    return real_epoll.epoll_ctl(epfd, op, fd, event);
}

int socket(int domain, int type, int protocol)
{
    init_preload();
    GLOBAL_LOCK;
    struct fd_info *fdi = calloc(1, sizeof(*fdi));

    int overlay_fd = real_socket.socket(domain, type, protocol);

    fd_to_epoll_fd[overlay_fd] = 0;

    if (debug_flag) {
        printf("socket(%d, %d, %d) --> %d\n", domain, type, protocol, overlay_fd);
        fflush(stdout);
    }

    if ((domain == AF_INET || domain == AF_INET6) && (type & SOCK_STREAM) && (!protocol || protocol == IPPROTO_TCP)) {
        int n, unix_sock = connect_router();
        if (unix_sock < 0) {
            log_error("socket() fails.\n");
            goto normal;
        }

        struct FfrRequestHeader req_header;
        req_header.func = SOCKET_SOCKET;
        req_header.body_size = sizeof(struct SOCKET_SOCKET_REQ);
#ifdef SECURITY
        int tmp_fd = dup(0);
        req_header.host_fd = tmp_fd;
#endif
        if ((n = write(unix_sock, &req_header, sizeof(req_header))) < sizeof(req_header)) {
            printf("socket() write header fails.\n");
            real_socket.close(unix_sock);
            goto normal;
        }

        struct SOCKET_SOCKET_REQ req_body;
        req_body.domain = domain;
        req_body.type = type;
        req_body.protocol = protocol;
        if ((n = write(unix_sock, &req_body, req_header.body_size)) < req_header.body_size) {
            log_error("socket() write body fails.\n");
            real_socket.close(unix_sock);
            goto normal;
        }

#ifndef SECURITY
        int host_fd = recv_fd(unix_sock);
#endif

        int bytes = 0, rsp_size = sizeof(struct SOCKET_SOCKET_RSP);
        struct SOCKET_SOCKET_RSP rsp;
        while(bytes < rsp_size) {
            n = read(unix_sock, (char*)&rsp + bytes, rsp_size - bytes);
            if (n < 0) {
                log_error("socket() read fails.\n");
                real_socket.close(unix_sock);
                goto normal;
            }
            bytes = bytes + n;
        }
        if (rsp.ret < 0) {
            log_error("socket() fails on router.\n");
            goto normal;
        }

#ifdef SECURITY
        int host_fd = tmp_fd;
#endif
        real_socket.close(unix_sock);

        idm_set(&idm, overlay_fd, fdi);
        fd_store(overlay_fd, overlay_fd, host_fd, fd_fsocket);
        GLOBAL_UNLOCK;
        return overlay_fd;
    }

normal:
    // normal socket
    idm_set(&idm, overlay_fd, fdi);
    fd_store(overlay_fd, overlay_fd, -1, fd_normal);
    GLOBAL_UNLOCK;
    return overlay_fd;
}


int bind(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
    GLOBAL_LOCK;
    if (debug_flag) {
        printf("bind(%d, %s, %hu)\n", socket, inet_ntoa(((struct sockaddr_in*)addr)->sin_addr), htons(((struct sockaddr_in*)addr)->sin_port));
        fflush(stdout);
    }

    if (fd_get_type(socket) == fd_normal) {
        GLOBAL_UNLOCK;
        return real_socket.bind(socket, addr, addrlen);
    }

    int overlay_fd = fd_get_overlay_fd(socket);
    int ret = real_socket.bind(overlay_fd, addr, addrlen);
    if (ret < 0) {
        GLOBAL_UNLOCK;
        return ret;
    }

    if (!is_on_overlay((struct sockaddr_in*)addr) && ((struct sockaddr_in*)addr)->sin_addr.s_addr != INADDR_ANY) {
        // bind on non-overlay address, no need to contact router
        GLOBAL_UNLOCK;
        return ret;
    }

    // communicate with router
    int n, unix_sock = connect_router();
    if (unix_sock < 0) {
        log_error("bind() fails.\n");
        GLOBAL_UNLOCK;
        return -1;
    }

    struct FfrRequestHeader req_header;
    req_header.func = SOCKET_BIND;
    req_header.body_size = 0;
#ifdef SECURITY
    req_header.host_fd = fd_get_host_fd(socket);
#endif
    if ((n = write(unix_sock, &req_header, sizeof(req_header))) < sizeof(req_header)) {
        printf("bind() write header fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }

#ifndef SECURITY
    if (send_fd(unix_sock, fd_get_host_fd(socket)) < 0) {
        log_error("bind() send fd fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }
#endif

    int bytes = 0, rsp_size = sizeof(struct SOCKET_BIND_RSP);
    struct SOCKET_BIND_RSP rsp;
    while(bytes < rsp_size) {
        n = read(unix_sock, (char*)&rsp + bytes, rsp_size - bytes);
        if (n < 0) {
            log_error("bind() read fails.\n");
            real_socket.close(unix_sock);
            GLOBAL_UNLOCK;
            return -1;
        }
        bytes = bytes + n;
    }
    if (rsp.ret < 0) {
        log_error("bind() fails on router.\n");
        GLOBAL_UNLOCK;
        return -1;
    }
    real_socket.close(unix_sock);

    GLOBAL_UNLOCK;
    return ret;
}

int listen(int socket, int backlog)
{
    GLOBAL_LOCK;
    if (debug_flag) {
        printf("listen(%d, %d)\n", socket, backlog);
        fflush(stdout);
    }

    if (fd_get_type(socket) == fd_normal) {
        GLOBAL_UNLOCK;
        return real_socket.listen(socket, backlog);
    }

    int overlay_fd = fd_get_overlay_fd(socket);
    int host_fd = fd_get_host_fd(socket);
    int ret = real_socket.listen(overlay_fd, backlog);
    if (ret < 0) {
        return ret;
    }
    real_socket.listen(host_fd, backlog);
    GLOBAL_UNLOCK;
    return ret;
}

int accept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
    GLOBAL_LOCK;
    if (debug_flag) {
        printf("accept(%d)\n", socket);
        fflush(stdout);
    }

    if (fd_get_type(socket) == fd_normal) {
        int overlay_fd = real_socket.accept(socket, addr, addrlen);
        if (overlay_fd < 0) {
            GLOBAL_UNLOCK;
            return overlay_fd;
        }
        struct fd_info *fdi = calloc(1, sizeof(*fdi));
        idm_set(&idm, overlay_fd, fdi);
        fd_store(overlay_fd, overlay_fd, -1, fd_normal);
        GLOBAL_UNLOCK;
        return overlay_fd;
    }

    int overlay_fd = real_socket.accept(fd_get_overlay_fd(socket), addr, addrlen);
    if (overlay_fd < 0) {
        log_error("accept() fails on overlay.\n");
        GLOBAL_UNLOCK;
        return overlay_fd;
    }

    if (!is_on_overlay((struct sockaddr_in*)addr)) {
        struct fd_info *fdi = calloc(1, sizeof(*fdi));
        idm_set(&idm, overlay_fd, fdi);
        fd_store(overlay_fd, overlay_fd, -1, fd_normal);
        GLOBAL_UNLOCK;
        return overlay_fd;
    }

    // The other side is on overlay, tell it my host binding address
    int original_flags = real_socket.fcntl(overlay_fd, F_GETFL);
    real_socket.fcntl(overlay_fd, F_SETFL, original_flags & ~O_NONBLOCK);

    char my_addr[32];
    struct sockaddr_in host_bind_addr;
    fd_get_host_bind_addr(socket, &host_bind_addr);
    sprintf(my_addr, "%u:%u", host_bind_addr.sin_addr.s_addr , host_bind_addr.sin_port);
    if (send(overlay_fd, my_addr, 31, 0) < 31) {
        log_error("accept() fails to send host binding.\n");
        GLOBAL_UNLOCK;
        return -1;
    }

    real_socket.fcntl(overlay_fd, F_SETFL, original_flags);

    int host_fd;
    struct fd_info *fdi = calloc(1, sizeof(*fdi));

    struct FfrRequestHeader req_header;
    req_header.func = SOCKET_ACCEPT;
    req_header.body_size = 0;
#ifdef SECURITY
    req_header.host_fd = fd_get_host_fd(socket);
    int tmp_fd = dup(0);
    req_header.con_fd = tmp_fd;
#endif

    // communicate with router
    int n, unix_sock = connect_router();
    if (unix_sock < 0) {
        log_error("accept() fails connecting to router.\n");
        GLOBAL_UNLOCK;
        return -1;
    }

    if ((n = write(unix_sock, &req_header, sizeof(req_header))) < sizeof(req_header)) {
        printf("accept() write header fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }

#ifndef SECURITY
    if (send_fd(unix_sock, fd_get_host_fd(socket)) < 0) {
        log_error("accept() send fd fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }

    host_fd = recv_fd(unix_sock);

#endif

    int bytes = 0, rsp_size = sizeof(struct SOCKET_ACCEPT_RSP);
    struct SOCKET_ACCEPT_RSP rsp;
    while(bytes < rsp_size) {
        n = read(unix_sock, (char*)&rsp + bytes, rsp_size - bytes);
        if (n < 0) {
            log_error("accept() read fails.\n");
            real_socket.close(unix_sock);
            GLOBAL_UNLOCK;
            return -1;
        }
        bytes = bytes + n;
    }
    if (rsp.ret < 0) {
        errno = -rsp.ret;
        log_error("accept() fails on router.\n");
        GLOBAL_UNLOCK;
        return -1;
    }

#ifdef SECURITY
    host_fd = tmp_fd;
#endif

    real_socket.close(unix_sock);

    // get host_fd, host_index, addr and addrlen

    idm_set(&idm, host_fd, fdi);
    fd_store(host_fd, overlay_fd, host_fd, fd_fsocket);
    GLOBAL_UNLOCK;
    return host_fd;
}

int accept4(int socket, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    GLOBAL_LOCK;
    if (debug_flag) {
        printf("accept4(%d)\n", socket);
        fflush(stdout);
    }

    if (fd_get_type(socket) == fd_normal) {
        int overlay_fd = real_socket.accept4(socket, addr, addrlen, flags);
        if (overlay_fd < 0) {
            GLOBAL_UNLOCK;
            return overlay_fd;
        }
        struct fd_info *fdi = calloc(1, sizeof(*fdi));
        idm_set(&idm, overlay_fd, fdi);
        fd_store(overlay_fd, overlay_fd, -1, fd_normal);
        GLOBAL_UNLOCK;
        return overlay_fd;
    }

    int overlay_fd = real_socket.accept4(fd_get_overlay_fd(socket), addr, addrlen, flags);
    if (overlay_fd < 0) {
        log_error("accept4() fails on overlay.\n");
        GLOBAL_UNLOCK;
        return overlay_fd;
    }

    if (!is_on_overlay((struct sockaddr_in*)addr)) {
        struct fd_info *fdi = calloc(1, sizeof(*fdi));
        idm_set(&idm, overlay_fd, fdi);
        fd_store(overlay_fd, overlay_fd, -1, fd_normal);
        GLOBAL_UNLOCK;
        return overlay_fd;
    }

    // The other side is on overlay, tell it my host binding address
    int original_flags = real_socket.fcntl(overlay_fd, F_GETFL);
    real_socket.fcntl(overlay_fd, F_SETFL, original_flags & ~O_NONBLOCK);

    char my_addr[32];
    struct sockaddr_in host_bind_addr;
    fd_get_host_bind_addr(socket, &host_bind_addr);
    sprintf(my_addr, "%u:%u", host_bind_addr.sin_addr.s_addr , host_bind_addr.sin_port);
    if (send(overlay_fd, my_addr, 31, 0) < 31) {
        log_error("accept4() fails to send host binding.\n");
        GLOBAL_UNLOCK;
        return -1;
    }

    real_socket.fcntl(overlay_fd, F_SETFL, original_flags);

    int host_fd;
    struct fd_info *fdi = calloc(1, sizeof(*fdi));

    struct FfrRequestHeader req_header;
    req_header.func = SOCKET_ACCEPT4;
    req_header.body_size = sizeof(struct SOCKET_ACCEPT4_REQ);
#ifdef SECURITY
    req_header.host_fd = fd_get_host_fd(socket);
    int tmp_fd = dup(0);
    req_header.con_fd = tmp_fd;
#endif

    // communicate with router
    int n, unix_sock = connect_router();
    if (unix_sock < 0) {
        log_error("accept4() fails connecting to router.\n");
        GLOBAL_UNLOCK;
        return -1;
    }

    if ((n = write(unix_sock, &req_header, sizeof(req_header))) < sizeof(req_header)) {
        printf("accept4() write header fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }

    struct SOCKET_ACCEPT4_REQ req_body;
    req_body.flags = flags;
    if ((n = write(unix_sock, &req_body, req_header.body_size)) < req_header.body_size) {
        log_error("accept4() write body fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }

#ifndef SECURITY
    if (send_fd(unix_sock, fd_get_host_fd(socket)) < 0) {
        log_error("accept4() send fd fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }
#endif
//change here
#ifdef SECURITY
    host_fd = tmp_fd;
#else
    host_fd = recv_fd(unix_sock);
#endif

    int bytes = 0, rsp_size = sizeof(struct SOCKET_ACCEPT4_RSP);
    struct SOCKET_ACCEPT4_RSP rsp;
    while(bytes < rsp_size) {
        n = read(unix_sock, (char*)&rsp + bytes, rsp_size - bytes);
        if (n < 0) {
            log_error("accept4() read fails.\n");
            real_socket.close(unix_sock);
            GLOBAL_UNLOCK;
            return -1;
        }
        bytes = bytes + n;
    }
    if (rsp.ret < 0) {
        errno = -rsp.ret;
        log_error("accept4() fails on router.\n");
        GLOBAL_UNLOCK;
        return -1;
    }
    real_socket.close(unix_sock);

    // get host_fd, host_index, addr and addrlen

    idm_set(&idm, host_fd, fdi);
    fd_store(host_fd, overlay_fd, host_fd, fd_fsocket);
    GLOBAL_UNLOCK;
    return host_fd;
}

int connect(int socket, const struct sockaddr *addr, socklen_t addrlen)
{
    GLOBAL_LOCK;
    if (debug_flag) {
        printf("connect(%d, %s, %hu)\n", socket, inet_ntoa(((struct sockaddr_in*)addr)->sin_addr), htons(((struct sockaddr_in*)addr)->sin_port));
        fflush(stdout);
    }

    if (fd_get_type(socket) == fd_normal) {
        GLOBAL_UNLOCK;
        return real_socket.connect(socket, addr, addrlen);
    }

    int overlay_fd = fd_get_overlay_fd(socket);

    // connect to outside overlay, simply return
    if (!is_on_overlay((struct sockaddr_in*)addr)) {
        log_error("connect() to outside overlay.\n");
        GLOBAL_UNLOCK;
        return real_socket.connect(overlay_fd, addr, addrlen);
    }

    // connect to overlay, we first clear the non-blocking bit
    int original_flags = real_socket.fcntl(overlay_fd, F_GETFL);
    real_socket.fcntl(overlay_fd, F_SETFL, original_flags & ~O_NONBLOCK);
    int ret = real_socket.connect(overlay_fd, addr, addrlen);
    if (ret < 0) {
        log_error("connect() fails on overlay.\n");
        real_socket.fcntl(overlay_fd, F_SETFL, original_flags);
        GLOBAL_UNLOCK;
        return -1;
    }

    // connect to overlay peer
    struct sockaddr_in host_addr;
    host_addr.sin_family = AF_INET;
    char buffer[32];
    if (recv(overlay_fd, buffer, 31, 0) <= 0) {
        log_error("connect() fails to get host binding.\n");
        real_socket.fcntl(overlay_fd, F_SETFL, original_flags);
        GLOBAL_UNLOCK;
        return -1;
    }
    sscanf(buffer, "%u:%hu", &(host_addr.sin_addr.s_addr), &(host_addr.sin_port));

    // set the flags back
    real_socket.fcntl(overlay_fd, F_SETFL, original_flags);

    if (debug_flag) {
        printf("HOST connect(%d, %s, %hu)\n", socket, inet_ntoa(host_addr.sin_addr), htons(host_addr.sin_port));
        fflush(stdout);
    }

    // communicate with router
    int n, unix_sock = connect_router();
    if (unix_sock < 0) {
        log_error("connect() fails.\n");
        GLOBAL_UNLOCK;
        return -1;
    }

    struct FfrRequestHeader req_header;
    req_header.func = SOCKET_CONNECT;
    req_header.body_size = sizeof(struct SOCKET_CONNECT_REQ);
#ifdef SECURITY
    req_header.host_fd = fd_get_host_fd(socket);
    req_header.con_fd = socket;
#endif
    if ((n = write(unix_sock, &req_header, sizeof(req_header))) < sizeof(req_header)) {
        printf("connect() write header fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }

    struct SOCKET_CONNECT_REQ req_body;
    req_body.host_addr = host_addr;
    req_body.host_addrlen = sizeof(host_addr);
    if ((n = write(unix_sock, &req_body, req_header.body_size)) < req_header.body_size) {
        log_error("connect() write body fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }
#ifndef SECURITY
    if (send_fd(unix_sock, fd_get_host_fd(socket)) < 0) {
        log_error("accept() send fd fails.\n");
        real_socket.close(unix_sock);
        GLOBAL_UNLOCK;
        return -1;
    }
#endif

    int bytes = 0, rsp_size = sizeof(struct SOCKET_CONNECT_RSP);
    struct SOCKET_CONNECT_RSP rsp;
    while(bytes < rsp_size) {
        n = read(unix_sock, (char*)&rsp + bytes, rsp_size - bytes);
        if (n < 0) {
            log_error("connect() read fails.\n");
            real_socket.close(unix_sock);
            GLOBAL_UNLOCK;
            return -1;
        }
        bytes = bytes + n;
    }

    real_socket.close(unix_sock);

    if (rsp.ret < 0) {
        if (rsp.ret != -EINPROGRESS) {
            errno = -rsp.ret;
            log_error("connect() fails on router.\n");
            GLOBAL_UNLOCK;
            return -1;
        }
    }

    // we overwrite the socket fd mapping
    int host_fd = fd_get_host_fd(socket);
    if (socket != host_fd) {
        int new_overlay_fd = dup(overlay_fd);
        dup2(host_fd, socket);
        if (fd_to_epoll_fd[overlay_fd] > 0) {
            real_epoll.epoll_ctl(fd_to_epoll_fd[overlay_fd], EPOLL_CTL_DEL, overlay_fd, NULL);
            real_epoll.epoll_ctl(fd_to_epoll_fd[overlay_fd], EPOLL_CTL_ADD, socket, &epoll_events[overlay_fd]);
            fd_to_epoll_fd[new_overlay_fd] = fd_to_epoll_fd[overlay_fd];
            fd_to_epoll_fd[overlay_fd] = 0;
            epoll_events[new_overlay_fd] = epoll_events[overlay_fd];
        }

        real_socket.close(host_fd);
        fd_store(socket, new_overlay_fd, socket, -1);
    }

    if (rsp.ret < 0) {
        errno = -rsp.ret;
        GLOBAL_UNLOCK;
        return -1;
    }

    GLOBAL_UNLOCK;
    return rsp.ret;
}

int getpeername(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
    GLOBAL_LOCK;
    if (fd_get_type(socket) == fd_normal) {
        GLOBAL_UNLOCK;
        return real_socket.getpeername(socket, addr, addrlen);
    }

    int overlay_fd = fd_get_overlay_fd(socket);
    GLOBAL_UNLOCK;
    return real_socket.getpeername(overlay_fd, addr, addrlen);
}

int getsockname(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
    GLOBAL_LOCK;
    if (fd_get_type(socket) == fd_normal) {
        GLOBAL_UNLOCK;
        return real_socket.getsockname(socket, addr, addrlen);
    }

    int overlay_fd = fd_get_overlay_fd(socket);
    GLOBAL_UNLOCK;
    return real_socket.getsockname(overlay_fd, addr, addrlen);
}

int getsockopt(int socket, int level, int optname,
        void *optval, socklen_t *optlen)
{
    GLOBAL_LOCK;
    if (fd_get_type(socket) == fd_normal) {
        GLOBAL_UNLOCK;
        return real_socket.getsockopt(socket, level, optname, optval, optlen);
    }
    int overlay_fd = fd_get_overlay_fd(socket);
    GLOBAL_UNLOCK;
    return real_socket.getsockopt(overlay_fd, level, optname, optval, optlen);
}

int setsockopt(int socket, int level, int optname,
        const void *optval, socklen_t optlen)
{
    GLOBAL_LOCK;
    if (debug_flag) {
        printf("setsockopt(%d, %d, %d)\n", socket, level, optname);
        fflush(stdout);
    }

    if (fd_get_type(socket) == fd_normal) {
        GLOBAL_UNLOCK;
        return real_socket.setsockopt(socket, level, optname, optval, optlen);
    }

    int overlay_fd = fd_get_overlay_fd(socket);
    int ret = real_socket.setsockopt(overlay_fd, level, optname, optval, optlen);
    if (optname != SO_REUSEPORT && optname != SO_REUSEADDR && level != IPPROTO_IPV6) {
        int host_fd = fd_get_host_fd(socket);
        ret = real_socket.setsockopt(host_fd, level, optname, optval, optlen);
    }
    GLOBAL_UNLOCK;
    return ret;
}

int fcntl(int socket, int cmd, ... /* arg */)
{
    GLOBAL_LOCK;
    va_list args;
    long lparam;
    void *pparam;
    int ret;
    bool normal;
    int overlay_fd = socket, host_fd = socket;

    init_preload();
    if (fd_get_type(socket) == fd_normal) {
        normal = 1;
    }
    else {
        normal = 0;
        overlay_fd = fd_get_overlay_fd(socket);
        host_fd = fd_get_host_fd(socket);
    }

    // TODO: need to check whether it's a socket here

    va_start(args, cmd);
    switch (cmd) {
    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
    case F_GETSIG:
    case F_GETLEASE:
        if (normal) {
            ret = real_socket.fcntl(socket, cmd);
        }
        else {
            ret = real_socket.fcntl(host_fd, cmd);
            if (overlay_fd != host_fd) {
                real_socket.fcntl(overlay_fd, cmd);
            }
        }
        break;
    case F_DUPFD:
    /*case F_DUPFD_CLOEXEC:*/
    case F_SETFD:
    case F_SETFL:
    case F_SETOWN:
    case F_SETSIG:
    case F_SETLEASE:
    case F_NOTIFY:
        lparam = va_arg(args, long);
        if (normal) {
            ret = real_socket.fcntl(socket, cmd, lparam);
        }
        else {
            ret = real_socket.fcntl(host_fd, cmd, lparam);
            if (overlay_fd != host_fd) {
                real_socket.fcntl(overlay_fd, cmd, lparam);
            }
        }
        break;
    default:
        pparam = va_arg(args, void *);
        if (normal) {
            ret = real_socket.fcntl(socket, cmd, pparam);
        }
        else {
            ret = real_socket.fcntl(host_fd, cmd, pparam);
            if (overlay_fd != host_fd) {
                real_socket.fcntl(overlay_fd, cmd, pparam);
            }
        }
        break;
    }
    va_end(args);
    GLOBAL_UNLOCK;
    return ret;
}

int close(int socket)
{
    GLOBAL_LOCK;
    struct fd_info *fdi;
    int ret;

    init_preload();
    if (fd_get_type(socket) == fd_normal) {
        fdi = idm_lookup(&idm, socket);
        if (fdi) {
            free(fdi);
            idm_clear(&idm, socket);
        }
        GLOBAL_UNLOCK;
        return real_socket.close(socket);
    }

    int overlay_fd = fd_get_overlay_fd(socket);
    int host_fd = fd_get_host_fd(socket);

    if (debug_flag) {
        printf("close(%d)\n", socket);
        fflush(stdout);
    }

    fdi = idm_lookup(&idm, socket);
    idm_clear(&idm, socket);
    free(fdi);
    if (overlay_fd != host_fd) {
        real_socket.close(host_fd);
    }
    ret = real_socket.close(overlay_fd);

    fd_to_epoll_fd[host_fd] = 0;
    fd_to_epoll_fd[overlay_fd] = 0;
    GLOBAL_UNLOCK;
    return ret;
}
