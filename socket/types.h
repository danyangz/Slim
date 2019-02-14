#ifndef TYPES_H
#define TYPES_H

#include <pthread.h>

typedef enum SOCKET_FUNCTION_CALL
{
        SOCKET_SOCKET,
        SOCKET_BIND,
        SOCKET_ACCEPT,
        SOCKET_ACCEPT4,
        SOCKET_CONNECT,
        SOCKET_GETSOCKNAME,

} SOCKET_FUNCTION_CALL;

struct FfrRequestHeader
{
        SOCKET_FUNCTION_CALL func;
        uint32_t body_size;
#ifdef SECURITY
        int host_fd;
        int con_fd;
#endif
};

struct FfrResponseHeader
{
        int rsp_size;
};

struct SOCKET_SOCKET_REQ
{
        int domain;
        int type;
        int protocol;
};

struct SOCKET_SOCKET_RSP
{
        int ret; // host_index or errno
};

struct SOCKET_BIND_RSP
{
        int ret;
};

struct SOCKET_ACCEPT_RSP
{
        int ret; // host_index or errno
};

struct SOCKET_ACCEPT4_REQ
{
        int flags;
};

struct SOCKET_ACCEPT4_RSP
{
        int ret; // host_index or errno
};

struct SOCKET_CONNECT_REQ
{
        struct sockaddr_in host_addr;
        socklen_t host_addrlen;
};

struct SOCKET_CONNECT_RSP
{
        int ret;
};

struct SOCKET_GETSOCKNAME_RSP
{
        struct sockaddr_in host_addr;
        socklen_t host_addrlen;
        int ret;
};

#endif /* TYPES_H */
