#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>

#include "original_functions.h"


int o_socket(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}

int o_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return bind(sockfd, addr, addrlen);
}

int o_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return connect(sockfd, addr, addrlen);
}

int o_listen(int sockfd, int backlog)
{
    return listen(sockfd, backlog);
}

int o_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return accept(sockfd, addr, addrlen);
}

/* TODO: add accept4 here */

int o_close(int sockfd)
{
    return close(sockfd);
}


int o_getsockopt(int sockfd, int level,
                 int optname, void *optval, socklen_t *optlen)
{
    return getsockopt(sockfd, level, optname, optval, optlen);
}

int o_setsockopt(int sockfd, int level,
                 int optname, void *optval, socklen_t optlen)
{
    return setsockopt(sockfd, level, optname, optval, optlen);
}


int o_read(int fd, void *buf, size_t count)
{
    return read(fd, buf, count);
}

int o_write(int fd, const void *buf, size_t count)
{
    return write(fd, buf, count);
}

int o_send(int sockfd, const void *buf, size_t len, int flags)
{
    return send(sockfd, buf, len, flags);
}

int o_recv(int sockfd, void *buf, size_t len, int flags)
{
    return recv(sockfd, buf, len, flags);
}
