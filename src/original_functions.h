
#ifndef SAFETLS__ORIGINAL_FUNCTIONS_H
#define SAFETLS__ORIGINAL_FUNCTIONS_H

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <poll.h>
#include <sys/epoll.h>
#include <sys/select.h>

int o_socket(int domain, int type, int protocol);

int o_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int o_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int o_listen(int sockfd, int backlog);

int o_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/* TODO: add accept4 here */

int o_close(int sockfd);


int o_getsockopt(int sockfd, int level,
                       int optname, void *optval, socklen_t *optlen);

int o_setsockopt(int sockfd, int level,
                       int optname, void *optval, socklen_t optlen);


int o_read(int fd, void *buf, size_t count);

int o_write(int fd, const void *buf, size_t count);

int o_send(int sockfd, const void *buf, size_t len, int flags);

int o_recv(int sockfd, void *buf, size_t len, int flags);



#endif
