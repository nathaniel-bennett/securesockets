/*
 * Written by Nathaniel Bennett
 */

#ifndef SECURESOCKETS_INCLUDE_TLS_H
#define SECURESOCKETS_INCLUDE_TLS_H

#include <sys/types.h>
#include <sys/socket.h>

#define IPPROTO_TLS 16125
#define AF_HOSTNAME 57 /* TODO: is this an alright value? */

#define SO_TLS_HOSTNAME               1
#define SO_TLS_MIN_PROTOCOL           2
#define SO_TLS_MAX_PROTOCOL           3
#define SO_TLS_CHOSEN_PROTOCOL        4
#define SO_TLS_ERROR_CODE             5
#define SO_TLS_ERROR_STRING           6
#define SO_TLS_COMPRESSION            7
#define SO_TLS_1_3_RECORD_PADDING     8



int WRAPPER_socket(int domain, int type, int protocol);

int WRAPPER_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int WRAPPER_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int WRAPPER_listen(int sockfd, int backlog);

int WRAPPER_accept4(int sockfd,
            struct sockaddr *addr, socklen_t *addrlen, int flags);

int WRAPPER_close(int sockfd);


int WRAPPER_getsockopt(int sockfd, int level,
            int optname, void *optval, socklen_t *optlen);

int WRAPPER_setsockopt(int sockfd, int level,
            int optname, void *optval, socklen_t optlen);


int WRAPPER_read(int fd, void *buf, size_t count);

int WRAPPER_write(int fd, const void *buf, size_t count);

int WRAPPER_send(int sockfd, const void *buf, size_t len, int flags);

int WRAPPER_recv(int sockfd, void *buf, size_t len, int flags);



#define socket(domain, type, protocol) WRAPPER_socket(domain, type, protocol)

#define bind(sockfd, addr, addrlen) WRAPPER_bind(sockfd, addr, addrlen)

#define connect(sockfd, addr, addrlen) WRAPPER_connect(sockfd, addr, addrlen)

#define listen(sockfd, backlog) WRAPPER_listen(sockfd, backlog)

#define accept(sockfd, addr, addrlen) WRAPPER_accept4(sockfd, addr, addrlen, 0)

#define accept4(sockfd, addr, addrlen, flags) \
            WRAPPER_accept4(sockfd, addr, addrlen, flags)

#define close(sockfd) WRAPPER_close(sockfd)


#define getsockopt(sockfd, level, optname, optval, optlen) \
            WRAPPER_getsockopt(sockfd, level, optname, optval, optlen)

#define setsockopt(sockfd, level, optname, optval, optlen) \
            WRAPPER_setsockopt(sockfd, level, optname, optval, optlen)


#define read(fd, buf, count) WRAPPER_read(fd, buf, count)

#define write(fd, buf, count) WRAPPER_write(fd, buf, count);

#define send(sockfd, buf, len, flags) WRAPPER_send(sockfd, buf, len, flags)

#define recv(sockfd, buf, len, flags) WRAPPER_recv(sockfd, buf, len, flags)

#endif
