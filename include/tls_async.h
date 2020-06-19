#ifndef SECURESOCKETS_INCLUDE_TLS_ASYNC_H
#define SECURESOCKETS_INCLUDE_TLS_ASYNC_H

#include <sys/select.h>
#include <poll.h>
#include <sys/epoll.h>

int WRAPPER_fcntl(int fd, int cmd, ...);

/*
void WRAPPER_fd_clr(int fd, fd_set *set);

int WRAPPER_fd_isset(int fd, fd_set *set);

void WRAPPER_fd_set(int fd, fd_set *set);
*/

int WRAPPER_poll(struct pollfd *fds, nfds_t nfds, int timeout);

int WRAPPER_ppoll(struct pollfd *fds, nfds_t nfds,
                  const struct timespec *tmo_p, const sigset_t *sigmask);

/*
int WRAPPER_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
*/


/* the cheeky way of overloading variadic functions in ANSI C */
#define fcntl WRAPPER_fcntl

/*
#undef FD_CLR
#define FD_CLR(fd, fdsetp) WRAPPER_fd_clr(fd, fdsetp)

#undef FD_ISSET
#define FD_ISSET(fd, fdsetp) WRAPPER_fd_isset(fd, fdsetp)

#undef FD_SET
#define FD_SET(fd, fdsetp) WRAPPER_fd_set(fd, fdsetp)
*/

#define poll(fds, nfds, timeout) WRAPPER_poll(fds, nfds, timeout)

#define ppoll(fds, nfds, tmo_p, sigmask) \
            WRAPPER_ppoll(fds, nfds, tmo_p, sigmask);

/*
#define epoll_ctl(epfd, op, fd, event) WRAPPER_epoll_ctl(epfd, op, fd, event)
*/

#endif
