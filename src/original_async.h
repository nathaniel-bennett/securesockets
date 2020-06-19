#ifndef SECURESOCKETS_SRC_ORIGINAL_ASYNC_H
#define SECURESOCKETS_SRC_ORIGINAL_ASYNC_H

#include <sys/epoll.h>
#include <sys/select.h>
#include <poll.h>
#include <stdarg.h>


int o_fcntl(int fd, int cmd, va_list args);

/*
void o_FD_CLR(int fd, fd_set *set);

int o_FD_ISSET(int fd, fd_set *set);

void o_FD_SET(int fd, fd_set *set);
*/

int o_ppoll(struct pollfd *fds, nfds_t nfds,
            const struct timespec *tmo_p, const sigset_t *sigmask);

/*
int o_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
*/


#endif
