#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>

#include "original_async.h"

int o_fcntl(int fd, int cmd, va_list args)
{
    int arg_int;
    struct flock *arg_lock;
    uint64_t* arg_uint64;


#if defined F_GETOWN_EX || defined F_SETOWN_EX
    struct f_owner_ex *arg_owner;
#endif

    switch (cmd) {
    case F_DUPFD:
    case F_DUPFD_CLOEXEC:
    case F_SETFD:
    case F_SETFL:
    case F_SETOWN:
#ifdef F_SETSIG
    case F_SETSIG:
#endif
#ifdef F_SETLEASE
    case F_SETLEASE:
#endif
#ifdef F_NOTIFY
    case F_NOTIFY:
#endif
#ifdef F_SETPIPE_SZ
    case F_SETPIPE_SZ:
#endif
#ifdef F_ADD_SEALS
    case F_ADD_SEALS:
#endif
        arg_int = va_arg(args, int);
        return fcntl(fd, cmd, arg_int);


    case F_GETFD:
    case F_GETFL:
    case F_GETOWN:
#ifdef F_GETSIG
    case F_GETSIG:
#endif
#ifdef F_GETLEASE
    case F_GETLEASE:
#endif
#ifdef F_GETPIPE_SZ
    case F_GETPIPE_SZ:
#endif
#ifdef F_GET_SEALS
    case F_GET_SEALS:
#endif
        return fcntl(fd, cmd);


    case F_SETLK:
    case F_SETLKW:
    case F_GETLK:
#ifdef F_OFD_SETLK
    case F_OFD_SETLK:
#endif
#ifdef F_OFD_SETLKW
    case F_OFD_SETLKW:
#endif
#ifdef F_OFD_GETLK
    case F_OFD_GETLK:
#endif
        arg_lock = va_arg(args, struct flock *);
        return fcntl(fd, cmd, arg_lock);
#ifdef F_GETOWN_EX
    case F_GETOWN_EX:
#endif
#ifdef F_SETOWN_EX
    case F_SETOWN_EX:
#endif
#if defined F_GETOWN_EX || defined F_SETOWN_EX
        arg_owner = va_arg(args, struct f_owner_ex *);
        return fcntl(fd, cmd, arg_owner);
#endif
    case F_GET_RW_HINT:
    case F_SET_RW_HINT:
    case F_GET_FILE_RW_HINT:
    case F_SET_FILE_RW_HINT:
        arg_uint64 = va_arg(args, uint64_t*);
        return fcntl(fd, cmd, arg_uint64);

    default:
        return -1;
    }
}

/*
void o_FD_CLR(int fd, fd_set *set)
{
    FD_CLR(fd, set);
}

int o_FD_ISSET(int fd, fd_set *set)
{
    return FD_ISSET(fd, set);
}

void o_FD_SET(int fd, fd_set *set)
{
    FD_SET(fd, set);
}
*/

int o_ppoll(struct pollfd *fds, nfds_t nfds,
            const struct timespec *tmo_p, const sigset_t *sigmask)
{
    return ppoll(fds, nfds, tmo_p, sigmask);
}

/*
int o_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return epoll_ctl(epfd, op, fd, event);
}
*/