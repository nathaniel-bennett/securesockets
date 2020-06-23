#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "../original_posix.h"
#include "../original_async.h"

#include "../socket.h"
#include "../err_internal.h"
#include "../socket_hashmap.h"
#include "../../include/tls.h"
#include "../../include/tls_async.h"

typedef struct tls_pair_st {
    int id;
    socket_ctx *sock_ctx;
} tls_pair;

int get_fd_to_watch(socket_ctx *sock_ctx);

void update_tls_sockets(tls_pair *tls_sockets,
            struct pollfd *fds, nfds_t nfds, int *num_ready);
int update_tls_socket_state(socket_ctx *sock_ctx, struct pollfd *poll_st);

struct timespec sum_of_times(struct timespec time1, struct timespec time2);
int time_is_after(struct timespec curr, struct timespec end_time);


int WRAPPER_fcntl(int fd, int cmd, ...)
{
    socket_ctx *sock_ctx;
    va_list args;
    int new_nonblocking_state;

    sock_ctx = get_tls_socket(fd);
    if (sock_ctx == NULL) {
        va_start(args, cmd);
        int ret = o_fcntl(fd, cmd, args);
        va_end(args);

        return ret;
    }

    if (cmd == F_SETFL) {
        va_start(args, cmd);

        if (va_arg(args, int) & O_NONBLOCK)
             new_nonblocking_state = 1;
        else
            new_nonblocking_state = 0;

        va_end(args);
    }

    /* blocking can't be changed once connecting/connected over TLS */
    /* if it could, this function would be the place to do it... */
    if (cmd == F_SETFL && sock_ctx->is_nonblocking != new_nonblocking_state) {

        /* if we're actively accepting or aren't new/listening then fail */
        if (sock_ctx->state != SOCKET_LISTENING && sock_ctx->state != SOCKET_NEW
                    || sock_ctx->accept_ctx != NULL) {
            set_socket_error(sock_ctx, EOPNOTSUPP,
                    "TLS error: TLS sockets' blocking state cannot be changed "
                    "once connect() or accept() have been called on them");
            return -1;
        }
    }

    va_start(args, cmd);
    int ret = o_fcntl(sock_ctx->fd, cmd, args);
    va_end(args);

    if (ret == 0 && cmd == F_SETFL)
        sock_ctx->is_nonblocking = new_nonblocking_state;

    return ret;
}


int WRAPPER_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct timespec timeout_nano;

    if (timeout <= 0)
        return WRAPPER_ppoll(fds, nfds, NULL, NULL);


    timeout_nano.tv_sec = timeout / 1000;
    timeout_nano.tv_nsec = (timeout % 1000) * 1000000;

    return WRAPPER_ppoll(fds, nfds, &timeout_nano, NULL);
}


int WRAPPER_ppoll(struct pollfd *fds, nfds_t nfds,
                  const struct timespec *tmo_p, const sigset_t *sigmask)
{
    struct timespec end_time, curr_time;
    tls_pair tls_sockets[nfds];
    int has_time_left = 1;
    int num_ready = -1;
    int i;

    if (tmo_p != NULL) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_time); /* TODO: check error */
        end_time = sum_of_times(end_time, *tmo_p);
    }

    memset(tls_sockets, 0, nfds * sizeof(tls_pair));
    clear_global_errors();

    for (i = 0; i < nfds; i++) {
        tls_sockets[i].sock_ctx = get_tls_socket(fds[i].fd);
        if (tls_sockets[i].sock_ctx == NULL)
            continue;

        tls_sockets[i].id = tls_sockets[i].sock_ctx->id;
        fds[i].fd = get_fd_to_watch(tls_sockets[i].sock_ctx);

        /* we fail all blocking async requests right now */
        if (!tls_sockets[i].sock_ctx->is_nonblocking) {
            errno = EOPNOTSUPP; /* TODO: write docs on why this is */
            goto end;
        }
    }

    do {
        num_ready = o_ppoll(fds, nfds, tmo_p, sigmask);
        if (num_ready <= 0)
            goto end;

        update_tls_sockets(tls_sockets, fds, nfds, &num_ready);

        if (tmo_p != NULL) {
            clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
            if (time_is_after(curr_time, end_time))
                has_time_left = 0;
        }

        errno = NO_ERROR;
    } while (num_ready == 0 && has_time_left);

end:
    for (i = 0; i < nfds; i++) {
        if (tls_sockets[i].sock_ctx != NULL)
            fds[i].fd = tls_sockets[i].id;
    }

    return num_ready;
}

void update_tls_sockets(tls_pair *tls_sockets,
            struct pollfd *fds, nfds_t nfds, int *num_ready)
{
    int ret, i;

    for (i = 0; i < nfds; i++) {
        socket_ctx* sock_ctx = tls_sockets[i].sock_ctx;
        if (sock_ctx == NULL)
            continue;

        if (fds[i].revents & POLLERR) {
            int error;
            socklen_t error_size = sizeof(int);
            ret = o_getsockopt(fds[i].fd,
                SOL_SOCKET, SO_ERROR, &error, &error_size);
            if (ret != 0)
                sock_ctx->error_code = ECANCELED; /* TODO: get better errno? */
            else
                sock_ctx->error_code = error;
            continue;
        }

        if (!(fds[i].revents & (POLLIN | POLLOUT)))
            continue; /* catches all other errors */

       ret = update_tls_socket_state(sock_ctx, &fds[i]);
       if (ret != 0)
           *num_ready -= 1;
    }
}

int update_tls_socket_state(socket_ctx *sock_ctx, struct pollfd *poll_st)
{
    int ret;

    switch (sock_ctx->state) {
    case SOCKET_CONNECTING_DNS:
    case SOCKET_CONNECTING_TCP:
    case SOCKET_CONNECTING_TLS:
    case SOCKET_FINISHING_CONN:
        /* because poll is level-triggered, connect only needs POLLOUT
         * to succeed (even though it reads in the TLS handshake) */
        ret = connect(sock_ctx->id, sock_ctx->addr, sock_ctx->addrlen);
        if (ret < 0) {
            poll_st->revents &= ~(POLLIN | POLLOUT);

            if (errno != EAGAIN && errno != EALREADY)
                poll_st->revents |= POLLERR;
            else
                return -1;

        } else {
            poll_st->revents & ~POLLIN;
            if (poll_st->revents == 0)
                return -1;
        }
        return 0;

    case SOCKET_LISTENING:
        if (sock_ctx->accept_ctx != NULL
            && sock_ctx->accept_ctx->state == SOCKET_FINISHING_CONN) {
            /* already has an accepted socket ready */
            return 0;
        }

        if (!(poll_st->events & POLLIN)) {
            poll_st->revents = POLLERR;
            set_socket_error(sock_ctx, ECANCELED, "Poll error: "
                    "listening sockets require POLLIN to function properly");
            return 0;
        }

        ret = accept(sock_ctx->id, NULL, 0);

        /* ret should ALWAYS be less than 0 here */
        if (ret >= 0) {
            /* TODO: for testing only--take out before prod */
            fprintf(stderr,
                "FATAL ERROR: accept in poll returned >= 0\n");
            return 0;
        }

        if (sock_ctx->accept_ctx == NULL
                    || sock_ctx->accept_ctx->state != SOCKET_FINISHING_CONN) {

            poll_st->revents &= ~(POLLIN | POLLOUT);

            if (sock_ctx->state == SOCKET_ERROR)
                poll_st->revents |= POLLERR;

            /* silently ignore non-fatal accept errors (such as TLS errors) */
            return -1;
        }

        return 0;

    default:
        return 0;
    }
}

int get_fd_to_watch(socket_ctx *sock_ctx)
{
    /* if we're in process of accepting, use the accepting fd */
    if (sock_ctx->state == SOCKET_LISTENING && sock_ctx->accept_ctx != NULL)
        return sock_ctx->accept_ctx->fd;
        /* else if (sock_ctx->state == SOCKET_CHECKING_REVOCATION)
            fds[i].fd = sock_ctx->rev_ctx->fd; */
    else
        return sock_ctx->fd;
}

struct timespec sum_of_times(struct timespec time1, struct timespec time2)
{
    time1.tv_sec += time2.tv_sec;
    time1.tv_nsec += time2.tv_nsec;
    if (time1.tv_nsec > 1000000000) {
        time1.tv_sec += 1;
        time1.tv_nsec -= 1000000000;
    }

    return time1;
}

int time_is_after(struct timespec curr, struct timespec end_time)
{
    if (curr.tv_sec > end_time.tv_sec)
        return 1;
    else if (curr.tv_sec == end_time.tv_sec
        && curr.tv_nsec >= end_time.tv_nsec)
        return 1;
    else
        return 0;
}

