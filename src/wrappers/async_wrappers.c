#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "../original_async.h"

#include "../socket.h"
#include "../err_internal.h"
#include "../socket_hashmap.h"
#include "../../include/tls.h"
#include "../../include/tls_async.h"



int get_fd_to_watch(socket_ctx *sock_ctx);

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


    timeout_nano.tv_sec = timeout/1000;
    timeout_nano.tv_nsec = (timeout%1000)*1000000;

    return WRAPPER_ppoll(fds, nfds, &timeout_nano, NULL);
}


/* TODO: set SO_ERROR getsockopt everywhere (esp. here) */
int WRAPPER_ppoll(struct pollfd *fds, nfds_t nfds,
                  const struct timespec *tmo_p, const sigset_t *sigmask)
{
    struct tls_pair {
        int id;
        socket_ctx *sock_ctx;
    };

    struct timespec end_time, curr_time;
    struct tls_pair tls_sockets[nfds];
    int has_time_left = 1;
    int num_ready = -1;
    int ret, i;

    if (tmo_p != NULL) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_time); /* TODO: check error */
        end_time = sum_of_times(end_time, *tmo_p);
    }

    memset(tls_sockets, 0, nfds * sizeof(struct tls_pair));
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

        for (i = 0; i < nfds; i++) {
            socket_ctx* sock_ctx = tls_sockets[i].sock_ctx;
            if (sock_ctx == NULL)
                continue;

            if (!(fds[i].revents & (POLLIN | POLLOUT)))
                continue;

            switch (sock_ctx->state) {
            case SOCKET_CONNECTING_DNS:
            case SOCKET_CONNECTING_TCP:
            case SOCKET_CONNECTING_TLS:
            case SOCKET_FINISHING_CONN:
                ret = connect(sock_ctx->id, sock_ctx->addr, sock_ctx->addrlen);
                if (ret < 0) {
                    fds[i].revents &= ~(POLLIN | POLLOUT);

                    if (errno != EAGAIN)
                        fds[i].revents |= POLLERR;
                    else
                        num_ready--;
                }
                break;

            case SOCKET_LISTENING:
                /* in case poll happens to be level-triggered */
                if (sock_ctx->accept_ctx != NULL
                    && sock_ctx->accept_ctx->state == SOCKET_FINISHING_CONN) {
                    break;
                }

                ret = accept(sock_ctx->id, NULL, 0);
                /* ret should ALWAYS be less than 0 here */
                if (ret >= 0) {
                    /* TODO: for testing only--take out before prod */
                    fprintf(stderr,
                        "FATAL ERROR: accept in poll returned >= 0\n");
                    break;
                }

                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    fds[i].revents &= ~(POLLIN | POLLOUT);
                    fds[i].revents |= POLLERR;

                } else if (sock_ctx->accept_ctx == NULL
                    || sock_ctx->accept_ctx->state != SOCKET_FINISHING_CONN) {
                    fds[i].revents &= ~(POLLIN | POLLOUT);
                    num_ready--;
                }

                break;

            default:
                fds[i].revents &= ~(POLLIN | POLLOUT);
                fds[i].revents |= POLLERR;
                break;
            }
        }

        if (tmo_p != NULL) {
            clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
            if (time_is_after(curr_time, end_time))
                has_time_left = 0;
        }

    } while (num_ready == 0 && has_time_left);

end:
    for (i = 0; i < nfds; i++) {
        if (tls_sockets[i].sock_ctx != NULL)
            fds[i].fd = tls_sockets[i].id;
    }

    return num_ready;
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



/* old code */
/*
int wrapper_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct tls_pair {
        int id;
        socket_ctx *sock_ctx;
    };

    struct timeval start_time = {.tv_sec = 0, .tv_usec = 0};
    struct timeval curr_time;
    struct timeval elapsed;
    struct tls_pair tls_sockets[nfds];
    int has_time_left = 1;
    int num_ready = -1;
    int ret, i;

    if (timeout != 0)
        gettimeofday(&start_time, null);

    memset(tls_sockets, 0, nfds * sizeof(struct tls_pair));

    for (i = 0; i < nfds; i++) {
        tls_sockets[i].sock_ctx = get_tls_socket(fds[i].fd);
        if (tls_sockets[i].sock_ctx == null)
            continue;

        tls_sockets[i].id = tls_sockets[i].sock_ctx->id;
        fds[i].fd = get_fd_to_watch(tls_sockets[i].sock_ctx);

        if (!tls_sockets[i].sock_ctx->is_nonblocking) {
            errno = eopnotsupp;
            goto end;
        }
    }

    do {
        num_ready = o_poll(fds, nfds, timeout);
        if (num_ready <= 0)
            goto end;

        for (i = 0; i < nfds; i++) {
            socket_ctx* sock_ctx = tls_sockets[i].sock_ctx;
            if (sock_ctx == null)
                continue;

            if (!(fds[i].revents & (pollin | pollout)))
                continue;

            switch (sock_ctx->state) {
            case socket_connecting_dns:
            case socket_connecting_tcp:
            case socket_connecting_tls:
            case socket_finishing_conn:
                ret = connect(sock_ctx->id, sock_ctx->addr, sock_ctx->addrlen);
                if (ret < 0) {
                    fds[i].revents &= ~(pollin | pollout);

                    if (errno != eagain)
                        fds[i].revents |= pollerr;
                    else
                        num_ready--;
                }
                break;

            case socket_listening:
                if (sock_ctx->accept_ctx != null
                    && sock_ctx->accept_ctx->state == socket_finishing_conn) {
                    break;
                }

                ret = accept(sock_ctx->id, null, 0);
                if (ret >= 0) {
                    fprintf(stderr,
                        "fatal error: accept in poll returned >= 0\n");
                    break;
                }

                if (errno != ewouldblock && errno != eagain) {
                    fds[i].revents &= ~(pollin | pollout);
                    fds[i].revents |= pollerr;

                } else if (sock_ctx->accept_ctx == null
                    || sock_ctx->accept_ctx->state != socket_finishing_conn) {
                    fds[i].revents &= ~(pollin | pollout);
                    num_ready--;
                }

                break;

            default:
                fds[i].revents &= ~(pollin | pollout);
                fds[i].revents |= pollerr;
                break;
            }
        }

        if (timeout != 0) {
            gettimeofday(&curr_time, null);
            timersub(&curr_time, &start_time, &elapsed);
            timeout -= (elapsed.tv_sec*1000 + elapsed.tv_usec/1000);
            has_time_left = (timeout > 0) ? 1 : 0;
        }
    } while (num_ready == 0 && has_time_left);

end:
    for (i = 0; i < nfds; i++) {
        if (tls_sockets[i].sock_ctx != NULL)
            fds[i].fd = tls_sockets[i].id;
    }

    return num_ready;
}
*/
