/*
 * Written by Nathaniel Bennett
 */

#include <errno.h>
#include <netdb.h>
#include <string.h>


#include "../original_functions.h" /* This MUST be before tls.h */
#include "../socket.h"
#include "../err_internal.h"
#include "../socket_hashmap.h"
#include "../../include/tls.h"



int is_fatal_listener_error(int error);


int WRAPPER_socket(int domain, int type, int protocol)
{
    socket_ctx *sock_ctx = NULL;
    int sockfd = -1;

    clear_global_errors();

    if (protocol != IPPROTO_TLS)
        return o_socket(domain, type, protocol);

    if (type != AF_HOSTNAME) {
        sockfd = o_socket(domain, type, IPPROTO_TCP);
        if (sockfd == -1)
            goto err;
    }

    sock_ctx = socket_ctx_new(sockfd);
    if (sock_ctx == NULL)
        goto err;

    return sock_ctx->id;
err:
    if (sockfd != -1)
        o_close(sockfd);

    return -1;
}


int WRAPPER_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    socket_ctx *sock_ctx = NULL;
    int ret;

    sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_bind(sockfd, addr, addrlen);

    clear_all_errors(sock_ctx);

    if (is_wrong_socket_state(sock_ctx, 1, SOCKET_NEW))
        return -1;

    ret = o_bind(sock_ctx->fd, addr, addrlen);
    if (ret != 0)
        sock_ctx->state = SOCKET_ERROR;

    return ret;
}


int WRAPPER_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    socket_ctx *sock_ctx = NULL;
    int ret;

    sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_connect(sockfd, addr, addrlen);

    clear_all_errors(sock_ctx);

    if (strlen(sock_ctx->hostname) <= 0) {
        errno = ECONNABORTED;
        set_err_string(sock_ctx,
            "TLS handshake error: "
            "no hostname was given to authenticate the connection");
        return -1;
    }


    switch(sock_ctx->state) {
    case SOCKET_NEW:
        if (prepare_socket_for_connection(sock_ctx) != 1)
            goto err;

        sock_ctx->state = SOCKET_CONNECTING_TCP;

        /* FALL THROUGH */
    case SOCKET_CONNECTING_TCP:
        ret = o_connect(sock_ctx->fd, addr, addrlen);
        if (ret == -1) {
            if (errno == EAGAIN || errno == EALREADY || errno == EINPROGRESS)
                return -1;
            else
                goto err;
        }
        sock_ctx->state = SOCKET_CONNECTING_TLS;

        /* FALL THROUGH */
    case SOCKET_CONNECTING_TLS:
        ret = attempt_socket_tls_connection(sock_ctx);
        if (ret != 1) {
            if (errno == EALREADY)
                return -1;
            else
                goto err;
        }

        sock_ctx->state = SOCKET_CONNECTED;
        return 0;

    case SOCKET_CONNECTED:
        errno = EISCONN;
        return -1;

    case SOCKET_ERROR:
        errno = EBADFD;
        return -1;

    default:
        errno = EOPNOTSUPP;
        return -1;
    }

err:

    sock_ctx->state = SOCKET_ERROR;
    return -1;
}


int WRAPPER_listen(int sockfd, int backlog)
{
    socket_ctx *sock_ctx = NULL;
    int ret;

    sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_listen(sockfd, backlog);

    clear_all_errors(sock_ctx);

    if (is_wrong_socket_state(sock_ctx, 1, SOCKET_NEW))
        return -1;

    ret = o_listen(sock_ctx->fd, backlog);
    if (ret != 0)
        sock_ctx->state = SOCKET_ERROR;
    else
        sock_ctx->state = SOCKET_LISTENING;

    return ret;
}


int WRAPPER_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    socket_ctx *listener = NULL;
    int new_fd;
    int ret;

    listener = get_tls_socket(sockfd);
    if (listener == NULL)
        return o_accept(sockfd, addr, addrlen);

    clear_all_errors(listener);

    if (is_wrong_socket_state(listener, 1, SOCKET_LISTENING))
        return -1;

    if (!already_accepting_connection(listener)) {
        new_fd = o_accept(listener->fd, addr, addrlen);
        if (new_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return -1;

            if (is_fatal_listener_error(errno))
                listener->state = SOCKET_ERROR;
            goto err;
        }

        listener->accept_ctx = accept_sock_ctx_new(new_fd, listener);
        if (listener->accept_ctx == NULL)
            goto err; /* close(new_fd) called within accept_sock_ctx_new() */
    }

    ret = SSL_connect(listener->accept_ctx->ssl);
    if (ret != 1) {
        switch (SSL_get_error(listener->ssl, ret)) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            errno = EALREADY;
            return -1;

        case SSL_ERROR_SYSCALL:
            goto err;

        case SSL_ERROR_ZERO_RETURN:
            errno = ECONNABORTED;
            goto err;

        default:
            set_socket_error_ssl(listener);
            goto err;
        }
    }

    listener->accept_ctx->state = SOCKET_CONNECTED;

    ret = add_tls_socket(listener->accept_ctx->id, listener->accept_ctx);
    if (ret != 0) {
        errno = ENOMEM;
        goto err;
    }

    int new_id = listener->accept_ctx->id;
    listener->accept_ctx = NULL;

    return new_id;

err:
    if (listener->accept_ctx != NULL)
        socket_ctx_free(listener->accept_ctx);
    listener->accept_ctx = NULL;
    return -1;
}


int WRAPPER_read(int fd, void *buf, size_t count)
{
    socket_ctx *sock_ctx = NULL;
    int num_read;

    sock_ctx = get_tls_socket(fd);
    if (sock_ctx == NULL)
        return o_read(fd, buf, count);

    clear_all_errors(sock_ctx);

    if (is_wrong_socket_state(sock_ctx, 1, SOCKET_CONNECTED))
        return -1;

    num_read = SSL_read(sock_ctx->ssl, buf, (int) count);

    switch (SSL_get_error(sock_ctx->ssl, num_read)) {
    case SSL_ERROR_NONE:
        return num_read;

    case SSL_ERROR_ZERO_RETURN:
        SSL_shutdown(sock_ctx->ssl);
        /* TODO: set state to SOCKET_SHUTDOWN here? */
        return 0;

    case SSL_ERROR_WANT_READ:
        errno = EAGAIN;
        return -1;

    case SSL_ERROR_SYSCALL:
        sock_ctx->state = SOCKET_ERROR;
        if (errno == NO_ERROR) /* unexpected EOF */
            return 0;
        else
            return -1;

    default: /* SSL_ERROR_SSL: */
        errno = EPROTO;
        set_socket_error_ssl(sock_ctx);
        sock_ctx->state = SOCKET_ERROR;
        return -1;
    }
}

int WRAPPER_write(int fd, const void *buf, size_t count)
{
    socket_ctx *sock_ctx = NULL;
    int num_sent;

    sock_ctx = get_tls_socket(fd);
    if (sock_ctx == NULL)
        return o_write(fd, buf, count);

    clear_all_errors(sock_ctx);

    if (is_wrong_socket_state(sock_ctx, 1, SOCKET_CONNECTED))
        return -1;

    num_sent = SSL_write(sock_ctx->ssl, buf, count);

    switch (SSL_get_error(sock_ctx->ssl, num_sent)) {
    case SSL_ERROR_NONE:
        return num_sent;

    case SSL_ERROR_ZERO_RETURN:
        SSL_shutdown(sock_ctx->ssl);
        /* TODO: set state to SOCKET_SHUTDOWN here? */
        return 0;

    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        errno = EAGAIN;
        return -1;

    case SSL_ERROR_SYSCALL:
        sock_ctx->state = SOCKET_ERROR;
        if (errno == NO_ERROR) /* unexpected EOF */
            return 0;
        else
            return -1;

    default: /* SSL_ERROR_SSL: */
        errno = EPROTO;
        set_socket_error_ssl(sock_ctx);
        sock_ctx->state = SOCKET_ERROR;
        return -1;
    }
}

int WRAPPER_send(int sockfd, const void *buf, size_t len, int flags)
{
    socket_ctx *sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_send(sockfd, buf, len, flags);

    if (flags == 0) {
        return WRAPPER_write(sockfd, buf, len);

    } else {
        /* As it stands, OpenSSL does not have functionality for implementing
         * the flags in send and recv; so any flags returns EOPNOTSUPP */
        set_err_string(sock_ctx, "send flags are not supported by TLS sockets");
        errno = EOPNOTSUPP;
        return -1;
    }
}

int WRAPPER_recv(int sockfd, void *buf, size_t len, int flags)
{
    socket_ctx *sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_recv(sockfd, buf, len, flags);

    if (flags == 0) {
        return WRAPPER_read(sockfd, buf, len);

    } else {
        set_err_string(sock_ctx, "recv flags are not supported by TLS sockets");
        errno = EOPNOTSUPP;
        return -1;
    }
}



int WRAPPER_close(int sockfd)
{
    socket_ctx *sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_close(sockfd);

    clear_all_errors(sock_ctx);

    socket_ctx_free(sock_ctx);

    return 0; /* TODO: worry about return value? signal interrupts? */
}



int is_fatal_listener_error(int error)
{
    switch (error)
    {
    case ENETDOWN:
    case EPROTO:
    case ENOPROTOOPT:
    case EHOSTDOWN:
    case ENONET:
    case EHOSTUNREACH:
    case EOPNOTSUPP:
    case ENETUNREACH:
    case ECONNABORTED:
    case EINTR:
        return 0;
    default:
        return 1;
    }
}

