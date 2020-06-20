#include <errno.h>
#include <limits.h>
#include <string.h>

#include <openssl/ssl.h>

#include "err_internal.h"
#include "original_posix.h"
#include "socket.h"
#include "socket_hashmap.h"

#define MIN_ID 30000

#define SECURE_CIPHERS  "ECDHE-ECDSA-AES256-GCM-SHA384:"  \
                        "ECDHE-RSA-AES256-GCM-SHA384:"    \
                        "ECDHE-ECDSA-CHACHA20-POLY1305:"  \
                        "ECDHE-RSA-CHACHA20-POLY1305:"    \
                        "ECDHE-ECDSA-AES128-GCM-SHA256:"  \
                        "ECDHE-RSA-AES128-GCM-SHA256"

#define SECURE_CIPHERSUITES "TLS_AES_256_GCM_SHA384:"       \
                            "TLS_AES_128_GCM_SHA256:"       \
                            "TLS_CHACHA20_POLY1305_SHA256:" \
                            "TLS_AES_128_CCM_SHA256:"       \
                            "TLS_AES_128_CCM_8_SHA256"

#define UBUNTU_CA_LOCATION "/etc/ssl/certs/ca-certificates.crt"

#define DEFAULT_BLOCK_PADDING 128

static int next_id = INT_MAX;

int get_id();
SSL_CTX *create_secure_ssl_ctx();


socket_ctx *socket_ctx_new(int sockfd)
{
    socket_ctx *sock_ctx = NULL;
    int ret;
    int error;
    int id = get_id();

    sock_ctx = calloc(1, sizeof(socket_ctx));
    if (sock_ctx == NULL)
        goto err;

    sock_ctx->addr = calloc(1, sizeof(struct sockaddr));
    if (sock_ctx->addr == NULL)
        goto err;

    sock_ctx->fd = -1;

    sock_ctx->ssl_ctx = create_secure_ssl_ctx();
    if (sock_ctx->ssl_ctx == NULL) {

        goto err; /* TODO: set errno here */
    }

    ret = add_tls_socket(id, sock_ctx);
    if (ret != 0)
        goto err;

    sock_ctx->id = id;
    sock_ctx->fd = sockfd; /* needs to go last--will close() twice otherwise */
    sock_ctx->state = SOCKET_NEW;

    return sock_ctx;
err:
    error = errno;
    if (sock_ctx != NULL)
        socket_ctx_free(sock_ctx);

    errno = error;
    return NULL;
}

int currently_accepting_connection(socket_ctx *listener)
{
    return (listener->accept_ctx == NULL) ? 0 : 1;
}

void stop_accepting_connection(socket_ctx *listener)
{
    if (listener->accept_ctx != NULL) {
        socket_ctx_free(listener->accept_ctx);
        listener->accept_ctx = NULL;
    }
}

socket_ctx *socket_ctx_accepted_new(int accepted_fd, socket_ctx *listening_ctx)
{
    socket_ctx *sock_ctx;
    int id;
    int ret;

    sock_ctx = calloc(1, sizeof(socket_ctx));
    if (sock_ctx == NULL)
        goto err;

    sock_ctx->fd = accepted_fd;

    sock_ctx->ssl = SSL_new(listening_ctx->ssl_ctx);
    if (sock_ctx->ssl == NULL)
        goto err;

    ret = SSL_set_fd(sock_ctx->ssl, sock_ctx->fd);
    if (ret != 1)
        goto err;

    ret = SSL_CTX_up_ref(listening_ctx->ssl_ctx);
    if (ret != 1)
        goto err;

    sock_ctx->ssl_ctx = listening_ctx->ssl_ctx;

    id = get_id();
    ret = add_tls_socket(id, sock_ctx);
    if (ret != 0)
        goto err;


    sock_ctx->id = id;
    sock_ctx->state = SOCKET_CONNECTING_TLS;

    return sock_ctx;
err:
    if (sock_ctx == NULL)
        o_close(accepted_fd);
    else
        socket_ctx_free(sock_ctx);

    return NULL;
}


void socket_ctx_free(socket_ctx *sock_ctx)
{
    int error = errno;

    if (sock_ctx->addr != NULL)
        free(sock_ctx->addr);

    if (sock_ctx->ssl != NULL)
        SSL_free(sock_ctx->ssl);

    if (sock_ctx->ssl_ctx != NULL)
        SSL_CTX_free(sock_ctx->ssl_ctx);

    if (sock_ctx->id != 0)
        del_tls_socket(sock_ctx->id);

    if (sock_ctx->fd != -1)
        o_close(sock_ctx->fd);

    free(sock_ctx);

    errno = error;
    return;
}


/**
 * Creates a unique ID for a socket context, decrementing by 1 each time. This
 * function will never return an ID less than MIN_ID, so regular socket file
 * descriptors are not at risk of colliding with the id of a TLS socket unless
 * the user has >30000 sockets open simultaneously AND has somehow made enough
 * TLS connections to decrement down to that number from ~4 billion.
 * @return A unique identifier that can be used to represent a socket context.
 */
int get_id()
{
    next_id -= 1;

    if (next_id < MIN_ID)
        next_id = INT_MAX;

    while (get_tls_socket(next_id) != NULL)
        next_id--;

    return next_id;
}

SSL_CTX *create_secure_ssl_ctx()
{
    SSL_CTX *ctx;
    int ret;

    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
        goto err;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_options(ctx, SSL_CTX_get_options(ctx)
                | SSL_OP_NO_COMPRESSION
                | SSL_OP_NO_TICKET); /* TODO: more ops to add??? */

    ret = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (ret != 1)
        goto err;

    ret = SSL_CTX_set_cipher_list(ctx, SECURE_CIPHERS);
    if (ret != 1)
        goto err;

    ret = SSL_CTX_set_ciphersuites(ctx, SECURE_CIPHERSUITES);
    if (ret != 1)
        goto err;

    /* TODO: make a function to get this regardless of OS or distro */
    ret = SSL_CTX_load_verify_locations(ctx, UBUNTU_CA_LOCATION, NULL);
    if (ret != 1)
        goto err;

    ret = SSL_CTX_set_block_padding(ctx, DEFAULT_BLOCK_PADDING);
    if (ret != 1)
        goto err;


    return ctx;
err:
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    return NULL;
}



/**
 * Checks the given connection to see if it matches any of the corresponding
 * states passed into the function. If not, the error string of the connection
 * is set and a negative error code is returned. Any state or combination of
 * states may be checked using this function (even CONN_ERROR), provided the
 * number of states to check are accurately reported in num.
 * @param conn The connection to verify.
 * @param num The number of connection states listed in the function arguments.
 * @param ... The variadic list of connection states to check.
 * @returns 0 if the state was one of the acceptable states listed, or 1
 * otherwise. If 1 is returned, errno will be set to an appropriate error code
 * indicating why it was the wrong state (EBADFD if the socket is in an error
 * state, and EOPNOTSUPP otherwise).
 */
int is_wrong_socket_state(socket_ctx* sock_ctx, int num, ...)
{
    va_list args;
    int i;

    errno = NO_ERROR;

    va_start(args, num);

    for (i = 0; i < num; i++) {
        enum socket_state state = va_arg(args, enum socket_state);
        if (sock_ctx->state == state)
            return 0;
    }
    va_end(args);

    switch(sock_ctx->state) {
    case SOCKET_ERROR:
        set_errno_code(sock_ctx, EBADFD);
    default:
        set_errno_code(sock_ctx, EOPNOTSUPP);
    }


    return 1;
}



int prepare_socket_for_connection(socket_ctx *sock_ctx)
{
    sock_ctx->ssl = SSL_new(sock_ctx->ssl_ctx);
    if (sock_ctx->ssl == NULL)
        goto err;

    int ret = SSL_set_fd(sock_ctx->ssl, sock_ctx->fd);
    if (ret != 1)
        goto err;

    ret = SSL_set1_host(sock_ctx->ssl, sock_ctx->hostname);
    if (ret != 1)
        goto err;

    ret = SSL_set_tlsext_host_name(sock_ctx->ssl, sock_ctx->hostname);
    if (ret != 1)
        goto err;

    return 1;
err:
    set_ssl_socket_error(sock_ctx);
    return 0;
}


int attempt_socket_tls_connection(socket_ctx *sock_ctx)
{
    int ret = SSL_connect(sock_ctx->ssl);
    if (ret != 1) {
        int reason = SSL_get_error(sock_ctx->ssl, ret);
        if (reason == SSL_ERROR_WANT_READ
            || reason == SSL_ERROR_WANT_WRITE) {
            set_errno_code(sock_ctx, EALREADY);
            return 0;

        } else if (reason == SSL_ERROR_SYSCALL) {
            if (errno == NO_ERROR)
                set_errno_code(sock_ctx, ECONNRESET);
            /* errno already has details in this case */
            return 0;

        } else if (reason == SSL_ERROR_ZERO_RETURN) {
            set_errno_code(sock_ctx, ECONNRESET);
            return 0;

        } else {
            set_handshake_socket_error(sock_ctx);
            return 0;
        }
    }

    X509 *peer_cert = SSL_get_peer_certificate(sock_ctx->ssl);
    if (peer_cert == NULL) {
        set_socket_error(sock_ctx, EPROTO,
                    "TLS handshake error: peer presented no certificate");
        return 0;
    }

    X509_free(peer_cert);

    set_errno_code(sock_ctx, NO_ERROR);
    return 1;
}







