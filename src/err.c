#include <errno.h>
#include <string.h>

#include <openssl/err.h>

#include "err_internal.h"
#include "socket.h"



void set_err_string(socket_ctx *sock_ctx, char *error_string, ...)
{
    va_list args;

    clear_socket_errors(sock_ctx);

    va_start(args, error_string);
    vsnprintf(sock_ctx->err_str, MAX_ERR_STRING, error_string, args);
    va_end(args);
}

void set_handshake_socket_error(socket_ctx *sock_ctx)
{
    unsigned long ssl_err = ERR_peek_error();
    long handshake_err = SSL_get_verify_result(sock_ctx->ssl);

    clear_all_errors(sock_ctx);

    const char *handshake_e_str = X509_verify_cert_error_string(handshake_err);
    const char *ssl_err_string = ERR_reason_error_string(ssl_err);

    switch (handshake_err) {
    case X509_V_OK:
        break;

    case X509_V_ERR_OUT_OF_MEM:
        errno = ENOMEM;
        return;

    default:
        set_err_string(sock_ctx, "TLS handshake error %li: %s",
            handshake_err, handshake_e_str);
        errno = EPROTO;
        return;
    }

    if (ERR_GET_REASON(ssl_err) == ERR_R_MALLOC_FAILURE) {
        errno = ENOMEM;
        return;
    }

    if (ERR_GET_LIB(ssl_err) == ERR_LIB_SSL) {

        switch(ERR_GET_REASON(ssl_err)) {
        case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE:
            set_err_string(sock_ctx, "TLS handshake error: peer sent alert "
                                     "(likely no common TLS version/ciphers)");
            break;

        default:
            set_err_string(sock_ctx,
                "TLS handshake error: %s",
                ssl_err_string);
        }

        errno = EPROTO;
        return;
    }

    set_err_string(sock_ctx, "TLS error: %s", ssl_err_string);
}

void set_socket_error_ssl(socket_ctx *sock_ctx)
{
    return set_socket_error_from_code(sock_ctx, ERR_peek_error());
}



void set_socket_error_from_code(socket_ctx *sock_ctx, unsigned long err)
{
    const char *err_string = ERR_reason_error_string(err);

    clear_all_errors(sock_ctx);

    if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE) {
        errno = ENOMEM;
        return;
    }

    set_err_string(sock_ctx, "TLS error: %s", err_string);
    errno = ECANCELED;
}

void set_errno_from_ssl()
{
    unsigned long err = ERR_peek_error();
    if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE) {
        errno = ENOMEM;
    }

    errno = ECANCELED;
}


void clear_global_errors()
{
    ERR_clear_error();
    errno = NO_ERROR;
}

void clear_socket_errors(socket_ctx *sock_ctx)
{
    memset(sock_ctx->err_str, '\0', MAX_ERR_STRING+1);
}

void clear_all_errors(socket_ctx *sock_ctx)
{
    clear_socket_errors(sock_ctx);
    clear_global_errors();
}


