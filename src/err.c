#include <errno.h>
#include <string.h>

#include <openssl/err.h>

#include "err_internal.h"
#include "socket.h"



void set_handshake_socket_error(socket_ctx *sock_ctx)
{
    unsigned long ssl_err = ERR_peek_error();
    long handshake_err = SSL_get_verify_result(sock_ctx->ssl);

    const char *handshake_str = X509_verify_cert_error_string(handshake_err);
    const char *ssl_str = ERR_reason_error_string(ssl_err);

    clear_all_errors(sock_ctx);

    switch (handshake_err) {
    case X509_V_OK:
        break;

    case X509_V_ERR_OUT_OF_MEM:
        set_errno_code(sock_ctx, ENOMEM);
        return;

    default:
        set_socket_error(sock_ctx, EPROTO,
                "TLS handshake error %li: %s", handshake_err, handshake_str);
        return;
    }

    if (ERR_GET_REASON(ssl_err) == ERR_R_MALLOC_FAILURE) {
        set_errno_code(sock_ctx, ENOMEM);
        return;
    }

    if (ERR_GET_LIB(ssl_err) == ERR_LIB_SSL) {
        switch(ERR_GET_REASON(ssl_err)) {
        case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE:
            set_socket_error(sock_ctx, EPROTO,
                        "TLS handshake error: peer sent alert "
                        "(likely no common TLS version/ciphers)");
            break;

            /* add more error cases here as needs be */

        default:
            set_socket_error(sock_ctx,
                        EPROTO, "TLS handshake error: %s", ssl_str);
        }
    } else {
        set_socket_error(sock_ctx, ECONNABORTED, "TLS error: %s", ssl_str);
    }

    return;
}

void set_errno_code(socket_ctx *sock_ctx, int errno_code)
{
    if (sock_ctx != NULL)
        sock_ctx->error_code = errno_code;
    errno = errno_code;
}

void set_socket_error(socket_ctx *sock_ctx, int error, char *err_string, ...)
{
    va_list args;

    clear_socket_errors(sock_ctx);

    errno = error;
    sock_ctx->error_code = error;

    va_start(args, err_string);
    vsnprintf(sock_ctx->err_str, MAX_ERR_STRING, err_string, args);
    va_end(args);
}


void set_ssl_socket_error(socket_ctx *sock_ctx)
{
    return set_socket_error_from_code(sock_ctx, ERR_peek_error());
}



void set_socket_error_from_code(socket_ctx *sock_ctx, unsigned long err)
{
    const char *err_string = ERR_reason_error_string(err);

    clear_all_errors(sock_ctx);

    if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE)
        set_errno_code(sock_ctx, ENOMEM);
    else
        set_socket_error(sock_ctx, ECANCELED, "TLS error: %s", err_string);
}

void clear_global_errors()
{
    ERR_clear_error();
    errno = NO_ERROR;
}

void clear_socket_errors(socket_ctx *sock_ctx)
{
    sock_ctx->error_code = NO_ERROR;
    memset(sock_ctx->err_str, '\0', MAX_ERR_STRING+1);
}

void clear_all_errors(socket_ctx *sock_ctx)
{
    clear_socket_errors(sock_ctx);
    clear_global_errors();
}



