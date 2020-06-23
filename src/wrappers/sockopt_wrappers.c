#include <errno.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../err_internal.h"
#include "../original_posix.h"
#include "../socket_hashmap.h"
#include "../../include/tls.h"

/* SO_ERROR */
int get_socket_error(socket_ctx *sock_ctx, int *error, socklen_t *len);

/* Hostname */
int get_hostname(socket_ctx *sock_ctx, char *hostname, socklen_t *len);
int set_hostname(socket_ctx *sock_ctx, char *hostname, socklen_t len);

/* TLS protocol range */
int get_min_protocol(socket_ctx *sock_ctx, int *version, socklen_t *len);
int set_min_protocol(socket_ctx *sock_ctx, int version, socklen_t len);
int get_max_protocol(socket_ctx *sock_ctx, int *version, socklen_t *len);
int set_max_protocol(socket_ctx *sock_ctx, int version, socklen_t len);
int get_chosen_protocol(socket_ctx *sock_ctx, int *version, socklen_t *len);

/* TLS-specific errors */
int get_error(socket_ctx *sock_ctx, char *buffer, socklen_t *buf_len);
int get_global_error(char *buffer, socklen_t *buf_len);

/* TLS compression */
int get_tls_compression(socket_ctx *sock_ctx, int *val, socklen_t *len);
int set_tls_compression(socket_ctx *sock_ctx, int *val, socklen_t len);

/* TLS 1.3+ Block Padding */
int get_record_padding(socket_ctx *sock_ctx, int *val, socklen_t *len);
int set_record_padding(socket_ctx *sock_ctx, int *val, socklen_t len);



/* Helper functions */
int size_not_within_range(socklen_t value, int min_size, int max_size);
int size_not_equal_to(socklen_t value, long expected_size);



/*******************************************************************************
 *                 GETSOCKOPT/SETSOCKOPT IMPLEMENTATIONS
 ******************************************************************************/

int WRAPPER_getsockopt(int sockfd, int level,
                       int optname, void *optval, socklen_t *optlen)
{
    socket_ctx *sock_ctx;

    if (optval == NULL || optlen == NULL || *optlen <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* special case--for retrieving OpenSSL error on socket failure */
    if (sockfd == -1 && level == IPPROTO_TLS && optname == SO_TLS_ERROR_STRING)
        return get_global_error((char*) optval, optlen);


    sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_getsockopt(sockfd, level, optname, optval, optlen);

    if (level == SOL_SOCKET && optname == SO_ERROR)
        return get_socket_error(sock_ctx, (int*) optval, optlen);

    /* regular getsockopt on a TLS socket */
    if (level != IPPROTO_TLS)
        return o_getsockopt(sock_ctx->fd, level, optname, optval, optlen);


    if (optname != SO_TLS_ERROR_STRING &&  optname != SO_TLS_ERROR_CODE)
        clear_all_errors(sock_ctx);

    /* TLS setsockopt on a TLS socket */
    switch(optname) {
    case SO_TLS_HOSTNAME:
        return get_hostname(sock_ctx, (char*) optval, optlen);

    case SO_TLS_MIN_PROTOCOL:
        return get_min_protocol(sock_ctx, (int*) optval, optlen);

    case SO_TLS_MAX_PROTOCOL:
        return get_max_protocol(sock_ctx, (int*) optval, optlen);

    case SO_TLS_CHOSEN_PROTOCOL:
        return get_chosen_protocol(sock_ctx, (int*) optval, optlen);

    case SO_TLS_ERROR_STRING:
        return get_error(sock_ctx, (char*) optval, optlen);

    case SO_TLS_COMPRESSION:
        return get_tls_compression(sock_ctx, (int*) optval, optlen);

    case SO_TLS_1_3_RECORD_PADDING:
        return get_record_padding(sock_ctx, (int *)optval, optlen);


        /* TODO: add more options here */

    default:
        errno = ENOPROTOOPT;
        return -1;
    }
}


int WRAPPER_setsockopt(int sockfd, int level,
                       int optname, const void *optval, socklen_t optlen)
{
    socket_ctx *sock_ctx;

    sock_ctx = get_tls_socket(sockfd);
    if (sock_ctx == NULL)
        return o_setsockopt(sockfd, level, optname, optval, optlen);

    clear_all_errors(sock_ctx);

    if (optval == NULL || optlen <= 0) {
        errno = EINVAL;
        return -1;
    }

    /* TODO: add to stack if AF_HOSTNAME */
    if (level != IPPROTO_TLS)
        return o_setsockopt(sock_ctx->fd, level, optname, optval, optlen);

    switch(optname) {
    case SO_TLS_HOSTNAME:
        return set_hostname(sock_ctx, (char*) optval, optlen);

    case SO_TLS_MIN_PROTOCOL:
        return set_min_protocol(sock_ctx, *((int*) optval), optlen);

    case SO_TLS_MAX_PROTOCOL:
        return set_max_protocol(sock_ctx, *((int*) optval), optlen);

    case SO_TLS_COMPRESSION:
        return set_tls_compression(sock_ctx, (int*) optval, optlen);

    case SO_TLS_1_3_RECORD_PADDING:
        return set_record_padding(sock_ctx, (int *)optval, optlen);


        /* TODO: add more options here */

    default:
        errno = ENOPROTOOPT;
        return -1;
    }
}



/*******************************************************************************
 *         INDIVIDUAL SETSOCKOPT/GETSOCKOPT FUNCTION IMPLEMENTATIONS
 ******************************************************************************/

int get_socket_error(socket_ctx *sock_ctx, int *error, socklen_t *len)
{
    if (size_not_equal_to(*len, sizeof(int)))
        return -1;

    *error = sock_ctx->error_code;
    sock_ctx->error_code = NO_ERROR;

    return 0;
}



int get_hostname(socket_ctx* sock_ctx, char *hostname, socklen_t *len)
{
    int hostname_len = strlen(sock_ctx->hostname) + 1;
    int final_len = (*len > hostname_len) ? hostname_len : *len;

    if (strlen(sock_ctx->hostname) == 0) {
        errno = EINVAL; /* TODO: change this to better descriptiveness */
        return -1;
    }

    memcpy(hostname, sock_ctx->hostname, final_len);
    *len = (socklen_t) final_len;
    errno = 0;
    return 0;
}

int set_hostname(socket_ctx* sock_ctx, char *hostname, socklen_t len)
{

    if (size_not_within_range(len, 1, MAX_HOSTNAME))
        return -1;

    if (is_wrong_socket_state(sock_ctx, 1, SOCKET_NEW))
        return -1;

    memset(sock_ctx->hostname, '\0', MAX_HOSTNAME+1);
    memcpy(sock_ctx->hostname, hostname, len);

    return 0;
}



int get_min_protocol(socket_ctx *sock_ctx, int *version, socklen_t *len)
{
    int ret;

    if (size_not_equal_to(*len, sizeof(int)))
        return -1;

    ret = SSL_CTX_get_min_proto_version(sock_ctx->ssl_ctx);
    switch (ret) {
    case TLS1_3_VERSION:
        *version = 3;
        return 0;
    case TLS1_2_VERSION:
        *version = 2;
        return 0;
    case TLS1_1_VERSION:
        *version = 1;
        return 0;
    case TLS1_VERSION:
        *version = 0;
        return 0;
    default:
        errno = -EINVAL;
        return -1;
    }
}

int set_min_protocol(socket_ctx *sock_ctx, int version, socklen_t len)
{
    int version_macro;
    int ret;

    if (size_not_equal_to(len, sizeof(int)))
        return -1;

    if (is_wrong_socket_state(sock_ctx, 2, SOCKET_NEW, SOCKET_LISTENING))
        return -1;

    switch (version) {
    case 0:
        version_macro = TLS1_VERSION;
        break;
    case 1:
        version_macro = TLS1_1_VERSION;
        break;
    case 2:
        version_macro = TLS1_2_VERSION;
        break;
    case 3:
        version_macro = TLS1_3_VERSION;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    ret = SSL_CTX_set_min_proto_version(sock_ctx->ssl_ctx, version_macro);
    if (ret != 1) {
        ERR_get_error();
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int get_max_protocol(socket_ctx *sock_ctx, int *version, socklen_t *len)
{
    int ret;

    if (size_not_equal_to(*len, sizeof(int)))
        return -1;

    ret = SSL_CTX_get_max_proto_version(sock_ctx->ssl_ctx);
    switch (ret) {
    case TLS1_3_VERSION:
        *version = 3;
        return 0;
    case TLS1_2_VERSION:
        *version = 2;
        return 0;
    case TLS1_1_VERSION:
        *version = 1;
        return 0;
    case TLS1_VERSION:
        *version = 0;
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

int set_max_protocol(socket_ctx *sock_ctx, int version, socklen_t len)
{
    int version_macro;
    int ret;

    if (size_not_equal_to(len, sizeof(int)))
        return -1;

    if (is_wrong_socket_state(sock_ctx, 1, SOCKET_NEW))
        return -1;

    switch (version) {
    case 0:
        version_macro = TLS1_VERSION;
        break;
    case 1:
        version_macro = TLS1_1_VERSION;
        break;
    case 2:
        version_macro = TLS1_2_VERSION;
        break;
    case 3:
        version_macro = TLS1_3_VERSION;
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    ret = SSL_CTX_set_max_proto_version(sock_ctx->ssl_ctx, version_macro);
    if (ret != 1) {
        errno = EINVAL; /* TODO: change this to a more descriptive code */
        return -1;
    }

    return 0;
}

int get_chosen_protocol(socket_ctx *sock_ctx, int *version, socklen_t *len)
{
    if (size_not_equal_to(*len, sizeof(int)))
        return -1;

   if (is_wrong_socket_state(sock_ctx, 1, SOCKET_CONNECTED))
       return -1;

   switch (SSL_version(sock_ctx->ssl)) {
   case TLS1_3_VERSION:
       *version = 3;
       return 0;
   case TLS1_2_VERSION:
       *version = 2;
       return 0;
   case TLS1_1_VERSION:
       *version = 1;
       return 0;
   case TLS1_VERSION:
       *version = 0;
       return 0;
   default:
       errno = ENODATA;
       return -1;
   }
}



int get_error(socket_ctx *sock_ctx, char *buffer, socklen_t *buf_len)
{
    if (strlen(sock_ctx->err_str) == 0) {
        errno = ENODATA;
        return -1;
    }

    int err_len = strlen(sock_ctx->err_str) + 1;

    if (*buf_len > err_len)
        *buf_len = err_len;

    memcpy(buffer, sock_ctx->err_str, *buf_len);
    return 0;
}

int get_global_error(char *buffer, socklen_t *buf_len)
{
    int err = ERR_get_error();
    const char *msg_start = "TLS error: ";
    const char *reason = ERR_reason_error_string(err);

    int msg_size = strlen(msg_start) + strlen(reason) + 1; /* +1 for '\0' */
    char err_message[msg_size];

    if (buffer == NULL || buf_len == NULL || *buf_len <= 0) {
        errno = EINVAL;
        return -1;
    }

    if (err == 0) {
        errno = ENODATA;
        return -1;
    }

    memset(err_message, 0, msg_size);
    strcpy(err_message, msg_start);
    strcat(err_message, reason);

    if (*buf_len > msg_size)
        *buf_len = msg_size;

    memcpy(buffer, err_message, *buf_len);

    errno = NO_ERROR;
    return 0;
}



int set_tls_compression(socket_ctx *sock_ctx, int *val, socklen_t len) {

    if (size_not_equal_to(len, sizeof(int)))
        return -1;

    if (is_wrong_socket_state(sock_ctx, 2, SOCKET_NEW, SOCKET_LISTENING))
        return -1;

    if (*val == 0)
        SSL_CTX_set_options(sock_ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);
    else
        SSL_CTX_clear_options(sock_ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);

    return 0;
}

int get_tls_compression(socket_ctx *sock_ctx, int *val, socklen_t *len)
{
    if (size_not_equal_to(*len, sizeof(int)))
        return -1;

    unsigned long opts = SSL_CTX_get_options(sock_ctx->ssl_ctx);
    if (opts & SSL_OP_NO_COMPRESSION)
        *val = 0;
    else
        *val = 1;

    return 0;
}



int get_record_padding(socket_ctx *sock_ctx, int *val, socklen_t *len)
{
    if (size_not_equal_to(*len, sizeof(int)))
        return -1;

    *val = sock_ctx->block_padding_size;
    return 0;
}

int set_record_padding(socket_ctx *sock_ctx, int *val, socklen_t len)
{
    if (size_not_equal_to(len, sizeof(int)))
        return -1;

    int ret = SSL_CTX_set_block_padding(sock_ctx->ssl_ctx, *val);
    if (ret != 1) {
        clear_global_errors();
        errno = EINVAL;
        return -1;
    }

    /* a size of 1 or 0 indicates no padding. We simplify this to just 0 */
    if (*val == 1)
        sock_ctx->block_padding_size = 0;
    else
        sock_ctx->block_padding_size = *val;

    return 0;
}



/*******************************************************************************
 *                          HELPER FUNCTIONS
 ******************************************************************************/

int size_not_within_range(socklen_t value,
                          int min_size, int max_size)
{
    if (value >= min_size && value <= max_size) {
        errno = NO_ERROR;
        return 0;

    } else {
        errno = EINVAL;
        return 1;
    }
}

int size_not_equal_to(socklen_t value, long expected_size)
{
    if (value == expected_size) {
        errno = NO_ERROR;
        return 0;

    } else {
        errno = EINVAL;
        return 1;
    }
}
