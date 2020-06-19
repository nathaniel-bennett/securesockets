#ifndef SAFETLS__SOCKET_H
#define SAFETLS__SOCKET_H

#include <sys/socket.h>

#include <openssl/ssl.h>



#define MAX_ERR_STRING 255
#define MAX_HOSTNAME 255

#define NO_ERROR 0

typedef struct socket_ctx_st socket_ctx;

enum socket_state {
    SOCKET_ERROR = 0,
    SOCKET_NEW,
    SOCKET_CONNECTING_DNS,
    SOCKET_CONNECTING_TCP,
    SOCKET_CONNECTING_TLS,
    SOCKET_FINISHING_CONN, /* for revocation or async functions */
    SOCKET_CONNECTED,
    SOCKET_LISTENING
};

struct socket_ctx_st {
    enum socket_state state;
    int id;

    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int fd;

    socket_ctx *accept_ctx;

    struct sockaddr *addr; /* TODO: copy to avoid invalid access? */
    socklen_t addrlen;

    int is_nonblocking;

    /* used primarily to hold information for setsockopt/getsockopt */
    char hostname[MAX_HOSTNAME+1];

    int error_code;
    char err_str[MAX_ERR_STRING+1];
    int block_padding_size;
};



socket_ctx *socket_ctx_new(int sockfd);

int already_accepting_connection(socket_ctx *sock_ctx);

socket_ctx *accept_sock_ctx_new(int accepted_fd, socket_ctx *listening_ctx);

void socket_ctx_free(socket_ctx *sock_ctx);

int prepare_socket_for_connection(socket_ctx *sock_ctx);

int attempt_socket_tls_connection(socket_ctx *sock_ctx);



int is_wrong_socket_state(socket_ctx* sock_ctx, int num, ...);

#endif
