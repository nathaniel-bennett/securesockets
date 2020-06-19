#ifndef SAFETLS__ERR_INTERNAL_H
#define SAFETLS__ERR_INTERNAL_H

#include "socket.h"


void set_ssl_socket_error(socket_ctx *sock_ctx);
void set_socket_error_from_code(socket_ctx *sock_ctx, unsigned long err);
void set_handshake_socket_error(socket_ctx *sock_ctx);

void set_socket_error(socket_ctx *sock_ctx, int error, char *err_string, ...);
void set_errno_code(socket_ctx *sock_ctx, int errno_code);

void clear_global_errors();
void clear_socket_errors(socket_ctx *sock_ctx);
void clear_all_errors(socket_ctx *sock_ctx);

#endif
