#ifndef SAFETLS__ERR_INTERNAL_H
#define SAFETLS__ERR_INTERNAL_H

#include "socket.h"


void set_err_string(socket_ctx *sock_ctx, char *error_string, ...);
void set_handshake_socket_error(socket_ctx *sock_ctx);
void set_socket_error_ssl(socket_ctx *sock_ctx);
void set_socket_error_from_code(socket_ctx *sock_ctx, unsigned long err);
void set_errno_from_ssl();

void clear_global_errors();
void clear_socket_errors(socket_ctx *sock_ctx);
void clear_all_errors(socket_ctx *sock_ctx);

#endif
