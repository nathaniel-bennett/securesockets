#ifndef SAFETLS__SOCKET_HASHMAP_H
#define SAFETLS__SOCKET_HASHMAP_H

#include "socket.h"

socket_ctx *get_tls_socket(int id);


int add_tls_socket(int id, socket_ctx *sock_ctx);

int del_tls_socket(int id);


#endif
