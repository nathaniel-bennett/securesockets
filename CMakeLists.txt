cmake_minimum_required(VERSION 3.16)
project(securesockets C)

set(CMAKE_C_STANDARD 90)

link_libraries("ssl" "crypto")

add_library(securesockets include/tls.h src/wrappers/socket_wrappers.c src/original_posix.h src/socket_hashmap.h src/socket_hashmap.c src/socket.c src/socket.h src/wrappers/sockopt_wrappers.c src/original_posix.c src/err.c src/err_internal.h include/tls_async.h src/wrappers/async_wrappers.c src/original_async.c src/original_async.h)