cmake_minimum_required(VERSION 3.16)
project(securesockets C)

set(CMAKE_C_STANDARD 90)

link_libraries("ssl" "crypto")

add_library(securesockets include/tls.h src/wrappers/socket_wrappers.c src/original_functions.h src/socket_hashmap.h src/socket_hashmap.c src/socket.c src/socket.h src/wrappers/sockopt_wrappers.c src/original_functions.c src/err.c src/err_internal.h)