cmake_minimum_required(VERSION 3.16)
project(securesockets C CXX)

set(CMAKE_C_STANDARD 90)
set(CMAKE_CXX_STANDARD 11)

link_libraries("ssl" "crypto")

add_library(securesockets
        include/tls.h
        include/tls_async.h
        src/wrappers/socket_wrappers.c
        src/wrappers/sockopt_wrappers.c
        src/wrappers/async_wrappers.c
        src/original_posix.h
        src/socket_hashmap.h
        src/socket_hashmap.c
        src/socket.c
        src/socket.h
        src/original_posix.c
        src/err.c
        src/err_internal.h
        src/original_async.c
        src/original_async.h)



add_executable(async_test_simple
        tests/async_test.cpp)
target_link_libraries(async_test_simple "gtest" "gtest_main" "pthread")
target_link_libraries(async_test_simple "securesockets")

