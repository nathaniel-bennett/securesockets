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



add_executable(PollTests
        tests/poll_tests.cpp tests/test_timeouts.h)
target_link_libraries(PollTests "gtest" "gtest_main" "pthread")
target_link_libraries(PollTests "securesockets")

add_executable(SocketTests
        tests/socket_tests.cpp tests/test_timeouts.h)
target_link_libraries(SocketTests "gtest" "gtest_main" "pthread")
target_link_libraries(SocketTests "securesockets")
