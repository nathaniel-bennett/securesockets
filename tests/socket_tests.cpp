

#include <gtest/gtest.h>

#include "test_timeouts.h"

/* C and C++ struggle to cooperate unless we direct them to */
extern "C" {

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include "../include/tls.h"


#define HOSTNAME "www.yahoo.com"
#define PORT "443"

}

class SocketTests : public testing::Test{
public:
    struct sockaddr* address;
    socklen_t addrlen;

    SocketTests()
    {
        struct addrinfo hints = {0};

        result = NULL;

        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = AF_INET;

        getaddrinfo(HOSTNAME, PORT, &hints, &result);

        if (result == NULL) {
            printf("Couldn't resolve DNS.\n");
            exit(1);
        }

        address = result->ai_addr;
        addrlen = result->ai_addrlen;
    }

    ~SocketTests()
    {
        freeaddrinfo(result);
    }

    virtual void SetUp()
    {

    }

    virtual void TearDown()
    {

    }

private:
    struct addrinfo* result;
};



void print_errors(int fd)
{
    char reason[256] = {0};
    socklen_t reason_len = 256;
    int error;
    socklen_t error_len = sizeof(error);
    int ret;

    fprintf(stderr, "Current errno code is %i: %s\n", errno, strerror(errno));

    ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len);
    if (ret == 0)
        fprintf(stderr, "Getsockopt errno code is %i: %s\n",
            error, strerror(error));
    else
        fprintf(stderr, "Couldn't get getsockopt errno code\n");

    ret = getsockopt(fd, IPPROTO_TLS,
        SO_TLS_ERROR_STRING, reason, &reason_len);
    if (ret != 0)
        fprintf(stderr, "Couldn't get TLS error string\n");
    else
        fprintf(stderr, "TLS error string: %s\n", reason);
}

/*******************************************************************************
 *                              TEST CASES
 ******************************************************************************/

TEST_F(SocketTests, SocketCreation) {

    int socket_return = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    int socket_errno = errno;

    EXPECT_GT(socket_return, 0);
    EXPECT_EQ(socket_errno, 0);
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketTests, SocketWrongDomain) {

    int socket_return = socket(AF_NETLINK, SOCK_STREAM, IPPROTO_TLS);
    int socket_errno = errno;

    EXPECT_EQ(socket_return, -1);
    /* TODO: test the errno here too */
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketTests, SocketWrongType) {
    /* TODO: someday we'll implement DTLS. this should be changed then */

    int socket_return = socket(AF_INET, SOCK_DGRAM, IPPROTO_TLS);
    int socket_errno = errno;

    EXPECT_EQ(socket_errno, EPROTONOSUPPORT);
    EXPECT_EQ(socket_return, -1);
    /* TODO: test the errno here too */
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketTests, SocketWithNonblockType) {

    int socket_return = socket(AF_INET,
        SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    EXPECT_GE(socket_return, 0);
    EXPECT_EQ(socket_errno, 0);
    /* TODO: test the errno here too */
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            errno, strerror(errno));
    else
        close(socket_return);
}

TEST_F(SocketTests, ConnectWithNonblockSocket) {

    int socket_return = socket(AF_INET,
        SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            socket_errno, strerror(socket_errno));

    ASSERT_GE(socket_return, 0);
    EXPECT_EQ(socket_errno, 0);
    /* TODO: test the errno here too */


    int hostname_setsockopt_return = setsockopt(socket_return,
        IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    if (hostname_setsockopt_return != 0) {
        fprintf(stderr, "Hostname setsockopt failed with errno %i: %s\n",
            hostname_errno, strerror(hostname_errno));
        close(socket_return);
    }

    ASSERT_EQ(hostname_setsockopt_return, 0);
    EXPECT_EQ(hostname_errno, 0);

    int connect_return = connect(socket_return, address, addrlen);
    int connect_errno = errno;

    EXPECT_EQ(connect_return, -1);
    EXPECT_EQ(connect_errno, EINPROGRESS);
    if (connect_return != -1)
        fprintf(stderr, "Connect returned 0 (should block)\n");
    else if (connect_errno != EINPROGRESS)
        fprintf(stderr, "Connect errno was %i: %s\n",
            connect_errno, strerror(connect_errno));

    close(socket_return);
}


TEST_F(SocketTests, Socket) {

    int socket_return = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    EXPECT_GE(socket_return, 0);
    /* TODO: test the errno here too */
    if (socket_return < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            errno, strerror(errno));
    else
        close(socket_return);
}


TEST_F(SocketTests, DoubleConnectFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, SO_TLS_HOSTNAME,
        HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);

    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);

    int second_connect_ret = connect(fd, address, addrlen);

    EXPECT_EQ(second_connect_ret, -1);
    EXPECT_EQ(errno, EISCONN);

    if (second_connect_ret == -1)
        print_errors(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)

}

TEST_F(SocketTests, ConnectThenListenFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, SO_TLS_HOSTNAME,
        HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);

    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);

    int listen_ret = listen(fd, SOMAXCONN);

    EXPECT_EQ(listen_ret, -1);
    EXPECT_EQ(errno, EOPNOTSUPP);

    if (listen_ret == -1)
        print_errors(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}



TEST_F(SocketTests, ConnectThenBindFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    EXPECT_EQ(errno, 0);
    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, SO_TLS_HOSTNAME,
        HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);


    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);

    struct sockaddr_in int_addr = {0};

    int_addr.sin_family = AF_INET;
    int_addr.sin_port = 0;
    int_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);


    int bind_ret = bind(fd, (struct sockaddr*) &int_addr, sizeof(sockaddr_in));

    EXPECT_EQ(bind_ret, -1);
    EXPECT_EQ(errno, EOPNOTSUPP);

    if (bind_ret == -1)
        print_errors(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)

}


TEST_F(SocketTests, ConnectThenAcceptFail) {

    TEST_TIMEOUT_BEGIN

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS);
    if (fd < 0)
        fprintf(stderr, "Socket failed to be created: %s\n", strerror(errno));

    ASSERT_GE(fd, 0);

    int setsockopt_ret = setsockopt(fd, IPPROTO_TLS, SO_TLS_HOSTNAME,
        HOSTNAME, strlen(HOSTNAME) + 1);
    if (setsockopt_ret < 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(setsockopt_ret, 0);

    int connect_ret = connect(fd, address, addrlen);
    if (connect_ret != 0) {
        print_errors(fd);
        close(fd);
    }

    ASSERT_EQ(connect_ret, 0);

    /* bad address to bind to, but shouldn't matter */
    struct sockaddr temp_addr;
    socklen_t temp_addrlen;
    int accept_ret = accept(fd, &temp_addr, &temp_addrlen);

    EXPECT_EQ(accept_ret, -1);
    EXPECT_EQ(errno, EOPNOTSUPP);

    if (accept_ret == -1)
        print_errors(fd);

    close(fd);

    TEST_TIMEOUT_FAIL_END(TIMEOUT_LONG)
}