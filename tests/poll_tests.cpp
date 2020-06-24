#include <gtest/gtest.h>

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>

#include "../include/tls.h"
#include "../include/tls_async.h"

#define HOSTNAME "www.yahoo.com"
#define PORT "443"

}

#define MAX_FDS 500

void print_errors(int fd);

class PollTests : public testing::Test {
public:
    struct sockaddr* address;
    socklen_t addrlen;

    int fd;
    int fds[MAX_FDS];

    PollTests()
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

    ~PollTests()
    {
        freeaddrinfo(result);
    }

    virtual void SetUp()
    {
        int i;
        fd = -1;

        for (i = 0; i < MAX_FDS; i++)
            fds[i] = -1;
    }

    virtual void TearDown()
    {
        int i;

        if (fd != -1) {
            print_errors(fd);
            close(fd);
        }

        for (i = 0; i < MAX_FDS; i++) {
            if (fds[i] != -1) {
                print_errors(fds[i]);
                close(fds[i]);
            }
        }
    }

private:
    struct addrinfo* result;
};

TEST_F(PollTests, Connect1) {

    fd = socket(AF_INET,
        SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    if (fd < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            socket_errno, strerror(socket_errno));

    EXPECT_EQ(socket_errno, 0);
    ASSERT_GE(fd, 0);

    int hostname_setsockopt_return = setsockopt(fd,
        IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    EXPECT_EQ(hostname_errno, 0);
    ASSERT_EQ(hostname_setsockopt_return, 0);

    int connect_return = connect(fd, address, addrlen);
    int connect_errno = errno;

    EXPECT_EQ(connect_errno, EINPROGRESS);
    ASSERT_EQ(connect_return, -1);

    struct pollfd fd_struct = {0};
    fd_struct.fd = fd;
    fd_struct.events = POLLIN | POLLOUT | POLLERR | POLLPRI | POLLHUP;

    int poll_return = poll(&fd_struct, 1, 6000);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 1);

    ASSERT_FALSE(fd_struct.revents & POLLERR);
    ASSERT_FALSE(fd_struct.revents & POLLHUP);
    ASSERT_FALSE(fd_struct.revents & POLLNVAL);
    ASSERT_FALSE(fd_struct.revents & POLLPRI);

    if (!(fd_struct.revents & POLLOUT))
        fprintf(stderr, "Socket wasn't ready for writing\n");

    ASSERT_TRUE(fd_struct.revents & POLLOUT);

    int connect_2nd_return = connect(fd, address, addrlen);
    int connect_2nd_errno = errno;

    EXPECT_EQ(connect_2nd_return, -1);
    EXPECT_EQ(connect_2nd_errno, EISCONN);

    close(fd);
    fd = -1;
}


TEST_F(PollTests, ConnectTimeout1) {

    fd = socket(AF_INET,
        SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    if (fd < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            socket_errno, strerror(socket_errno));

    EXPECT_EQ(socket_errno, 0);
    ASSERT_GE(fd, 0);

    int hostname_setsockopt_return = setsockopt(fd,
        IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    EXPECT_EQ(hostname_errno, 0);
    ASSERT_EQ(hostname_setsockopt_return, 0);

    int connect_return = connect(fd, address, addrlen);
    int connect_errno = errno;

    EXPECT_EQ(connect_errno, EINPROGRESS);
    ASSERT_EQ(connect_return, -1);

    struct pollfd fd_struct = {0};
    fd_struct.fd = fd;
    fd_struct.events = POLLIN | POLLOUT | POLLERR | POLLPRI | POLLHUP;

    int poll_return = poll(&fd_struct, 1, 20);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 0);

    close(fd);
    fd = -1;
}


TEST_F(PollTests, ConnectWriteRead1) {

    fd = socket(AF_INET,
        SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
    int socket_errno = errno;

    if (fd < 0)
        fprintf(stderr, "Socket creation failed with errno %i: %s\n",
            socket_errno, strerror(socket_errno));

    EXPECT_EQ(socket_errno, 0);
    ASSERT_GE(fd, 0);

    int hostname_setsockopt_return = setsockopt(fd,
        IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
    int hostname_errno = errno;

    EXPECT_EQ(hostname_errno, 0);
    ASSERT_EQ(hostname_setsockopt_return, 0);

    int connect_return = connect(fd, address, addrlen);
    int connect_errno = errno;

    ASSERT_EQ(connect_return, -1);
    ASSERT_EQ(connect_errno, EINPROGRESS);

    struct pollfd fd_struct = {0};
    fd_struct.fd = fd;
    fd_struct.events = POLLIN | POLLOUT;

    int poll_return = poll(&fd_struct, 1, 6000);
    int poll_errno = errno;

    EXPECT_EQ(poll_errno, 0);
    ASSERT_EQ(poll_return, 1);

    ASSERT_FALSE(fd_struct.revents & POLLERR);
    ASSERT_FALSE(fd_struct.revents & POLLHUP);
    ASSERT_FALSE(fd_struct.revents & POLLNVAL);
    ASSERT_FALSE(fd_struct.revents & POLLPRI);

    if (!(fd_struct.revents & POLLOUT))
        fprintf(stderr, "Socket wasn't ready for writing\n");

    ASSERT_TRUE(fd_struct.revents & POLLOUT);

    int total_write_len = strlen("GET / HTTP/1.1\r\n\r\n")+1;

    int write_return = write(fd,
        "GET / HTTP/1.1\r\n\r\n", total_write_len);
    int write_errno = errno;

    if (write_return < total_write_len && write_return > 0)
        fprintf(stderr, "Not all of the message was written\n");
    else if (write_return == 0)
        fprintf(stderr, "Unexpected EOF\n");
    else if (write_return < 0)
        print_errors(fd);

    EXPECT_EQ(write_errno, 0);
    ASSERT_EQ(write_return, total_write_len);

    char buf[10000] = {0};
    int total_read_len = 0;
    int curr_read_len;

    curr_read_len = read(fd, buf, 10000);
    EXPECT_EQ(curr_read_len, -1);
    EXPECT_EQ(errno, EAGAIN);

    fd_struct.events = POLLIN;
    poll_return = poll(&fd_struct, 1, 4000);
    ASSERT_EQ(poll_return, 1);

    ASSERT_TRUE(fd_struct.revents & POLLIN);

    curr_read_len = read(fd, &buf[total_read_len], 10000-total_read_len);
    int read_errno = errno;

    if (curr_read_len == 0) {
        fprintf(stderr, "Unexpected EOF on file descriptor\n");
    } else if (curr_read_len < 0){
        print_errors(fd);
    }

    EXPECT_EQ(read_errno, 0);
    ASSERT_GT(curr_read_len, 0);

    close(fd);
    fd = -1;
}

TEST_F(PollTests, Connect5) {

    const int FD_COUNT = 5;
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
        int socket_errno = errno;

        if (fds[i] < 0)
            fprintf(stderr, "Socket creation failed with errno %i: %s\n",
                socket_errno, strerror(socket_errno));

        EXPECT_EQ(socket_errno, 0);
        ASSERT_GT(fds[i], 0);

        int hostname_setsockopt_return = setsockopt(fds[i],
            IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
        int hostname_errno = errno;

        EXPECT_EQ(hostname_errno, 0);
        ASSERT_EQ(hostname_setsockopt_return, 0);

        int connect_return = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        EXPECT_EQ(connect_errno, EINPROGRESS);
        ASSERT_EQ(connect_return, -1);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left_to_connect = FD_COUNT;
    while(fds_left_to_connect > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0); /* EALREADY being returned... need to fix */
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            if (fd_structs[i].revents == 0)
                continue;

            num_fds_ready++;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            if (!(fd_structs[i].revents & POLLOUT)) {
                fprintf(stderr, "Socket wasn't ready for writing\n");
                continue;
            }

            ASSERT_TRUE(fd_structs[i].revents & POLLOUT);

            int connect_2nd_return = connect(fds[i], address, addrlen);
            int connect_2nd_errno = errno;

            EXPECT_EQ(connect_2nd_return, -1);
            EXPECT_EQ(connect_2nd_errno, EISCONN);

            fd_structs[i].events = 0;
        }

        ASSERT_EQ(num_fds_ready, poll_return);

        fds_left_to_connect -= num_fds_ready;
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}

TEST_F(PollTests, Connect23) {

    const int FD_COUNT = 23;
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
        int socket_errno = errno;

        if (fds[i] < 0)
            fprintf(stderr, "Socket creation failed with errno %i: %s\n",
                socket_errno, strerror(socket_errno));

        EXPECT_EQ(socket_errno, 0);
        ASSERT_GT(fds[i], 0);

        int hostname_setsockopt_return = setsockopt(fds[i],
            IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
        int hostname_errno = errno;

        EXPECT_EQ(hostname_errno, 0);
        ASSERT_EQ(hostname_setsockopt_return, 0);

        int connect_return = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        EXPECT_EQ(connect_errno, EINPROGRESS);
        ASSERT_EQ(connect_return, -1);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left_to_connect = FD_COUNT;
    while(fds_left_to_connect > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0); /* EALREADY being returned... need to fix */
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            if (fd_structs[i].revents == 0)
                continue;

            num_fds_ready++;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            if (!(fd_structs[i].revents & POLLOUT)) {
                fprintf(stderr, "Socket wasn't ready for writing\n");
                continue;
            }

            ASSERT_TRUE(fd_structs[i].revents & POLLOUT);

            int connect_2nd_return = connect(fds[i], address, addrlen);
            int connect_2nd_errno = errno;

            EXPECT_EQ(connect_2nd_return, -1);
            EXPECT_EQ(connect_2nd_errno, EISCONN);

            fd_structs[i].events = 0;
        }

        ASSERT_EQ(num_fds_ready, poll_return);

        fds_left_to_connect -= num_fds_ready;
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}

TEST_F(PollTests, ConnectWriteRead5) {

    const int FD_COUNT = 5;
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
        int socket_errno = errno;

        if (fds[i] < 0)
            fprintf(stderr, "Socket creation failed with errno %i: %s\n",
                socket_errno, strerror(socket_errno));

        EXPECT_EQ(socket_errno, 0);
        ASSERT_GT(fds[i], 0);

        int hostname_setsockopt_return = setsockopt(fds[i],
            IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
        int hostname_errno = errno;

        EXPECT_EQ(hostname_errno, 0);
        ASSERT_EQ(hostname_setsockopt_return, 0);

        int connect_return = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        EXPECT_EQ(connect_errno, EINPROGRESS);
        ASSERT_EQ(connect_return, -1);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left = FD_COUNT;
    while(fds_left > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0);
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            char buf[10000] = {0};
            int total_read_len = 0;
            int curr_read_len;

            if (fd_structs[i].revents == 0)
                continue;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            num_fds_ready++;

            if (fd_structs[i].revents & POLLOUT) { /* ready for write */
                int connect_2nd_return = connect(fds[i], address, addrlen);
                int connect_2nd_errno = errno;

                EXPECT_EQ(connect_2nd_return, -1);
                EXPECT_EQ(connect_2nd_errno, EISCONN);


                int total_write_len = strlen("GET / HTTP/1.1\r\n\r\n")+1;

                int write_return = write(fds[i],
                    "GET / HTTP/1.1\r\n\r\n", total_write_len);
                int write_errno = errno;

                if (write_return < total_write_len && write_return > 0)
                    fprintf(stderr, "Not all of the message was written\n");
                else if (write_return == 0)
                    fprintf(stderr, "Unexpected EOF\n");

                EXPECT_EQ(write_errno, 0);
                ASSERT_EQ(write_return, total_write_len);

                fd_structs[i].events = POLLIN | POLLHUP | POLLERR;

            } else if (fd_structs[i].revents & POLLIN) { /* ready for read */
                curr_read_len = read(fds[i], buf, 10000);
                int read_errno = errno;

                if (curr_read_len == 0) {
                    fprintf(stderr, "Unexpected EOF on file descriptor\n");
                } else if (curr_read_len < 0){
                    print_errors(fd);
                }

                EXPECT_EQ(read_errno, 0);
                ASSERT_GT(curr_read_len, 0);

                fd_structs[i].events = 0;

                fds_left -= 1;

            }
        }

        ASSERT_EQ(num_fds_ready, poll_return);
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}

TEST_F(PollTests, ConnectWriteRead47) {

    const int FD_COUNT = 47;
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
        int socket_errno = errno;

        if (fds[i] < 0)
            fprintf(stderr, "Socket creation failed with errno %i: %s\n",
                socket_errno, strerror(socket_errno));

        EXPECT_EQ(socket_errno, 0);
        ASSERT_GT(fds[i], 0);

        int hostname_setsockopt_return = setsockopt(fds[i],
            IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
        int hostname_errno = errno;

        EXPECT_EQ(hostname_errno, 0);
        ASSERT_EQ(hostname_setsockopt_return, 0);

        int connect_return = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        EXPECT_EQ(connect_errno, EINPROGRESS);
        ASSERT_EQ(connect_return, -1);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left = FD_COUNT;
    while(fds_left > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0); /* EALREADY being returned... need to fix */
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            char buf[10000] = {0};
            int total_read_len = 0;
            int curr_read_len;

            if (fd_structs[i].revents == 0)
                continue;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            num_fds_ready++;

            if (fd_structs[i].revents & POLLOUT) { /* ready for write */
                int connect_2nd_return = connect(fds[i], address, addrlen);
                int connect_2nd_errno = errno;

                EXPECT_EQ(connect_2nd_return, -1);
                EXPECT_EQ(connect_2nd_errno, EISCONN);


                int total_write_len = strlen("GET / HTTP/1.1\r\n\r\n")+1;

                int write_return = write(fds[i],
                    "GET / HTTP/1.1\r\n\r\n", total_write_len);
                int write_errno = errno;

                if (write_return < total_write_len && write_return > 0)
                    fprintf(stderr, "Not all of the message was written\n");
                else if (write_return == 0)
                    fprintf(stderr, "Unexpected EOF\n");

                EXPECT_EQ(write_errno, 0);
                ASSERT_EQ(write_return, total_write_len);

                fd_structs[i].events = POLLIN | POLLHUP | POLLERR;

            } else if (fd_structs[i].revents & POLLIN) { /* ready for read */
                curr_read_len = read(fds[i], buf, 10000);
                int read_errno = errno;

                if (curr_read_len == 0) {
                    fprintf(stderr, "Unexpected EOF on file descriptor\n");
                } else if (curr_read_len < 0){
                    print_errors(fd);
                }

                EXPECT_EQ(read_errno, 0);
                ASSERT_GT(curr_read_len, 0);

                fd_structs[i].events = 0;

                fds_left -= 1;

            }
        }

        ASSERT_EQ(num_fds_ready, poll_return);
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}


/*******************************************************************************
 *                               LOAD TESTS
 ******************************************************************************/


TEST_F(PollTests, Connect200) {

    const int FD_COUNT = 200;
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
        int socket_errno = errno;

        if (fds[i] < 0)
            fprintf(stderr, "Socket creation failed with errno %i: %s\n",
                socket_errno, strerror(socket_errno));

        EXPECT_EQ(socket_errno, 0);
        ASSERT_GT(fds[i], 0);

        int hostname_setsockopt_return = setsockopt(fds[i],
            IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
        int hostname_errno = errno;

        EXPECT_EQ(hostname_errno, 0);
        ASSERT_EQ(hostname_setsockopt_return, 0);

        int connect_return = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        EXPECT_EQ(connect_errno, EINPROGRESS);
        ASSERT_EQ(connect_return, -1);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left_to_connect = FD_COUNT;
    while(fds_left_to_connect > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0); /* EALREADY being returned... need to fix */
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            if (fd_structs[i].revents == 0)
                continue;

            num_fds_ready++;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            if (!(fd_structs[i].revents & POLLOUT)) {
                fprintf(stderr, "Socket wasn't ready for writing\n");
                continue;
            }

            ASSERT_TRUE(fd_structs[i].revents & POLLOUT);

            int connect_2nd_return = connect(fds[i], address, addrlen);
            int connect_2nd_errno = errno;

            EXPECT_EQ(connect_2nd_return, -1);
            EXPECT_EQ(connect_2nd_errno, EISCONN);

            fd_structs[i].events = 0;
        }

        ASSERT_EQ(num_fds_ready, poll_return);

        fds_left_to_connect -= num_fds_ready;
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}

TEST_F(PollTests, ConnectWriteRead200) {

    const int FD_COUNT = 200;
    int i;

    for (i = 0; i < FD_COUNT; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TLS);
        int socket_errno = errno;

        if (fds[i] < 0)
            fprintf(stderr, "Socket creation failed with errno %i: %s\n",
                socket_errno, strerror(socket_errno));

        EXPECT_EQ(socket_errno, 0);
        ASSERT_GT(fds[i], 0);

        int hostname_setsockopt_return = setsockopt(fds[i],
            IPPROTO_TLS, SO_TLS_HOSTNAME, HOSTNAME, strlen(HOSTNAME)+1);
        int hostname_errno = errno;

        EXPECT_EQ(hostname_errno, 0);
        ASSERT_EQ(hostname_setsockopt_return, 0);

        int connect_return = connect(fds[i], address, addrlen);
        int connect_errno = errno;

        EXPECT_EQ(connect_errno, EINPROGRESS);
        ASSERT_EQ(connect_return, -1);
    }

    struct pollfd fd_structs[FD_COUNT] = {0};

    for (i = 0; i < FD_COUNT; i++) {
        fd_structs[i].fd = fds[i];
        fd_structs[i].events = POLLOUT | POLLERR | POLLPRI | POLLHUP;
    }

    int fds_left = FD_COUNT;
    while(fds_left > 0) {

        int poll_return = poll(fd_structs, FD_COUNT, 6000);
        int poll_errno = errno;

        EXPECT_EQ(poll_errno, 0); /* EALREADY being returned... need to fix */
        ASSERT_GT(poll_return, 0);

        int num_fds_ready = 0;
        for (i = 0; i < FD_COUNT; i++) {
            char buf[10000] = {0};
            int total_read_len = 0;
            int curr_read_len;

            if (fd_structs[i].revents == 0)
                continue;

            ASSERT_FALSE(fd_structs[i].revents & POLLERR);
            ASSERT_FALSE(fd_structs[i].revents & POLLHUP);
            ASSERT_FALSE(fd_structs[i].revents & POLLNVAL);
            ASSERT_FALSE(fd_structs[i].revents & POLLPRI);

            num_fds_ready++;

            if (fd_structs[i].revents & POLLOUT) { /* ready for write */
                int connect_2nd_return = connect(fds[i], address, addrlen);
                int connect_2nd_errno = errno;

                EXPECT_EQ(connect_2nd_return, -1);
                EXPECT_EQ(connect_2nd_errno, EISCONN);


                int total_write_len = strlen("GET / HTTP/1.1\r\n\r\n")+1;

                int write_return = write(fds[i],
                    "GET / HTTP/1.1\r\n\r\n", total_write_len);
                int write_errno = errno;

                if (write_return < total_write_len && write_return > 0)
                    fprintf(stderr, "Not all of the message was written\n");
                else if (write_return == 0)
                    fprintf(stderr, "Unexpected EOF\n");

                EXPECT_EQ(write_errno, 0);
                ASSERT_EQ(write_return, total_write_len);

                fd_structs[i].events = POLLIN | POLLHUP | POLLERR;

            } else if (fd_structs[i].revents & POLLIN) { /* ready for read */
                curr_read_len = read(fds[i], buf, 10000);
                int read_errno = errno;

                if (curr_read_len == 0) {
                    fprintf(stderr, "Unexpected EOF on file descriptor\n");
                } else if (curr_read_len < 0){
                    print_errors(fd);
                }

                EXPECT_EQ(read_errno, 0);
                ASSERT_GT(curr_read_len, 0);

                fd_structs[i].events = 0;

                fds_left -= 1;

            }
        }

        ASSERT_EQ(num_fds_ready, poll_return);
    }

    for (i = 0; i < FD_COUNT; i++) {
        close(fds[i]);
        fds[i] = -1;
    }
}


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


