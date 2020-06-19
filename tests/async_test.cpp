#include <gtest/gtest.h>

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>

#include "../include/tls.h"
#include "../include/tls_async.h"

}

/* TODO: clean this up thoroughly */

void print_errors(int fd);

TEST(Hello, World) {
    int fd;
    struct addrinfo hints, *listp = NULL, *p;
    /* Get a list of potential server addresses*/
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    hints.ai_flags |= AI_ADDRCONFIG;

    getaddrinfo("www.google.com", "443", &hints, &listp);

    if (listp == NULL) {
        printf("\nNo addrinfo pointers available to traverse through...\n");
        exit(1);
    }

    /* Walk the list until one is successfully connected to */
    for (p = listp; p != NULL; p = p->ai_next) {
        if ((fd = socket(p->ai_family, p->ai_socktype, IPPROTO_TLS)) < 0) {
            EXPECT_GE(fd, 0);
            fprintf(stderr, "\nSocket failed to create...\n");
            continue; /* Try next socket; this one failed */
        }

        int fcntl_resp = fcntl(fd, F_SETFL, O_NONBLOCK);
        EXPECT_EQ(fcntl_resp, 0);
        if (fcntl_resp != 0) {
            perror("fcntl failed");
        }

        socklen_t hostname_len = 15;

        int hostname_resp = setsockopt(fd, IPPROTO_TLS, SO_TLS_HOSTNAME, (void*)"www.google.com", hostname_len);
        if (hostname_resp != 0) {
            perror("hostname addition failed");
            close(fd);
            return;
        }


        int connect_resp = connect(fd, p->ai_addr, p->ai_addrlen);
        EXPECT_EQ(connect_resp, -1);
        EXPECT_EQ(errno, EINPROGRESS);
        if (connect_resp < 0) {
            if (errno != EINPROGRESS) {
                perror("Connect failed");
                print_errors(fd);
            }
        } else {
            break;
        }
        struct pollfd pollfd;
        pollfd.fd = fd;
        pollfd.events = POLLIN | POLLOUT | POLLERR;
        int poll_ret = poll(&pollfd, (nfds_t) 1, 5000);

        EXPECT_GT(poll_ret, 0);

        if (poll_ret == 1) {
            if (pollfd.revents & POLLERR) {
                int error;
                socklen_t err_len = sizeof(int);
                int ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &err_len);
                if (ret == 0) {
                    printf("Socket returned error code %i: %s\n", error, strerror(error));
                } else {
                    printf("Socket failed but returned no error code\n");
                }
                break;
            }

            connect_resp = connect(fd, p->ai_addr, p->ai_addrlen);
            if (connect_resp < 0 && errno == EISCONN) {
                printf("Success polling!!\n");
                break;
            } else if (connect_resp == 0) {
                printf("Success(ish) polling--connect returned 0\n");
            } else {
                perror("polling socket failed");
            }
        }


        close(fd);
    }

    if (listp != NULL) {
        /* Clean up */
        freeaddrinfo(listp);
    }

    if (p == NULL) { /* All connections failed */
        printf("\nAll connections failed...\n");
    }

    close(fd);
    return;
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

