# Secure Sockets - A TLS extension to the POSIX Sockets API

The Secure Sockets library is meant to be a simple, secure and portable solution for making TLS connections as a client or server in C. Its main focus is ease of use--a developer with a working knowledge of the POSIX Sockets API in C should be able to upgrade existing HTTP code to HTTPS with the ease of a single `#include`, a single protocol flag (`IPPROTO_TLS`), and optionally a few `setsockopt()` calls to add specifics to the code configuration. No extra functions or cumbersome data types need to be learned--just a few flags that add to the existing `socket()` and `setsockopt()` functions. 

Secure Sockets work by wrapping around existing libraries of functions that deal with sockets. The functions are overridden by macro replacements, which then determine whether the socket was specified as a TLS socket or not when it was created and perform their intended operations. If the socket was created regularly, any functions acting on that socket act as if the library was never included; if the socket is a TLS socket, then all of the verification and encryption needed for it will be done. The library uses OpenSSL under the hood.

This library is meant to be helpful for anyone who wants to use TLS connections in their code. Two groups may find it especially useful, though:
1. Those who want to upgrade an existing code bases to use HTTPS connections
2. Those who haven't learned a TLS library but want to build HTTPS functionality into their code quickly and safely

## Status

The project is currently under early development. The basic sockets functions (such as `socket()`, `connect()`, `listen()`, etc) have been fully implemented, though certain functions such as `shutdown()` and `ioctl()` don't yet fully work for TLS sockets. The functions work whether blocking or non-blocking, though some functions associated with non-blocking operation (such as `select()` or `epoll()`) have no working implementation either. Most of the development is currently focused on client-side connections; however, server-side connections are on the roadmap.

The following features are considered pretty stable to use:
- Blocking and non-blocking POSIX API calls, other than `shutdown()`
- Setting non-blocking sockets with `fcntl()`, as well as `socket()` or `accept4()` combined with the `SOCK_NONBLOCK` flag.
- Using `poll()` to moniter connecting/connected client-side file descriptors for read/write ability

The following features are in active development and should be added to the Secure Sockets library within the next month:

- Server-side support and tests for `poll()`
- Support for other built-in asynchronous functions (`select()` and `epoll()`)
- Full revocation checks for each client connection made (using OCSP caching and OCSP responders)

Other features are in the planning phase:

- Caching of revocation responses to reduce connection time on repeatedly visited hosts
- Server-side certificate/PrivateKey loading via `setsockopt()` calls
- A plethora of `setsockopt()` and `getsockopt()` additions for fine-tuning of TLS connection settings
- Built-in threadlocks to make each TLS socket thread-safe (NOTE: regular non-TLS sockets will remain NOT thread-safe)
- Support for Libevent functions/other libraries that provide helpful functionality to TCP sockets
- MacOS, Windows and BSD portability
- Certificate Transparency for both client and server