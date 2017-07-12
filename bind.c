//
// Created by Kostya on 11/07/2017.
//

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>

#include "utils.h"
#include "conf.h"
#include "log.h"


int bind_local_udp(const char *udp_listen_host, struct addrinfo * chosen_ai) {
    struct addrinfo hints, *res, *p;
    int sock_fd;

    char hostname [120];
    char port [10];

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    parse_host(udp_listen_host, (char *) &hostname, 120, (char *) &port, 10, &hints.ai_family);

    int rc = getaddrinfo((char *) &hostname, (char *) &port, &hints, &res);
    if (rc != 0) {
        log(LOG_INFO, "Unable to resolve UDP bind address %s. (%d: %s)\n", hostname, rc, gai_strerror(rc));
        exit(1);
    }

    int bound = 0;
    for (p = res; p != NULL; p = p->ai_next) {
        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;
        if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            continue;
        }
        bound = 1;
        memcpy(chosen_ai, p, sizeof(struct addrinfo));
        break;
    }
    freeaddrinfo(res);
    if (!bound)
        die("Unable to bind UDP socket", errno);

    set_noblock(sock_fd);
    return sock_fd;
}


int bind_server_tcp_socket(const char *server_listen) {
    struct addrinfo hints, *res, *p;
    int sock_fd;
    socklen_t clen;

    char hostname [120];
    char port [10];

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    parse_host(server_listen, (char *) &hostname, 120, (char *) &port, 10, &hints.ai_family);

    int rc = getaddrinfo((char *) &hostname, (char *) &port, &hints, &res);
    if (rc != 0) {
        log(LOG_INFO, "Unable to resolve TCP bind address %s. (%d: %s)\n", hostname, rc, gai_strerror(rc));
        exit(1);
    }

    int bound = 0;
    for (p = res; p != NULL; p = p->ai_next) {
        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;

        clen = 1;
        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));

        if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            continue;
        }

        bound = 1;
        break;
    }
    freeaddrinfo(res);
    if (!bound)
        die("Unable to bind UDP socket", errno);

    if (listen(sock_fd, BACKLOG) == -1) {
        die("Unable to listen server listening TCP socket", errno);
    }

    set_noblock(sock_fd);
    return sock_fd;
}

int server_accept_client(int server_tcp_sock_fd) {
    struct sockaddr_storage clientaddr;
    socklen_t clientlen = sizeof(clientaddr);

    int childfd = accept(server_tcp_sock_fd,
                         (struct sockaddr *) &clientaddr, &clientlen);
    if (childfd < 0) {
        log(LOG_INFO, "ERROR on accept, skipping that connection. (%d: %s)", errno, strerror(errno));
    }

    return childfd;
}

int resolve_dest_with_hints(const char *host, struct addrinfo *hints_,
                            struct sockaddr *si_res, socklen_t *si_res_size) {
    struct addrinfo hints, *res, *p;
    char hostname [120];
    char port [10];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = hints_->ai_family;
    hints.ai_socktype = hints_->ai_socktype;
    hints.ai_protocol = hints_->ai_protocol;

    parse_host(host, (char *) &hostname, 120, (char *) &port, 10, &hints.ai_family);

    int rc = getaddrinfo((char *) &hostname, (char *) &port, &hints, &res);
    if (rc != 0) {
        log(LOG_INFO, "Unable to resolve address %s. (%d: %s)\n", host, rc, gai_strerror(rc));
        return 0;
    }
    for (p = res; p != NULL; p = p->ai_next) {
        if (p->ai_addrlen > *si_res_size)
            continue;
        memcpy(si_res, p->ai_addr, p->ai_addrlen);
        *si_res_size = p->ai_addrlen;
        freeaddrinfo(res);
        return 1;
    }

    freeaddrinfo(res);
    return 0;
}

int resolve_dest_to_ai(const char *host, struct addrinfo *ai_res, int ai_socktype) {
    struct addrinfo hints, *res, *p;
    int sock_fd;

    char hostname [120];
    char port [10];

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = ai_socktype;
    parse_host(host, (char *) &hostname, 120, (char *) &port, 10, &hints.ai_family);

    int rc = getaddrinfo((char *) &hostname, (char *) &port, &hints, &res);
    if (rc != 0) {
        log(LOG_INFO, "Unable to resolve address %s. (%d: %s)\n", host, rc, gai_strerror(rc));
        return 0;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        if (p->ai_addrlen == 0)
            continue;
        if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
            continue;
        close(sock_fd);

        struct sockaddr * si = (struct sockaddr *) malloc(p->ai_addrlen);  // todo !! this is never free'd
        memcpy(si, p->ai_addr, p->ai_addrlen);
        memcpy(ai_res, p, sizeof(struct addrinfo));
        ai_res->ai_addr = si;
        freeaddrinfo(res);
        return 1;
    }
    freeaddrinfo(res);
    return 0;
}
