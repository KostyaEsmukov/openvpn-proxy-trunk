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

#include "utils.h"
#include "conf.h"


int bind_local_udp(int port) {
    struct sockaddr_in si_bind;
    int sock_fd;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        die("Unable to create listening UDP socket", errno);

    memset(&si_bind, 0, sizeof(si_bind));
    si_bind.sin_family = AF_INET;
    si_bind.sin_port = htons(port);
    si_bind.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(sock_fd, (struct sockaddr *) &si_bind, sizeof(si_bind)) == -1)
        die("Unable to bind UDP socket", errno);

    set_noblock(sock_fd);
    return sock_fd;
}


int bind_server_tcp_socket(const char *server_listen) {
    struct sockaddr_in si_bind;
    int sock_fd;
    socklen_t clen;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        die("Unable to create server listening TCP socket", errno);
    }

    clen = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));

    memset(&si_bind, 0, sizeof(si_bind));
    si_bind.sin_family = AF_INET;
    if (!resolve_host(server_listen, &si_bind.sin_addr, &si_bind.sin_port)) {
        die("Unable to resolve server TCP listen address", errno);
    }

    if (bind(sock_fd, (struct sockaddr *) &si_bind, sizeof(struct sockaddr)) == -1) {
        die("Unable to bind server listening TCP socket", errno);
    }

    if (listen(sock_fd, BACKLOG) == -1) {
        die("Unable to listen server listening TCP socket", errno);
    }

    set_noblock(sock_fd);
    return sock_fd;
}

int server_accept_client(int server_tcp_sock_fd) {
    struct sockaddr_in clientaddr;
    socklen_t clientlen;

    int childfd = accept(server_tcp_sock_fd,
                         (struct sockaddr *) &clientaddr, &clientlen);
    if (childfd < 0) {
        syslog(LOG_INFO, "ERROR on accept, skipping that connection. (%d: %s)", errno, strerror(errno));
    }

    return childfd;
}
