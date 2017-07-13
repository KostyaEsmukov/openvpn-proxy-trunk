//
// Created by Kostya on 10/07/2017.
//

#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>

#include "utils.h"
#include "subflow.h"


int connect_directly(struct addrinfo *ai_dest) {
    int sock_fd;
    socklen_t clen;

    if ((sock_fd = socket(ai_dest->ai_family, ai_dest->ai_socktype, ai_dest->ai_protocol)) == -1) {
        return -1;
    }

    clen = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));

    if (connect(sock_fd, ai_dest->ai_addr, ai_dest->ai_addrlen) == -1) {
        return -1;
    }

    set_noblock(sock_fd);
    return sock_fd;
}

int connect_via_proxy(struct addrinfo *ai_proxy, const char *dest) {

    int proxyfd = connect_directly(ai_proxy);
    if (proxyfd < 0)
        return proxyfd;

    char buf[128];
    size_t len = snprintf(buf, 128, "CONNECT %s HTTP/1.0\r\n\r\n", dest);
    if (sendexactly(proxyfd, &buf, len) < 0) {
        return -1;
    }

    return proxyfd;
}

