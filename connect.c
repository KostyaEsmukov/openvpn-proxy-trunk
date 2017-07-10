//
// Created by Kostya on 10/07/2017.
//

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "utils.h"


int connect_directly(struct sockaddr_in si_dest) {
    struct sockaddr_in si_bind;
    int sock_fd;
    socklen_t clen;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    clen = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));

    memset(&si_bind, 0, sizeof(si_bind));
    si_bind.sin_family = AF_INET;
    si_bind.sin_addr = si_dest.sin_addr;
    si_bind.sin_port = si_dest.sin_port;

    if (connect(sock_fd, (struct sockaddr *) &si_bind, sizeof(struct sockaddr)) == -1) {
        return -1;
    }

    set_noblock(sock_fd);
    return sock_fd;
}

int connect_via_proxy(struct sockaddr_in si_proxy, char *dest) {

    int proxyfd = connect_directly(si_proxy);
    if (proxyfd < 0)
        return proxyfd;

    char buf[128];
    size_t len = snprintf((char *) &buf, 128, "CONNECT %s HTTP/1.0\r\n", dest);
    if (sendexactly(proxyfd, &buf, len) < 0) {
        return -1;
    }

    return proxyfd;
}


