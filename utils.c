//
// Created by Kostya on 10/07/2017.
//

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>


#include "utils.h"


void die(const char * msg, int errno_) {
    fprintf(stderr, "%s\n", msg);
    if (errno_ > 0)
        fprintf(stderr, "%s\n", strerror(errno_));
    exit(1);
}


void set_noblock(int sock_fd) {
    int flags;
    if ((flags = fcntl(sock_fd, F_GETFL, 0)) < 0) {
        die("get flags", errno);
    }
    if (fcntl(sock_fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        die("set blocking", errno);
    }
}

/*
 * gethostbyname() wrapper. Return 1 if OK, otherwise 0.
 *
 * from cntlm
 */
int so_resolv(struct in_addr *host, const char *name) {

    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(name, NULL, &hints, &res);
    if (rc != 0) {
        syslog(LOG_INFO, "so_resolv: %s failed (%d: %s)\n", name, rc, gai_strerror(rc));
        return 0;
    }
    int addr_set = 0;
    for (p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in *ad = (struct sockaddr_in*)(p->ai_addr);
        if (ad == NULL) {
            freeaddrinfo(res);
            return 0;
        }
        if (!addr_set) {
            memcpy(host, &ad->sin_addr, p->ai_addrlen);
            addr_set = 1;
        }
    }

    freeaddrinfo(res);

    return 1;
}


/*
 * Shortcut for malloc/memset zero.
 */
char *new(size_t size) {
    char *tmp;

    tmp = malloc(size);
    memset(tmp, 0, size);

    return tmp;
}

/*
 * Standard substr. To prevent modification of the source
 * (terminating \x0), return the result in a new memory.
 */
char *substr(const char *src, int pos, int len) {
    int l;
    char *tmp;

    if (len == 0)
        len = strlen(src);

    l = MIN(len, strlen(src) - pos);
    if (l <= 0) {
        return new(1);
    }

    tmp = new(l + 1);
    strlcpy(tmp, src + pos, l + 1);

    return tmp;
}


int resolve_host(const char * host, struct in_addr * addr, in_port_t * port) {
    int len, p;
    char * addr_str;

    len = strlen(host);
    p = strcspn(host, ":");
    if (p < len-1) {
        addr_str = substr(host, 0, p);
        if (!so_resolv(addr, addr_str)) {
            syslog(LOG_ERR, "Cannot resolve address %s\n", addr_str);
            return 0;
        }
        free(addr_str);
        *port = atoi(host+p+1);
    } else {
        addr->s_addr = htonl(INADDR_ANY);
        *port = atoi(host);
    }

    if (!*port) {
        fprintf(stderr, "Invalid port %s.", host);
        exit(1);
    }
    return 1;
}

ssize_t readexactly(int fd, void *buf, size_t nbyte) {
    ssize_t i;
    ssize_t buf_pos = 0;

    do {
        if ((i = read(fd, buf + buf_pos, nbyte - buf_pos)) < 0) {
            return i;
        }
        buf_pos += i;
    } while (buf_pos < nbyte);
    return buf_pos;
}

ssize_t sendexactly(int fd, void *buf, size_t nbyte) {
    ssize_t i;
    ssize_t buf_pos = 0;

    do {
        if ((i = send(fd, buf + buf_pos, nbyte - buf_pos, 0)) < 0) {
            return i;
        }
        buf_pos += i;
    } while (buf_pos < nbyte);
    return buf_pos;
}


uint32_t secure_random() {
    // Linux http://man7.org/linux/man-pages/man2/getrandom.2.html
    // BSD http://man.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man3/arc4random.3?query=arc4random%26sec=3

    int fd = open("/dev/urandom", O_RDONLY);
    uint32_t res = 0;
    size_t pos = 0;
    while (pos < sizeof(uint32_t)) {
        ssize_t result = read(fd, &res + pos, (sizeof res) - pos);
        if (result < 0) {
            die("Unable to dead from /dev/urandom", errno);
        }
        pos += result;
    }
    close(fd);
    return res;
}