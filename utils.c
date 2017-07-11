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
char *substr(const char *src, size_t pos, size_t len) {
    size_t l;
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

void parse_host(const char *host,
                char *parsed_hostname, size_t parsed_hostname_size,
                char *parsed_port, size_t parsed_port_size,
                int *parsed_family) {
    size_t len = strlen(host);

    char * p = strrchr(host, ':');
    ssize_t offset = -1;
    if (p != NULL)
        offset = p - host + 1;
    if (offset >= 0 && offset < len - 1 && host[len - 1] != ']') {
        // this is port
        strncpy(parsed_port, host + offset + 1, MIN(len - offset - 1, parsed_port_size));
        len = offset; // limit to addr part
    }
    if (len >= 2 && host[0] == '[' && host[len - 1] == ']') {  // ipv6
        // strip braces
        strncpy(parsed_hostname, host + 1, MIN(len - 2, parsed_hostname_size));
        *parsed_family = AF_INET6;
    } else {
        strncpy(parsed_hostname, host, MIN(len, parsed_hostname_size));
        *parsed_family = 0;  // any
    }
}

//ssize_t readexactly(int fd, void *buf, size_t nbyte) {
//    ssize_t i;
//    ssize_t buf_pos = 0;
//
//    do {
//        if ((i = read(fd, buf + buf_pos, nbyte - buf_pos)) < 0) {
//            if (errno == EAGAIN)
//                continue;
//            return i;
//        }
//        buf_pos += i;
//    } while (buf_pos < nbyte);
//    return buf_pos;
//}

ssize_t sendexactly(int fd, void *buf, size_t nbyte) {
    ssize_t i;
    ssize_t buf_pos = 0;

    do {
        // todo try the send all flag ???
        if ((i = send(fd, buf + buf_pos, nbyte - buf_pos, 0)) < 0) {
            if (errno == EAGAIN)
                continue;
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