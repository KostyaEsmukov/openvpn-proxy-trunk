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

    size_t p = strrchr(host, ':') - host + 1;
    if (p < len - 1 && host[len - 1] != ']') {
        // this is port
        strncpy(parsed_port, host + p + 1, MIN(len - p - 1, parsed_port_size));
        len = p;
    }
    if (host[0] == '[' && host[len - 1] == ']') {  // ipv6
        // strip braces
        strncpy(parsed_hostname, host + 1, MIN(len - 2, parsed_hostname_size));
        *parsed_family = AF_INET6;
    } else {
        strncpy(parsed_hostname, host, MIN(len, parsed_hostname_size));
        *parsed_family = 0;
    }
}

///*
// * gethostbyname() wrapper. Return 1 if OK, otherwise 0.
// *
// * from cntlm
// */
//int so_resolv(struct sockaddr_in * si, const char *name, int sock_type) {
//
//    struct addrinfo hints, *res, *p;
//
//    memset(&hints, 0, sizeof(hints));
//    char * hostname;
//    size_t namelen = strlen(name);
//    if (name[0] == '[' && name[namelen - 1] == ']') {  // ipv6
//        // strip braces
//        hostname = substr(name, 1, namelen - 1);
//        hints.ai_family = AF_INET6;
//    } else {
//        hostname = strdup(name);
//        hints.ai_family = AF_INET;
//    }
//    hints.ai_socktype = sock_type; // SOCK_STREAM;
//    int rc = getaddrinfo(hostname, NULL, &hints, &res);
//    free(hostname);
//    if (rc != 0) {
//        syslog(LOG_INFO, "so_resolv: %s failed (%d: %s)\n", name, rc, gai_strerror(rc));
//        return 0;
//    }
//
//    for (p = res; p != NULL; p = p->ai_next) {
//        struct sockaddr_in *ad = (struct sockaddr_in*)(p->ai_addr);
//        if (ad == NULL) {
//            continue;
//        }
//        memcpy(si, ad, sizeof(struct sockaddr_in));
//        freeaddrinfo(res);
//        return 1; // resolved
//    }
//
//    freeaddrinfo(res);
//    return 0;
//}
//
//

//
//int resolve_host_connect(const char * host, struct sockaddr_in * si, int sock_type) {
//    int len, p;
//    char * addr_str;
//
//    len = strlen(host);
//    p = strrchr(host, ':') - host + 1;
//    if (p < len-1) {
//        addr_str = substr(host, 0, p);
//        if (!so_resolv(si, addr_str, sock_type)) {
//            syslog(LOG_ERR, "Cannot resolve address %s\n", addr_str);
//            return 0;
//        }
//        free(addr_str);
//        si->sin_port = htons(atoi(host+p+1));
//        return 1; // resolved
//    }
//    fprintf(stderr, "Invalid host %s.", host);
//    return 0;
//}

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