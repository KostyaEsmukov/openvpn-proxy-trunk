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
#include <time.h>

#include "log.h"
#include "utils.h"


void die(const char *msg, int errno_) {
    log(LOG_CRIT, "%s\n", msg);
    if (errno_ > 0)
        log(LOG_CRIT, "%s\n", strerror(errno_));
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

void parse_host(const char *host,
                char *parsed_hostname, size_t parsed_hostname_size,
                char *parsed_port, size_t parsed_port_size,
                int *parsed_family) {
    size_t len = strlen(host);

    char *p = strrchr(host, ':');
    ssize_t offset = -1;
    if (p != NULL)
        offset = p - host + 1;
    if (offset >= 0 && offset < len - 1 && host[len - 1] != ']') {
        // this is port
        size_t parsed_pos_len = MIN(len - offset, parsed_port_size);
        strncpy(parsed_port, host + offset, parsed_pos_len);
        parsed_port[parsed_pos_len] = 0;
        len = offset - 1; // limit to addr part
    }
    size_t parsed_hostname_len;
    if (len >= 2 && host[0] == '[' && host[len - 1] == ']') {  // ipv6
        // strip braces
        parsed_hostname_len = MIN(len - 2, parsed_hostname_size);
        strncpy(parsed_hostname, host + 1, parsed_hostname_len);
        *parsed_family = AF_INET6;
    } else {
        parsed_hostname_len = MIN(len, parsed_hostname_size);
        strncpy(parsed_hostname, host, parsed_hostname_len);
        *parsed_family = 0;  // any
    }
    parsed_hostname[parsed_hostname_len] = 0;
}

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

time_t clock_seconds() {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t) != 0) {
        die("Unable to call clock_gettime", errno);
    }
    return t.tv_sec;
}

void write_pidfile(const char *pidfile_path) {
    int pidfile_fd = open(pidfile_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pidfile_fd < 0) {
        die("Unable to create pid file", errno);
    }

    char pid[30];  // sizeof(pid_t)
    snprintf(pid, 30, "%d\n", getpid());
    write(pidfile_fd, pid, strlen(pid));
    close(pidfile_fd);
}
