//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_UTILS_H
#define OPENVPN_PROXY_TRUNK_UTILS_H

#include <arpa/inet.h>

# define MIN(a, b)		((a) < (b) ? (a) : (b))
# define MAX(a, b)		((a) > (b) ? (a) : (b))

void die(const char * msg, int errno_);
void set_noblock(int sock_fd);
int resolve_host(const char * host, struct in_addr * addr, in_port_t * port);
ssize_t readexactly(int fd, void *buf, size_t nbyte);
ssize_t sendexactly(int fd, void *buf, size_t nbyte);
uint32_t secure_random();

#endif //OPENVPN_PROXY_TRUNK_UTILS_H
