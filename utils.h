//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_UTILS_H
#define OPENVPN_PROXY_TRUNK_UTILS_H

# define MIN(a, b)		((a) < (b) ? (a) : (b))

void die(const char * msg, int errno_);
void set_noblock(int sock_fd);
int resolve_host(const char * host, struct in_addr * addr, in_port_t * port);

#endif //OPENVPN_PROXY_TRUNK_UTILS_H
