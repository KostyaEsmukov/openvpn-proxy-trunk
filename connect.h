//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_CONNECT_H
#define OPENVPN_PROXY_TRUNK_CONNECT_H

int connect_directly(struct addrinfo *ai_dest);

int connect_via_proxy(struct addrinfo *ai_proxy, const char *dest);

#endif //OPENVPN_PROXY_TRUNK_CONNECT_H
