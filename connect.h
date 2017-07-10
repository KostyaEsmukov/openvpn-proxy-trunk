//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_CONNECT_H
#define OPENVPN_PROXY_TRUNK_CONNECT_H

int connect_via_proxy(struct sockaddr_in si_proxy, char * dest);
int connect_directly(struct sockaddr_in si_dest);

#endif //OPENVPN_PROXY_TRUNK_CONNECT_H
