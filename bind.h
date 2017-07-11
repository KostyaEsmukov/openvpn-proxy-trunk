//
// Created by Kostya on 11/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_BIND_H
#define OPENVPN_PROXY_TRUNK_BIND_H

int bind_local_udp(int port);
int bind_server_tcp_socket(const char *server_listen);
int server_accept_client(int server_tcp_sock_fd);

#endif //OPENVPN_PROXY_TRUNK_BIND_H
