//
// Created by Kostya on 11/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_BIND_H
#define OPENVPN_PROXY_TRUNK_BIND_H

int bind_local_udp(const char *udp_listen_host, struct addrinfo * chosen_ai);
int bind_server_tcp_socket(const char *server_listen);
int server_accept_client(int server_tcp_sock_fd);
int resolve_dest_with_hints(const char *host, struct addrinfo *hints_,
                            struct sockaddr *si_res, socklen_t *si_res_size);
int resolve_dest_to_ai(const char *host, struct addrinfo *ai_res, int ai_socktype);

#endif //OPENVPN_PROXY_TRUNK_BIND_H
