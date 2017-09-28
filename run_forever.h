//
// Created by Kostya on 28/09/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_RUN_FOREVER_H
#define OPENVPN_PROXY_TRUNK_RUN_FOREVER_H

static volatile int quit = 0;

void sighandler(int p);
void run_forever(const char *udp_local_listen, const char *udp_local_dest,
                 int is_client, const char *server_listen,
                 const char *shared_secret,
                 int client_conenctions,
                 const char *client_proxy, const char *client_dest,
                 const char *pidfile_path);


#endif //OPENVPN_PROXY_TRUNK_RUN_FOREVER_H
