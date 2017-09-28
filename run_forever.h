//
// Created by Kostya on 28/09/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_RUN_FOREVER_H
#define OPENVPN_PROXY_TRUNK_RUN_FOREVER_H

#include "subflow.h"

static volatile int quit = 0;



void sighandler(int p);
void run_forever(const char *tunneled_udp_listen,
                 const char *tunneled_udp_dest,
                 int is_client,
                 const char *server_listen,
                 const char *shared_secret,
                 subflows_group_config *subflows_group_configs,
                 size_t subflows_group_configs_len,
                 const char *pidfile_path);


#endif //OPENVPN_PROXY_TRUNK_RUN_FOREVER_H
