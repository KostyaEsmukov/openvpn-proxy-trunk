//
// Created by Kostya on 11/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_CONF_H
#define OPENVPN_PROXY_TRUNK_CONF_H

#define MAGIC_HEADER "MG\x00\x42"
#define MAGIC_HEADER_LEN 4

#define BACKLOG 10  // server tcp listen backlog
#define MAX_TUNNEL_CONNECTIONS 20
#define SUBFLOW_INIT_DEADLINE_SECONDS 10  // drop subflows which haven't entered READY state in that time
#define GROW_DELAY_AFTER_FAIL_SECONDS 5  // wait that long before attempting to grow subflows
#define BUFSIZE_UDP (2 << 16)  // from local udp
#define BUFSIZE_TCP_RECV (2 << 16)  // from tcp to local udp, CONNECT proxy response, initial neg

#define DEBUG 1

#include "log.h"

#endif //OPENVPN_PROXY_TRUNK_CONF_H
