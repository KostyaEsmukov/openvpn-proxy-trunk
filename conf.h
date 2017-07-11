//
// Created by Kostya on 11/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_CONF_H
#define OPENVPN_PROXY_TRUNK_CONF_H

#define BACKLOG 10  // server tcp listen backlog
#define MAX_TUNNEL_CONNECTIONS 20
#define SUBFLOW_INIT_DEADLINE_SECONDS 10  // drop subflows which haven't entered READY state in that time
#define GROW_DELAY_AFTER_FAIL_SECONDS 5
#define BUFSIZE_UDP (2 << 16)

#endif //OPENVPN_PROXY_TRUNK_CONF_H
