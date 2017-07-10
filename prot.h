//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_PROT_H
#define OPENVPN_PROXY_TRUNK_PROT_H

#include <inttypes.h>

#define MAGIC_HEADER "MG\x00\x42"
#define MAGIC_HEADER_LEN 4

#define ALLOWED_TIME_DRIFT_SECONDS (60 * 5)

/**
                           +---------+         +---------+
                           | Client  |         | Server  |
                           +---------+         +---------+
          --------------------\ |                   |
          | UNK + tunnel_id + |-|                   |
          | client_nonce      | |                   |
          |-------------------| |                   | ------\
                                |                   |-| UNK |
                                |                   | |-----|
                                |                   |
                                | client_greet      |
                                |------------------>|
                                |                   | ------------------------------\
                                |                   |-| GREETED + tunnel_id +       |
                                |                   | | client_nonce + server_nonce |
                                |                   | |-----------------------------|
                                |      server_greet |
                                |<------------------|
------------------------------\ |                   |
| READY + tunnel_id +         |-|                   |
| client_nonce + server_nonce | |                   |
|-----------------------------| |                   |
                                | client_ack        |
                                |------------------>|
                                |                   | ------------------------------\
                                |                   |-| READY + tunnel_id +         |
                                |                   | | client_nonce + server_nonce |
                                |                   | |-----------------------------|


http://textart.io/sequence
Source:

object Client Server
note left of Client: UNK + tunnel_id +\n client_nonce
note right of Server: UNK
Client->Server: client_greet
note right of Server: GREETED + tunnel_id +\n client_nonce + server_nonce
Server->Client: server_greet
note left of Client: READY + tunnel_id +\n client_nonce + server_nonce
Client->Server: client_ack
note right of Server: READY + tunnel_id +\n client_nonce + server_nonce
 */


// packets

struct client_greet {
    uint32_t tunnel_id;
    uint32_t nonce;
};

struct server_greet {
    uint32_t nonce;
    char hmac[32];
};

struct client_ack {
    char hmac[32];
};

struct udp_datagram_header {
    uint16_t datagram_len;
};

// local state

enum ss_state {
    SS_PROXY_RESPONSE_WAITING, SS_UNK, SS_GREETED, SS_READY
};
typedef enum ss_state ss_state;

struct subflow_state {
    int sock_fd;
    clock_t connect_clock;
    uint32_t tunnel_id;
    uint32_t client_nonce;
    uint32_t server_nonce;
    ss_state state;
};

typedef struct subflow_state subflow_state;

// hmac data

struct hmac_data {
    char prefix [2];  // cl - client, se - server
    uint32_t tunnel_id;
    uint32_t client_nonce;
    uint32_t server_nonce;
};

//
//static struct sign_message *sign_message_new(struct client_helo *header) {
//    struct sign_message *res;
//    res = (struct sign_message *) malloc(sizeof(struct sign_message));
//    strcpy(res->prefix, "cl");
//    res->time = header->time;
//    res->tunnel_id = header->tunnel_id;
//    res->subflow_id = header->subflow_id;
//    return res;
//}

subflow_state * accept_subflow(int fd);


#endif //OPENVPN_PROXY_TRUNK_PROT_H
