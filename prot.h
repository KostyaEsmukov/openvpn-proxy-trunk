//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_PROT_H
#define OPENVPN_PROXY_TRUNK_PROT_H

#include <inttypes.h>

#include "conf.h"
#include "subflow.h"

#define CLIENT_GREET_LEN (MAGIC_HEADER_LEN + sizeof(struct client_greet))
#define SERVER_GREET_LEN (MAGIC_HEADER_LEN + sizeof(struct server_greet))
#define CLIENT_ACK_LEN (MAGIC_HEADER_LEN + sizeof(struct client_ack))

#define HMAC_LEN 32  // sha256

/**
                           +---------+         +---------+
                           | Client  |         | Server  |
                           +---------+         +---------+
   ---------------------------\ |                   |
   | [PROXY_RESPONSE_WAITING] |-|                   |
   |--------------------------| |                   |
                                |                   | ---------------------\
                                |                   |-| UNK + server_nonce |
                                |                   | |--------------------|
                                |                   |
                                | client_greet      |
                                |------------------>|
          --------------------\ |                   |
          | UNK + tunnel_id + |-|                   |
          | client_nonce      | |                   |
          |-------------------| |                   | ------------------------------\
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
note left of Client: [PROXY_RESPONSE_WAITING]
note right of Server: UNK + server_nonce
Client->Server: client_greet
note left of Client: UNK + tunnel_id +\n client_nonce
note right of Server: GREETED + tunnel_id +\n client_nonce + server_nonce
Server->Client: server_greet
note left of Client: READY + tunnel_id +\n client_nonce + server_nonce
Client->Server: client_ack
note right of Server: READY + tunnel_id +\n client_nonce + server_nonce
 */


// packets

struct __attribute__((__packed__)) client_greet {
    uint32_t tunnel_id;
    uint32_t client_nonce;
};

struct __attribute__((__packed__)) server_greet {
    uint32_t server_nonce;
    byte hmac[HMAC_LEN]; // "s1" tunnel_id client_nonce server_nonce
};

struct __attribute__((__packed__)) client_ack {
    byte hmac[HMAC_LEN]; // "c1" tunnel_id client_nonce server_nonce
};

struct __attribute__((__packed__)) udp_datagram_header {
    uint16_t datagram_len;
};
typedef struct udp_datagram_header udp_datagram_header;

// hmac data

struct __attribute__((__packed__)) hmac_data {
    char prefix [2];  // cl - client, se - server
    uint32_t tunnel_id;
    uint32_t client_nonce;
    uint32_t server_nonce;
};


int send_client_greet(subflow_state * subflow);

int process_negotiation_buffer(subflow_state *subflow, int is_client, const char *shared_secret);



#endif //OPENVPN_PROXY_TRUNK_PROT_H
