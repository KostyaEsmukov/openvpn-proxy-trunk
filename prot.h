//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_PROT_H
#define OPENVPN_PROXY_TRUNK_PROT_H

#include <inttypes.h>

#include "subflow.h"

#define MAGIC_HEADER "MG\x00\x42"
#define MAGIC_HEADER_LEN 4

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

struct client_greet {
    uint32_t tunnel_id;
    uint32_t client_nonce;
};

struct server_greet {
    uint32_t server_nonce;
    char hmac[HMAC_LEN]; // "s1" tunnel_id client_nonce server_nonce
};

struct client_ack {
    char hmac[HMAC_LEN]; // "c1" tunnel_id client_nonce server_nonce
};

struct udp_datagram_header {
    uint16_t datagram_len;
};
typedef struct udp_datagram_header udp_datagram_header;

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


int send_client_greet(subflow_state * subflow);

int process_negotiation_buffer(subflow_state *subflow, int is_client, const char *shared_secret);



#endif //OPENVPN_PROXY_TRUNK_PROT_H
