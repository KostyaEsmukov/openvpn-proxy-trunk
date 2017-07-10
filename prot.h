//
// Created by Kostya on 10/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_PROT_H
#define OPENVPN_PROXY_TRUNK_PROT_H

#include <inttypes.h>

#define MAGIC_HEADER "MG\x00\x42"
#define MAGIC_HEADER_LEN 4

#define ALLOWED_TIME_DRIFT_SECONDS (60 * 5)


struct client_helo {
    uint64_t time;
    uint32_t tunnel_id;
    uint32_t subflow_id;
    char hmac[64];
};

struct sign_message {
    char prefix [2];  // cl - client, se - server
    uint64_t time;
    uint32_t tunnel_id;
    uint32_t subflow_id;
};

static struct sign_message *sign_message_new(struct client_helo *header) {
    struct sign_message *res;
    res = (struct sign_message *) malloc(sizeof(struct sign_message));
    strcpy(res->prefix, "cl");
    res->time = header->time;
    res->tunnel_id = header->tunnel_id;
    res->subflow_id = header->subflow_id;
    return res;
}

int accept_subflow(int fd, uint32_t *active_tunnel_id, int has_subflows,
                   uint32_t *latest_subflow_id, const char * shared_secret);

#endif //OPENVPN_PROXY_TRUNK_PROT_H
