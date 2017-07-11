//
// Created by Kostya on 11/07/2017.
//

#ifndef OPENVPN_PROXY_TRUNK_SUBFLOW_H
#define OPENVPN_PROXY_TRUNK_SUBFLOW_H

enum ss_state {
    SS_PROXY_RESPONSE_WAITING, SS_UNK, SS_GREETED, SS_READY
};
typedef enum ss_state ss_state;

struct recv_buf {
    size_t pos;
    char * buf;
};

struct subflow_state {
    int sock_fd;
    clock_t connect_clock;
    uint32_t tunnel_id;
    uint32_t client_nonce;
    uint32_t server_nonce;
    ss_state state;
    struct recv_buf buf_struct;
};
typedef struct subflow_state subflow_state;

subflow_state *add_subflow_unk(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd,
                               uint32_t active_tunnel_id, int is_client);

subflow_state *add_subflow_proxy_waiting(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd,
                                         uint32_t active_tunnel_id);

void remove_subflow(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd);

void remove_from_buf(subflow_state *subflow, size_t offset);

#endif //OPENVPN_PROXY_TRUNK_SUBFLOW_H
