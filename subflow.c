//
// Created by Kostya on 11/07/2017.
//

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "conf.h"
#include "subflow.h"
#include "utils.h"


subflow_state *_add_subflow(subflow_state *active_subflows_state,
                            int *active_subflows_count,
                            int sock_fd,
                            ss_state state,
                            uint32_t active_tunnel_id, int is_client) {
    assert(*active_subflows_count < MAX_TUNNEL_CONNECTIONS);

    subflow_state *new_subflow = &active_subflows_state[(*active_subflows_count)++];
    memset(new_subflow, 0, sizeof(subflow_state));

    assert(!is_client || active_tunnel_id != 0);
    new_subflow->tunnel_id = active_tunnel_id;
    new_subflow->sock_fd = sock_fd;
    new_subflow->state = state;
    new_subflow->connect_clock = clock_seconds();

    uint32_t *nonce;
    if (is_client) {
        nonce = &new_subflow->client_nonce;
    } else {
        nonce = &new_subflow->server_nonce;
    }
    *nonce = 0;
    while (*nonce == 0) *nonce = secure_random();

    new_subflow->buf_struct.buf = (byte *) malloc(BUFSIZE_TCP_RECV);
    return new_subflow;
}

subflow_state *add_subflow_unk(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd,
                               uint32_t active_tunnel_id, int is_client) {
    return _add_subflow(active_subflows_state, active_subflows_count, sock_fd, SS_UNK, active_tunnel_id, is_client);
}

subflow_state *add_subflow_proxy_waiting(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd,
                                         uint32_t active_tunnel_id) {
    // definitely a client
    return _add_subflow(active_subflows_state, active_subflows_count, sock_fd, SS_PROXY_RESPONSE_WAITING,
                        active_tunnel_id, 1);
}

void remove_subflow(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd) {
    int pos;
    for (pos = 0; pos < *active_subflows_count; pos++) {
        if (active_subflows_state[pos].sock_fd == sock_fd)
            break;
    }
    if (pos >= *active_subflows_count)
        return; // not found

    free(active_subflows_state[pos].buf_struct.buf);

    for (; pos + 1 < *active_subflows_count; pos++) {
        active_subflows_state[pos] = active_subflows_state[pos + 1];
    }

    --(*active_subflows_count);
}

void remove_from_buf(subflow_state *subflow, size_t offset) {
    assert(subflow->buf_struct.pos >= offset);
    if (subflow->buf_struct.pos > offset) {
        memmove(subflow->buf_struct.buf, subflow->buf_struct.buf + offset, subflow->buf_struct.pos - offset);
    }
    subflow->buf_struct.pos -= offset;
}