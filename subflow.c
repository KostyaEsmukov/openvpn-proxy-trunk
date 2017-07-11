//
// Created by Kostya on 11/07/2017.
//

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include "conf.h"
#include "subflow.h"


void _add_subflow(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd, ss_state state) {
    if (*active_subflows_count >= MAX_TUNNEL_CONNECTIONS) {
        fprintf(stderr, "Assertion error. Tried to add more connections than expected\n");
        exit(1);
    }

    subflow_state * new_subflow = &active_subflows_state[(*active_subflows_count)++];
    memset(new_subflow, 0, sizeof(subflow_state));
    new_subflow->sock_fd = sock_fd;
    new_subflow->state = state;
    new_subflow->connect_clock = clock();
    new_subflow->buf_struct.buf = (char *) malloc(BUFSIZE_TCP_RECV);
}

void add_subflow_unk(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd) {
    _add_subflow(active_subflows_state, active_subflows_count, sock_fd, SS_UNK);
}

void add_subflow_proxy_waiting(subflow_state *active_subflows_state, int *active_subflows_count, int sock_fd) {
    _add_subflow(active_subflows_state, active_subflows_count, sock_fd, SS_PROXY_RESPONSE_WAITING);
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
