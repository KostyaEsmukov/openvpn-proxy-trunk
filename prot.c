//
// Created by Kostya on 10/07/2017.
//

#include <syslog.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

#include "prot.h"
#include "utils.h"

unsigned char *hmac_sha256(const void *key, int keylen,
                           const unsigned char *data, size_t datalen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, NULL, NULL);
}


unsigned char * compute_hmac(subflow_state *subflow, const char prefix[2], const char *shared_secret) {
    struct hmac_data hd;
    strncpy((char *) &hd.prefix, (const char *)&prefix, 2);
    hd.tunnel_id = subflow->tunnel_id;
    hd.client_nonce = subflow->client_nonce;
    hd.server_nonce = subflow->server_nonce;
    return hmac_sha256(shared_secret, strlen(shared_secret), (unsigned char *) &hd, sizeof(hd));
}

int send_client_greet(subflow_state *subflow) {
    char buf[CLIENT_GREET_LEN];
    memcpy((char *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct client_greet g;
    g.tunnel_id = subflow->tunnel_id;
    g.client_nonce = subflow->client_nonce;
    memcpy((char *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, CLIENT_GREET_LEN) > 0;
}

int send_server_greet(subflow_state *subflow, const char *shared_secret) {
    char buf[SERVER_GREET_LEN];
    memcpy((char *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct server_greet g;
    g.server_nonce = subflow->server_nonce;

    unsigned char *hmac = compute_hmac(subflow, "s1", shared_secret);
    memcpy((char *) &g.hmac, hmac, HMAC_LEN);
    free(hmac);

    memcpy((char *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, SERVER_GREET_LEN) > 0;
}

int send_client_ack(subflow_state *subflow, const char *shared_secret) {
    char buf[CLIENT_ACK_LEN];
    memcpy((char *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct client_ack g;

    unsigned char *hmac = compute_hmac(subflow, "c1", shared_secret);
    memcpy((char *) &g.hmac, hmac, HMAC_LEN);
    free(hmac);

    memcpy((char *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, CLIENT_ACK_LEN) > 0;
}

int process_proxy_connect(subflow_state *subflow, int *changed) {
    /**
     * Expecting proxy HTTP response
     */

    *changed = 0;
    char *rnrn = memmem(subflow->buf_struct.buf, subflow->buf_struct.pos, "\r\n\r\n", 4);
    if (rnrn == NULL)
        return 1; // not full response yet
    size_t offset = rnrn - subflow->buf_struct.buf + 4;

    if (strncmp(subflow->buf_struct.buf, "HTTP/1.0 ", 9)
        && strncmp(subflow->buf_struct.buf, "HTTP/1.1 ", 9)) {
        fprintf(stderr, "Invalid proxy response, expected HTTP/1.0");
        // todo ?? log what we got?
        return 0;
    }

    if (strncmp(subflow->buf_struct.buf + 9, "200", 3)) {
        fprintf(stderr, "Invalid proxy response, not 200");
        return 0;
    }

    // we are connected. remove response from buffer

    remove_from_buf(subflow, offset);
    subflow->state = SS_UNK; // connected to target
    *changed = 1;
    return send_client_greet(subflow);
}

int is_valid_magic(char * buf) {
    return memcmp(buf, MAGIC_HEADER, MAGIC_HEADER_LEN) == 0;
}

int process_server_unk(subflow_state *subflow, int *changed, const char *shared_secret) {
    /**
     * Expecting client_greet response
     */

    if (subflow->buf_struct.pos < CLIENT_GREET_LEN)
        return 1;  // not full response yet

    if (!is_valid_magic(subflow->buf_struct.buf)) {
        fprintf(stderr, "Invalid magic in client_greet");
        return 0;
    }
    assert(subflow->buf_struct.pos >= MAGIC_HEADER_LEN + sizeof(struct client_greet));
    struct client_greet *g = (struct client_greet *) (subflow->buf_struct.buf + MAGIC_HEADER_LEN);

    if (subflow->tunnel_id == 0) {
        subflow->tunnel_id = g->tunnel_id;
    } else if (subflow->tunnel_id != g->tunnel_id) {
        fprintf(stderr, "Rejected client with different tunnel id");
        return 0;
    }
    subflow->client_nonce = g->client_nonce;

    // we have saved the needed info, let's present ourselves now

    remove_from_buf(subflow, CLIENT_GREET_LEN);
    subflow->state = SS_GREETED; // connected to target
    *changed = 1;
    return send_server_greet(subflow, shared_secret);
}

int process_client_unk(subflow_state *subflow, int *changed, const char *shared_secret) {
    /**
     * Expecting server_greet response
     */

    if (subflow->buf_struct.pos < SERVER_GREET_LEN)
        return 1;  // not full response yet

    if (!is_valid_magic(subflow->buf_struct.buf)) {
        fprintf(stderr, "Invalid magic in server_greet");
        return 0;
    }

    assert(subflow->buf_struct.pos >= MAGIC_HEADER_LEN + sizeof(struct server_greet));
    struct server_greet *g = (struct server_greet *) (subflow->buf_struct.buf + MAGIC_HEADER_LEN);

    subflow->server_nonce = g->server_nonce;
    unsigned char *our_hmac = compute_hmac(subflow, "s1", shared_secret);
    if (memcmp(our_hmac, &g->hmac, HMAC_LEN) != 0) {
        fprintf(stderr, "hmac mismatch in server_greet");
        free(our_hmac);
        return 0;
    }
    free(our_hmac);

    // okay, we are good with this server. tell'em that

    remove_from_buf(subflow, SERVER_GREET_LEN);
    subflow->state = SS_READY; // receiving/sending datagrams
    *changed = 1;
    return send_client_ack(subflow, shared_secret);
}

int process_server_greeted(subflow_state *subflow, int *changed, const char *shared_secret) {
    /**
     * Expecting client_ack response
     */

    if (subflow->buf_struct.pos < CLIENT_ACK_LEN)
        return 1;  // not full response yet

    if (!is_valid_magic(subflow->buf_struct.buf)) {
        fprintf(stderr, "Invalid magic in client_ack");
        return 0;
    }

    assert(subflow->buf_struct.pos >= MAGIC_HEADER_LEN + sizeof(struct client_ack));
    struct client_ack *g = (struct client_ack *) (subflow->buf_struct.buf + MAGIC_HEADER_LEN);

    unsigned char *our_hmac = compute_hmac(subflow, "c1", shared_secret);
    if (memcmp(our_hmac, &g->hmac, HMAC_LEN) != 0) {
        fprintf(stderr, "hmac mismatch in client_ack");
        free(our_hmac);
        return 0;
    }
    free(our_hmac);

    // okay, we are good with this client too. start sending/receiving datagrams

    remove_from_buf(subflow, CLIENT_ACK_LEN);
    subflow->state = SS_READY; // receiving/sending datagrams
    *changed = 1;
    return 1;
}


// returns false if we are not good anymore - this subflow should be closed
int process_negotiation_buffer(subflow_state *subflow, int is_client, const char *shared_secret) {
    int changed = 0;
    do {
        switch (subflow->state) {
            case SS_PROXY_RESPONSE_WAITING:
                assert(is_client);
                if (!process_proxy_connect(subflow, &changed))
                    return 0;
                break;
            case SS_UNK:
                if (is_client) {
                    if (!process_client_unk(subflow, &changed, shared_secret))
                        return 0;
                } else {
                    if (!process_server_unk(subflow, &changed, shared_secret))
                        return 0;
                }
                break;
            case SS_GREETED:
                assert(!is_client);
                if (!process_server_greeted(subflow, &changed, shared_secret))
                    return 0;
                break;
            default:
                assert(0);
        }
    } while (changed);
    return 1;
}
