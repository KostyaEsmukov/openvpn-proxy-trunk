//
// Created by Kostya on 10/07/2017.
//

#define _GNU_SOURCE
#include <string.h>
#include <syslog.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <assert.h>

#include "prot.h"
#include "utils.h"
#include "log.h"

void hmac_sha256(const void *key, int keylen,
                 const unsigned char *data, size_t datalen,
                 unsigned char *result, unsigned int result_size) {
    HMAC(EVP_sha256(), key, keylen, data, datalen, result, &result_size);
}


void compute_hmac(subflow_state *subflow, const char prefix[3], const char *shared_secret,
                  unsigned char * result, unsigned int result_size) {
    struct hmac_data hd;
    memcpy((byte *) &hd.prefix, prefix, 2);
    hd.tunnel_id = subflow->tunnel_id;
    hd.client_nonce = subflow->client_nonce;
    hd.server_nonce = subflow->server_nonce;
    hmac_sha256(shared_secret, strlen(shared_secret),
                (unsigned char *) &hd, sizeof(hd),
                result, result_size);
#ifdef DEBUG
//    printf("hmac calculation\n");
//    printf_bytes(&hd, sizeof(hd));
//    printf_bytes(result, result_size);
#endif
}

int send_client_greet(subflow_state *subflow) {
    byte buf[CLIENT_GREET_LEN];
    memcpy((byte *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct client_greet g;
    g.tunnel_id = subflow->tunnel_id;
    g.client_nonce = subflow->client_nonce;
    memcpy((byte *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, CLIENT_GREET_LEN) > 0;
}

int send_server_greet(subflow_state *subflow, const char *shared_secret) {
    byte buf[SERVER_GREET_LEN];
    memcpy((byte *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct server_greet g;
    g.server_nonce = subflow->server_nonce;

    compute_hmac(subflow, "s1", shared_secret, (unsigned char *) &g.hmac, HMAC_LEN);

    memcpy((byte *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, SERVER_GREET_LEN) > 0;
}

int send_client_ack(subflow_state *subflow, const char *shared_secret) {
    byte buf[CLIENT_ACK_LEN];
    memcpy((byte *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct client_ack g;

    compute_hmac(subflow, "c1", shared_secret, (unsigned char *) &g.hmac, HMAC_LEN);

    memcpy((byte *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, CLIENT_ACK_LEN) > 0;
}

int process_proxy_connect(subflow_state *subflow, int *changed) {
    /**
     * Expecting proxy HTTP response
     */

    *changed = 0;
    byte *rnrn = memmem(subflow->buf_struct.buf, subflow->buf_struct.pos, "\r\n\r\n", 4);
    if (rnrn == NULL)
        return 1; // not full response yet
    size_t offset = rnrn - subflow->buf_struct.buf + 4; // 4 - \r\n\r\n

    if (memcmp(subflow->buf_struct.buf, "HTTP/1.0 ", 9)
        && memcmp(subflow->buf_struct.buf, "HTTP/1.1 ", 9)) {
        log(LOG_INFO, "Invalid proxy response, expected HTTP/1.0");
        // todo ?? log what we got?
        return 0;
    }

    if (memcmp(subflow->buf_struct.buf + 9, "200", 3)) {
        log(LOG_INFO, "Invalid proxy response, not 200");
        return 0;
    }

    // we are connected. remove response from buffer

    remove_from_buf(subflow, offset);
    subflow->state = SS_UNK; // connected to target
    *changed = 1;
    return send_client_greet(subflow);
}

int is_valid_magic(byte * buf) {
    int res = memcmp(buf, MAGIC_HEADER, MAGIC_HEADER_LEN) == 0;
#ifdef DEBUG
    if (!res) {
        printf("magic mismatch. received vs expected:\n");
        printf_bytes(buf, MAGIC_HEADER_LEN);
        printf_bytes(MAGIC_HEADER, MAGIC_HEADER_LEN);
    }
#endif
    return res;
}

int process_server_unk(subflow_state *subflow, int *changed, const char *shared_secret) {
    /**
     * Expecting client_greet response
     */

    if (subflow->buf_struct.pos < CLIENT_GREET_LEN)
        return 1;  // not full response yet

    if (!is_valid_magic(subflow->buf_struct.buf)) {
        log(LOG_INFO, "Invalid magic in client_greet");
        return 0;
    }
    assert(subflow->buf_struct.pos >= MAGIC_HEADER_LEN + sizeof(struct client_greet));
    struct client_greet *g = (struct client_greet *) (subflow->buf_struct.buf + MAGIC_HEADER_LEN);

    if (subflow->tunnel_id == 0) {
        subflow->tunnel_id = g->tunnel_id;
    } else if (subflow->tunnel_id != g->tunnel_id) {
        log(LOG_INFO, "Rejected client with different tunnel id");
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
        log(LOG_INFO, "Invalid magic in server_greet");
        return 0;
    }

    assert(subflow->buf_struct.pos >= MAGIC_HEADER_LEN + sizeof(struct server_greet));
    struct server_greet *g = (struct server_greet *) (subflow->buf_struct.buf + MAGIC_HEADER_LEN);

    subflow->server_nonce = g->server_nonce;

    unsigned char our_hmac[HMAC_LEN];
    compute_hmac(subflow, "s1", shared_secret, (unsigned char *) &our_hmac, HMAC_LEN);
    if (memcmp(&our_hmac, &g->hmac, HMAC_LEN) != 0) {
        log(LOG_INFO, "hmac mismatch in server_greet");
        return 0;
    }

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
        log(LOG_INFO, "Invalid magic in client_ack");
        return 0;
    }

    assert(subflow->buf_struct.pos >= MAGIC_HEADER_LEN + sizeof(struct client_ack));
    struct client_ack *g = (struct client_ack *) (subflow->buf_struct.buf + MAGIC_HEADER_LEN);

    unsigned char our_hmac[HMAC_LEN];
    compute_hmac(subflow, "c1", shared_secret, (unsigned char *) &our_hmac, HMAC_LEN);
    if (memcmp(&our_hmac, &g->hmac, HMAC_LEN) != 0) {
        log(LOG_INFO, "hmac mismatch in client_ack");
        return 0;
    }

    // okay, we are good with this client too. start sending/receiving datagrams

    remove_from_buf(subflow, CLIENT_ACK_LEN);
    subflow->state = SS_READY; // receiving/sending datagrams
    *changed = 1;
    return 1;
}


// returns false if we are not good anymore - this subflow should be closed
int process_negotiation_buffer(subflow_state *subflow, int is_client, const char *shared_secret) {
    int changed;
    do {
        changed = 0;
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
            case SS_READY:
                break;
            default:
                assert(0);
        }
    } while (changed);
    return 1;
}
