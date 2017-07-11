//
// Created by Kostya on 10/07/2017.
//

#include <syslog.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "prot.h"
#include "utils.h"
#include "subflow.h"

unsigned char *hmac_sha256(const void *key, int keylen,
                           const unsigned char *data, size_t datalen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, NULL, NULL);
}


int process_proxy_connect(subflow_state *subflow, int *changed) {
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

    memmove(subflow->buf_struct.buf, subflow->buf_struct.buf + offset, subflow->buf_struct.pos - offset);
    subflow->buf_struct.pos -= offset;
    subflow->state = SS_UNK; // connected to target
    *changed = 1;
    return send_client_greet(subflow);
}

int process_client_unk(subflow_state *subflow, int *changed, const char *shared_secret) {
    // expect server greet
    // todo
}

int process_server_unk(subflow_state *subflow, int *changed, const char *shared_secret) {
    // expect client greet
    // todo
}

int process_server_greeted(subflow_state *subflow, int *changed, const char *shared_secret) {
    // expect client ack
    // todo
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

int send_client_greet(subflow_state *subflow) {
    char buf[60];
    strncpy((char *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct client_greet g;
    g.tunnel_id = subflow->tunnel_id;
    g.client_nonce = subflow->client_nonce;
    memcpy((char *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, MAGIC_HEADER_LEN + sizeof(g)) > 0;
}

int send_server_greet(subflow_state *subflow, const char *shared_secret) {
    char buf[60];
    strncpy((char *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct server_greet g;
    g.server_nonce = subflow->server_nonce;

    struct hmac_data hd;
    strncpy((char *) &hd.prefix, "s1", 2);
    hd.tunnel_id = subflow->tunnel_id;
    hd.client_nonce = subflow->client_nonce;
    hd.server_nonce = subflow->server_nonce;
    unsigned char *hmac = hmac_sha256(shared_secret, strlen(shared_secret), (unsigned char *) &hd, sizeof(hd));
    memcpy((char *) &g.hmac, hmac, HMAC_LEN);
    free(hmac);

    memcpy((char *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, MAGIC_HEADER_LEN + sizeof(g)) > 0;
}

int send_client_ack(subflow_state *subflow, const char *shared_secret) {
    char buf[60];
    strncpy((char *) &buf, MAGIC_HEADER, MAGIC_HEADER_LEN);
    struct client_ack g;

    struct hmac_data hd;
    strncpy((char *) &hd.prefix, "c1", 2);
    hd.tunnel_id = subflow->tunnel_id;
    hd.client_nonce = subflow->client_nonce;
    hd.server_nonce = subflow->server_nonce;
    unsigned char *hmac = hmac_sha256(shared_secret, strlen(shared_secret), (unsigned char *) &hd, sizeof(hd));
    memcpy((char *) &g.hmac, hmac, HMAC_LEN);
    free(hmac);

    memcpy((char *) &buf + MAGIC_HEADER_LEN, &g, sizeof(g));

    return sendexactly(subflow->sock_fd, &buf, MAGIC_HEADER_LEN + sizeof(g)) > 0;
}



//
//int accept_subflow(int fd, uint32_t *active_tunnel_id, int has_subflows,
//                   uint32_t *latest_subflow_id, const char *shared_secret) {
//
//    char buf[64];
//    ssize_t buf_pos = 0;
//    struct client_helo header;
//
//    if (readexactly(fd, &buf, MAGIC_HEADER_LEN) < 0) {
//        syslog(LOG_INFO, "Unable to read from socket (%d: %s)", errno, strerror(errno));
//        return 0;
//    }
//
//    if (strncmp(buf, MAGIC_HEADER, buf_pos) != 0) {
//        syslog(LOG_INFO, "Rejected subflow: Bad magic");
//        return 0;
//    }
//
//    if (readexactly(fd, &header, sizeof(struct client_helo)) < 0) {
//        syslog(LOG_INFO, "Unable to read from socket (%d: %s)", errno, strerror(errno));
//        return 0;
//    }
//
//    int64_t time_drift = llabs((int64_t) time(NULL) - (int64_t) header.time);
//    if (time_drift > ALLOWED_TIME_DRIFT_SECONDS) {
//        syslog(LOG_INFO, "Rejected subflow: too large time drift: %lld", time_drift);
//        return 0;
//    }
//
//    if (has_subflows && *active_tunnel_id != header.tunnel_id) {
//        syslog(LOG_INFO, "Rejected subflow: bad tunnel id.");
//        return 0;
//    }
//
//    if (*latest_subflow_id >= header.subflow_id) {
//        syslog(LOG_INFO, "Rejected subflow: too low subflow id.");
//        return 0;
//    }
//
//    struct sign_message *data = sign_message_new(&header);
//    unsigned char *our_hmac = hmac_sha256(shared_secret, strlen(shared_secret),
//                                          (const unsigned char *) data, sizeof(*data));
//    free(data);
//
//    if ((strncmp((char *) our_hmac, (char *) header.hmac, 32)) != 0) {
//        // todo string format as bytes
//        syslog(LOG_INFO, "Rejected subflow: bad hmac. their != our. %s != %s.", (char *) header.hmac, our_hmac);
//        return 0;
//    }
//
//    *active_tunnel_id = header.tunnel_id;
//    *latest_subflow_id = header.subflow_id;
//
//    return 1;
//}

