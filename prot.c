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

#include "prot.h"
#include "utils.h"

unsigned char *hmac_sha256(const void *key, int keylen,
                           const unsigned char *data, size_t datalen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, NULL, NULL);
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

