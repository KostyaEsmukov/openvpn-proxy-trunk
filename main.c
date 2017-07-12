#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <signal.h>

#include "utils.h"
#include "prot.h"
#include "connect.h"
#include "conf.h"
#include "log.h"
#include "bind.h"
#include "subflow.h"


static volatile int quit = 0;

void sighandler(int p) {
    if (!quit)
        log(LOG_INFO, "Signal %d received, issuing clean shutdown\n", p);
    else
        log(LOG_INFO, "Signal %d received, forcing shutdown\n", p);

    quit++;

    if (quit > 1)
        exit(1);
}

void grow_subflows(subflow_state *active_subflows_state, int *active_subflows_count,
                   int desired_subflows_count,
                   const char *client_proxy, const char *client_dest,
                   struct addrinfo *ai,
                   time_t *last_fail, uint32_t active_tunnel_id) {

    if (*active_subflows_count >= desired_subflows_count)
        return;

    if (*last_fail != 0 && clock_seconds() - *last_fail < GROW_DELAY_AFTER_FAIL_SECONDS) {
        return;
    }

    if (ai->ai_addrlen == 0) {  // not resolved yet
        if (client_proxy != NULL) {
            if (!resolve_dest_to_ai(client_proxy, ai, SOCK_STREAM)) {
                log(LOG_WARNING, "Unable to resolve proxy address (%d: %s)", errno, strerror(errno));
                *last_fail = clock_seconds();
                return;
            }
        } else {
            if (!resolve_dest_to_ai(client_dest, ai, SOCK_STREAM)) {
                log(LOG_WARNING, "Unable to resolve destination address (%d: %s)", errno, strerror(errno));
                *last_fail = clock_seconds();
                return;
            }
        }
    }

    for (int i = 0; i < desired_subflows_count - *active_subflows_count; i++) {
        int childfd;
        if (client_proxy != NULL) {
            childfd = connect_via_proxy(ai, client_dest);
        } else {
            childfd = connect_directly(ai);
        }
        if (childfd < 0) {
            log(LOG_WARNING, "Unable to connect to dest (%d: %s)", errno, strerror(errno));
            *last_fail = clock_seconds();
            return;
        }
        subflow_state *sf;
        if (client_proxy != NULL) {
            sf = add_subflow_proxy_waiting(active_subflows_state, active_subflows_count, childfd, active_tunnel_id);
        } else {
            sf = add_subflow_unk(active_subflows_state, active_subflows_count, childfd, active_tunnel_id, 1);

            // I know, it doesn't feels right to do this here
            if (!send_client_greet(sf)) {
                log(LOG_INFO, "Subflow client greet failed: (%d: %s)", errno, strerror(errno));
                close(sf->sock_fd);
                remove_subflow(active_subflows_state, active_subflows_count, sf->sock_fd);
                *last_fail = clock_seconds();
                return;
            }
        }
#ifdef DEBUG
        log(LOG_DEBUG, "Created new subflow. tunnel id: %d", sf->tunnel_id);
#endif
    }
}

int write_outgoing_datagram(byte *buf, size_t len,
                            subflow_state *active_subflows_state, int active_subflows_count,
                            int *last_write_subflow,
                            fd_set *writefds) {
    for (int i = 0; i < active_subflows_count; i++) {
        int cur = (*last_write_subflow + i) % active_subflows_count;

        if (active_subflows_state[i].state != SS_READY)
            continue; // not suitable yet

        if (!FD_ISSET(active_subflows_state[i].sock_fd, writefds))
            continue; // not available for writing atm

        if (sendexactly(active_subflows_state[i].sock_fd, buf, len) < 0) {
            // write has failed, but we don't know for sure, so let's just drop that datagram
            *last_write_subflow = cur;
            return 0;
        }
        *last_write_subflow = cur;
        return 1;
    }
    // drop the datagram - no suitable subflow for writing
    return 0;
}

int fill_tcp_buf(subflow_state *subflow) {
    ssize_t bufsize = BUFSIZE_TCP_RECV - subflow->buf_struct.pos;
    if (bufsize > 0) {
        int read = recv(
                subflow->sock_fd,
                subflow->buf_struct.buf + subflow->buf_struct.pos,
                bufsize,
                0); // flags
        if (read <= 0) {
            if (errno == EAGAIN)
                return 1;
            log(LOG_INFO, "TCP recv failed: %d : %s", errno, strerror(errno));
            return 2;
        }
        subflow->buf_struct.pos += read;
    } // else - no space in buffer. it should be drained first
    return 0;
}

int send_udp(subflow_state *subflow,
             int local_udp_sock_fd,
             struct sockaddr_storage *udp_client, socklen_t udp_client_len) {
    udp_datagram_header *dh;
    ssize_t tail_size;
    size_t pos = 0;  // to iterate through datagrams in the buf
    int result = 1;  // 1 - ok, 0 - subflow should be closed
    while (pos + sizeof(udp_datagram_header) < subflow->buf_struct.pos) {
        dh = (udp_datagram_header *) (subflow->buf_struct.buf + pos);
        tail_size = subflow->buf_struct.pos - sizeof(udp_datagram_header) - pos;
        if (dh->datagram_len > tail_size)
            break;  // not full datagram yet - need to receive more

        ssize_t res = sendto(local_udp_sock_fd,
                             subflow->buf_struct.buf + sizeof(udp_datagram_header) + pos,
                             dh->datagram_len, 0,
                             (struct sockaddr *) udp_client, udp_client_len);

        if (res <= 0) {
            if (errno == EAGAIN)
                break; // will be retried later
            log(LOG_WARNING, "Unable to send local UDP: (%d: %s)", errno, strerror(errno));
            if (errno == EMSGSIZE) { // something has fucked up: probably header has shifted off. drop that subflow
                result = 0;
                log(LOG_WARNING, "Going to drop that subflow. Received UDP len: %d", dh->datagram_len);
            }
            break;
        }
        pos += dh->datagram_len + sizeof(udp_datagram_header);
    }
    remove_from_buf(subflow, pos);
    return result;
}

void run_forever(const char *udp_local_listen, const char *udp_local_dest,
                 int is_client, const char *server_listen,
                 const char *shared_secret,
                 int client_conenctions,
                 const char *client_proxy, const char *client_dest) {
    uint32_t active_tunnel_id = 0;  // 0 on server means it is unknown yet
    while (is_client && active_tunnel_id == 0) active_tunnel_id = secure_random();

    subflow_state *active_subflows_state = (subflow_state *) malloc(sizeof(subflow_state) * MAX_TUNNEL_CONNECTIONS);
    int active_subflows_count = 0;
    time_t last_fail = 0;
    int last_write_subflow = 0;

    byte *udp_buf = (byte *) malloc(BUFSIZE_UDP);
    struct addrinfo udp_server_ai;  // used for resolving dest UDP
    struct sockaddr_storage udp_client;  // refreshed each time if not set from the `-d` commandline flag
    socklen_t udp_client_len = 0;  // 0 - unknown yet

    struct addrinfo tcp_client;  // stored only once.
    memset(&tcp_client, 0, sizeof(struct addrinfo));
    int server_tcp_sock_fd;

    if (!is_client) {
        server_tcp_sock_fd = bind_server_tcp_socket(server_listen);
#ifdef DEBUG
        printf("Listening TCP on %s\n", server_listen);
#endif
    }

    if (is_client) {
        grow_subflows(active_subflows_state, &active_subflows_count,
                      client_conenctions,
                      client_proxy, client_dest,
                      &tcp_client,
                      &last_fail, active_tunnel_id);
    }

    int local_udp_sock_fd = bind_local_udp(udp_local_listen, &udp_server_ai);
#ifdef DEBUG
    printf("Listening UDP on %s\n", udp_local_listen);
#endif
    if (udp_local_dest != NULL) {
        udp_client_len = sizeof(udp_client);
        if (!resolve_dest_with_hints(udp_local_dest, &udp_server_ai,
                                     (struct sockaddr *) &udp_client, &udp_client_len)) {
            die("Unable to resolve local UDP dest host", errno);
        }
    }

    fd_set readfds, errorfds, zerofds;
    FD_ZERO(&zerofds);  // we will compare against it by value later
    struct timeval timeout;
    int maxfd;

    while (quit == 0) {
        if (!is_client && active_subflows_count == 0 && active_tunnel_id != 0) {
            active_tunnel_id = 0;  // accept new tunnels
#ifdef DEBUG
            log(LOG_DEBUG, "Resetting active tunnel id to 0");
#endif
        }
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        FD_ZERO(&readfds);
        FD_ZERO(&errorfds);

        // watch local UDP listening socket for input datagrams and errors.
        // no need to watch for write availability - just throw datagrams out as they come.
        FD_SET(local_udp_sock_fd, &readfds);
        FD_SET(local_udp_sock_fd, &errorfds);
        maxfd = local_udp_sock_fd;

        if (!is_client) {
            // watch for new connections on server TCP socket
            FD_SET(server_tcp_sock_fd, &readfds);
            FD_SET(server_tcp_sock_fd, &errorfds);
            maxfd = MAX(maxfd, server_tcp_sock_fd);
        }

        for (int i = 0; i < active_subflows_count; i++) {
            FD_SET(active_subflows_state[i].sock_fd, &readfds);
            FD_SET(active_subflows_state[i].sock_fd, &errorfds);
            maxfd = MAX(maxfd, active_subflows_state[i].sock_fd);
        }

        // don't check for write availability of subflows here,
        // because they're most of the time available, so this would produce
        // unneeded select wake-ups.
        if (select(maxfd + 1, &readfds, 0, &errorfds, &timeout) < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            log(LOG_INFO, "ERROR in select: %d: %s", errno, strerror(errno));
            sleep(1);
            continue;
        }

        /**
         * Check and process errors.
         *
         * FD_ISSET is very slow, thus we try to eliminate unneeded FD_ISSET
         * checks on errorfds when there're definitely no errors (that is most of the time)
         */
        if (memcmp(&errorfds, &zerofds, sizeof(fd_set)) != 0) {
            if (FD_ISSET(local_udp_sock_fd, &errorfds)) {
                die("Local UDP listening socket has failed", errno);
            }
            if (!is_client) {
                if (FD_ISSET(server_tcp_sock_fd, &errorfds)) {
                    die("Server TCP listening socket has failed", errno);
                }
            }
            for (int i = active_subflows_count - 1; i >= 0; i--) {  // reversed to be able to delete subflows
                if (FD_ISSET(active_subflows_state[i].sock_fd, &errorfds)) {
                    log(LOG_INFO, "Subflow died");
                    close(active_subflows_state[i].sock_fd);
                    remove_subflow(active_subflows_state, &active_subflows_count, active_subflows_state[i].sock_fd);
                    continue;
                }
            }
        }

        /**
         * Read from local UDP socket
         */
        if (FD_ISSET(local_udp_sock_fd, &readfds)) {
            // recv always returns a single full datagram. see man 2 recv.
            ssize_t len;
            if (udp_local_dest == NULL) {
                // update destination from that packet
                udp_client_len = sizeof(udp_client);
                len = recvfrom(
                        local_udp_sock_fd,
                        udp_buf + sizeof(udp_datagram_header),  // reserve space for header
                        BUFSIZE_UDP - sizeof(udp_datagram_header),
                        0,  // flags
                        (struct sockaddr *) &udp_client, &udp_client_len);
                if (len <= 0)  // we failed here - retry later on
                    udp_client_len = 0;
            } else {
                len = recv(
                        local_udp_sock_fd,
                        udp_buf + sizeof(udp_datagram_header),  // reserve space for header
                        BUFSIZE_UDP - sizeof(udp_datagram_header),
                        0);
            }
            if (len <= 0) {
                if (errno != EAGAIN)
                    die("Local UDP recv failed", errno);
            }
            if (len > 0) {
                fd_set writefds;

                // return immediately (see man 2 select)
                timeout.tv_sec = 0;
                timeout.tv_usec = 0;
                FD_ZERO(&writefds);
                for (int i = 0; i < active_subflows_count; i++) {
                    FD_SET(active_subflows_state[i].sock_fd, &writefds);
                    maxfd = MAX(maxfd, active_subflows_state[i].sock_fd);
                }
                if (select(maxfd + 1, 0, &writefds, 0, &timeout) < 0) {
                    if (errno == EAGAIN) continue;
                    log(LOG_INFO, "ERROR in TCP write select", errno);
                } else {
                    // select is OK, we've got our writefds.
                    udp_datagram_header *header = (udp_datagram_header *) udp_buf;
                    header->datagram_len = len;
                    if (!write_outgoing_datagram(
                            udp_buf, len + sizeof(udp_datagram_header),
                            active_subflows_state, active_subflows_count,
                            &last_write_subflow, &writefds)) {
                        // this datagram has been dropped
                        // todo ?? maybe log?
                    }
                }
            }
        }

        /**
         * Accept new TCP subflows on the server TCP listening socket
         */
        if (!is_client) {
            if (FD_ISSET(server_tcp_sock_fd, &readfds)) {
                int childfd = server_accept_client(server_tcp_sock_fd);
                if (active_subflows_count >= MAX_TUNNEL_CONNECTIONS) {  // drop extra connections
#ifdef DEBUG
                    printf("Dropped as max subflows\n");
#endif
                    close(childfd);
                } else {
                    log(LOG_INFO, "Subflow started negotiation");
                    add_subflow_unk(active_subflows_state, &active_subflows_count,
                                    childfd, active_tunnel_id, is_client);
                }
            }
        }

        for (int i = active_subflows_count - 1; i >= 0; i--) {  // reversed to be able to delete subflows
            if (FD_ISSET(active_subflows_state[i].sock_fd, &readfds)) {
                int res = fill_tcp_buf(&active_subflows_state[i]);
                if (res == 1) continue; // eagain
                if (res == 2) {
                    log(LOG_INFO, "Subflow recv failed: (%d: %s)", errno, strerror(errno));
                    close(active_subflows_state[i].sock_fd);
                    remove_subflow(active_subflows_state, &active_subflows_count, active_subflows_state[i].sock_fd);
                    continue;
                }

                if (active_subflows_state[i].buf_struct.pos != 0) {
                    if (active_subflows_state[i].state == SS_READY) {
                        if (!send_udp(&active_subflows_state[i],
                                      local_udp_sock_fd,
                                      &udp_client, udp_client_len)) {
                            log(LOG_INFO, "Dropping subflow due to failed local UDP send");
                            close(active_subflows_state[i].sock_fd);
                            remove_subflow(active_subflows_state, &active_subflows_count,
                                           active_subflows_state[i].sock_fd);
                            continue;
                        }
                    } else {
                        if (!process_negotiation_buffer(&active_subflows_state[i], is_client, shared_secret)) {
                            log(LOG_INFO, "Subflow protocol negotiation failed: (%d: %s)", errno, strerror(errno));
                            close(active_subflows_state[i].sock_fd);
                            remove_subflow(active_subflows_state, &active_subflows_count,
                                           active_subflows_state[i].sock_fd);
                            continue;
                        }
                        if (active_subflows_state[i].state == SS_READY) {
                            log(LOG_INFO, "Subflow accepted. Currently active: %d", active_subflows_count);
                        }
                        if (!is_client && active_tunnel_id == 0 && active_subflows_state[i].state == SS_READY) {
                            active_tunnel_id = active_subflows_state[i].tunnel_id;
#ifdef DEBUG
                            log(LOG_DEBUG, "Setting active tunnel id: %d", active_tunnel_id);
#endif
                        }
                    }
                }
            }

            if (active_subflows_state[i].state != SS_READY) {
                // drop hang subflows
                if ((clock_seconds() - active_subflows_state[i].connect_clock) > SUBFLOW_INIT_DEADLINE_SECONDS) {
                    close(active_subflows_state[i].sock_fd);
#ifdef DEBUG
                    printf("Dropped as hung subflow.\n");
#endif
                    remove_subflow(active_subflows_state, &active_subflows_count, active_subflows_state[i].sock_fd);
                }
            }
        }

        if (is_client) {
            grow_subflows(active_subflows_state, &active_subflows_count,
                          client_conenctions,
                          client_proxy, client_dest,
                          &tcp_client,
                          &last_fail, active_tunnel_id);
        }
    }

    // todo ?? (graceful shutdown): drain write buffers before closing sockets

    close(local_udp_sock_fd);
    if (!is_client) {
        close(server_tcp_sock_fd);
    }
    // cleanup
    for (int i = 0; i < active_subflows_count; i++) {
        close(active_subflows_state[i].sock_fd);
    }
    free(active_subflows_state);
    free(udp_buf);
}

void print_help(char **argv) {
    printf("openvpn udp proxy trunk. Creates multiple TCP connections "
                   "via HTTP Proxy using CONNECT and tunnels UDP packets "
                   "through them.\n");
    printf("Version " VERSION "\n");

    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s [-ldcsknph]\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t-h  Print this help.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Common options:\n");
    fprintf(stderr, "\t-l  <udp_listen_host>:<udp_listen_port> UDP address to listen.\n");
    fprintf(stderr, "\t-d  <addr>:<port> Where to send incoming UDP. If absent, will be determined from the first received packet.\n");
    fprintf(stderr, "\t-k  <shared_secret> Common shared secret between client and server.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Client options:\n");
    fprintf(stderr, "\t-c  <dest_host>:<dest_port> Client mode.\n");
    fprintf(stderr, "\t-n  <client_connection_number> Number of TCP connections to maintain (not more than %d).\n", MAX_TUNNEL_CONNECTIONS);
    fprintf(stderr, "\t-p  <client_proxy_host>:<client_proxy_port> HTTP proxy to connect via (if needed).\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Server options:\n");
    fprintf(stderr, "\t-s  <listen_addr>:<listen_port> Server mode. TCP socket to listen on.\n");
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    char *udp_local_listen = NULL;
    char *udp_local_dest = NULL;
    int is_client = -1;
    char *shared_secret = NULL;
    int client_conenctions = 1;
    char *client_proxy = NULL;
    char *client_dest = NULL;
    char *server_listen = NULL;
    int help = 0;

    int i;
    while ((i = getopt(argc, argv, "l:c:s:k:n:p:d:h")) != -1) {
        switch (i) {
            case 'l':
                udp_local_listen = strdup(optarg);
                break;
            case 'c':
                is_client = 1;
                client_dest = strdup(optarg);
                break;
            case 's':
                is_client = 0;
                server_listen = strdup(optarg);
                break;
            case 'k':
                shared_secret = strdup(optarg);
                break;
            case 'n':
                client_conenctions = atoi(optarg);
                break;
            case 'p':
                client_proxy = strdup(optarg);
                break;
            case 'd':
                udp_local_dest = strdup(optarg);
                break;
            case 'h':
                help = 2;
                break;
            default:
                help = 1;
        }
    }

    if (help != 2) {  // don't validate args when help is asked
        if (udp_local_listen == NULL) {
            fprintf(stderr, "-l is required\n");
            help = 1;
        }
        if (is_client < 0) {
            fprintf(stderr, "either -c or -s is required\n");
            help = 1;
        }
        if (shared_secret == NULL) {
            fprintf(stderr, "-k is required\n");
            help = 1;
        }

        if (is_client) {
            if (client_conenctions > MAX_TUNNEL_CONNECTIONS) {
                fprintf(stderr, "-n can't be more than %d\n", MAX_TUNNEL_CONNECTIONS);
                help = 1;
            }
        }
    }

    if (help) {
        print_help(argv);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, &sighandler);
    signal(SIGTERM, &sighandler);
    signal(SIGHUP, &sighandler);

    run_forever(udp_local_listen, udp_local_dest,
                is_client, server_listen,
                shared_secret,
                client_conenctions,
                client_proxy, client_dest);

    free(udp_local_listen);
    free(udp_local_dest);
    free(shared_secret);
    free(client_proxy);
    free(client_dest);
    free(server_listen);
    return 0;
}