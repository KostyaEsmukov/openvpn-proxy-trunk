#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#include "utils.h"
#include "prot.h"
#include "connect.h"
#include "conf.h"
#include "bind.h"
#include "subflow.h"


int quit = 0;

void sighandler(int p) {
    if (!quit)
        syslog(LOG_INFO, "Signal %d received, issuing clean shutdown\n", p);
    else
        syslog(LOG_INFO, "Signal %d received, forcing shutdown\n", p);

    quit++;
}

void grow_subflows(subflow_state *active_subflows_state, int *active_subflows_count,
                   int desired_subflows_count, char *client_proxy, char *client_dest,
                   clock_t *last_fail) {

    if (*active_subflows_count >= desired_subflows_count)
        return;

    if (clock() - *last_fail < GROW_DELAY_AFTER_FAIL_SECONDS) {
        return;
    }

    struct sockaddr_in si;
    memset(&si, 0, sizeof(si));
    si.sin_family = AF_INET;

    if (client_proxy != NULL) {
        if (!resolve_host(client_proxy, &si.sin_addr, &si.sin_port)) {
            syslog(LOG_WARNING, "Unable to resolve proxy address (%d: %s)", errno, strerror(errno));
            *last_fail = clock();
            return;
        }
    } else {
        if (!resolve_host(client_dest, &si.sin_addr, &si.sin_port)) {
            syslog(LOG_WARNING, "Unable to resolve destination address (%d: %s)", errno, strerror(errno));
            *last_fail = clock();
            return;
        }
    }

    for (int i = 0; i < desired_subflows_count - *active_subflows_count; i++) {
        int childfd;
        if (client_proxy != NULL) {
            childfd = connect_via_proxy(si, client_dest);
        } else {
            childfd = connect_directly(si);
        }
        if (childfd < 0) {
            syslog(LOG_WARNING, "Unable to connect to dest (%d: %s)", errno, strerror(errno));
            *last_fail = clock();
            return;
        }
        if (client_proxy != NULL) {
            add_subflow_proxy_waiting(active_subflows_state, active_subflows_count, childfd);
        } else {
            add_subflow_unk(active_subflows_state, active_subflows_count, childfd);
        }
    }
}

int write_outgoing_datagram(char *buf, ssize_t len,
                            subflow_state *active_subflows_state, int active_subflows_count,
                            int *last_write_subflow,
                            fd_set *writefds) {
    for (int i = 0; i < active_subflows_count; i++) {
        int cur = (*last_write_subflow + i) % active_subflows_count;

        if (active_subflows_state[i].state != SS_READY)
            continue; // not suitable yet

        if (!FD_ISSET(active_subflows_state[i].sock_fd, writefds))
            continue; // not available for writing atm

        if (sendexactly(active_subflows_state[i].sock_fd, &buf, len) < 0) {
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

void run_forever(int udp_local_listen, char *udp_local_dest,
                 int is_client, const char *server_listen,
                 const char *shared_secret,
                 int client_conenctions, char *client_proxy, char *client_dest) {
    uint32_t active_tunnel_id = secure_random();
    subflow_state *active_subflows_state = (subflow_state *) malloc(sizeof(subflow_state) * MAX_TUNNEL_CONNECTIONS);
    int active_subflows_count = 0;
    clock_t last_fail = clock() - GROW_DELAY_AFTER_FAIL_SECONDS - 1;
    int last_write_subflow = 0;
    char *udp_buf = (char *) malloc(BUFSIZE_UDP);
    struct sockaddr_in udp_client;
    socklen_t udp_client_len = 0;

    if (udp_local_dest != NULL) {
        udp_client.
        if (!resolve_host(client_proxy, &si.sin_addr, &si.sin_port)) {
            die("Unable to resolve local UDP dest host", errno);
        }
    }

    int server_tcp_sock_fd;

    if (!is_client)
        server_tcp_sock_fd = bind_server_tcp_socket(server_listen);

    if (is_client) {
        grow_subflows(active_subflows_state, &active_subflows_count,
                      client_conenctions,
                      client_proxy, client_dest, &last_fail);
    }

    int local_udp_sock_fd = bind_local_udp(udp_local_listen);

    fd_set readfds, writefds, errorfds;
    int maxfd;

    while (quit == 0) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
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
            FD_SET(active_subflows_state[i].sock_fd, &writefds);
            FD_SET(active_subflows_state[i].sock_fd, &errorfds);
            maxfd = MAX(maxfd, active_subflows_state[i].sock_fd);
        }

        if (select(maxfd + 1, &readfds, &writefds, &errorfds, 0) < 0) {
            if (errno == EAGAIN) continue;
            die("ERROR in select", errno);
        }

        /**
         * Read from local UDP socket
         */
        if (FD_ISSET(local_udp_sock_fd, &errorfds)) {
            die("Local UDP listening socket has failed", errno);
        }
        if (FD_ISSET(local_udp_sock_fd, &readfds)) {
            // recv always returns a single full datagram. see man 2 recv.
            ssize_t len;
            if (udp_client_len <= 0) {
                // we don't know destination yet - get it from that packet
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
                udp_datagram_header header;
                header.datagram_len = len;
                memcpy(udp_buf, &header, sizeof(udp_datagram_header));
                if (!write_outgoing_datagram(
                        udp_buf, len + sizeof(udp_datagram_header),
                        active_subflows_state, active_subflows_count,
                        &last_write_subflow, &writefds)) {
                    // this datagram has been dropped
                    // todo ?? maybe log?
                }
            }
        }

        /**
         * Accept new TCP subflows on the server TCP listening socket
         */
        if (!is_client) {
            if (FD_ISSET(server_tcp_sock_fd, &errorfds)) {
                die("Server TCP listening socket has failed", errno);
            }
            if (FD_ISSET(server_tcp_sock_fd, &readfds)) {
                int childfd = server_accept_client(server_tcp_sock_fd);
                if (active_subflows_count >= MAX_TUNNEL_CONNECTIONS) {  // drop extra connections
                    close(childfd);
                } else {
                    add_subflow_unk(active_subflows_state, &active_subflows_count, childfd);
                }
            }
        }

        for (int i = active_subflows_count - 1; i >= 0; i--) {  // reversed to be able to delete subflows
            if (FD_ISSET(active_subflows_state[i].sock_fd, &errorfds)) {
                syslog(LOG_INFO, "Subflow died");
                close(active_subflows_state[i].sock_fd);
                remove_subflow(active_subflows_state, &active_subflows_count, active_subflows_state[i].sock_fd);
                continue;
            }

            if (FD_ISSET(active_subflows_state[i].sock_fd, &readfds)) {
                // todo read from subflow - either state update or new datagram
            }

            if (active_subflows_state[i].state != SS_READY) {
                // drop hang subflows
                if (clock() - active_subflows_state[i].connect_clock > SUBFLOW_INIT_DEADLINE_SECONDS) {
                    close(active_subflows_state[i].sock_fd);
                    remove_subflow(active_subflows_state, &active_subflows_count, active_subflows_state[i].sock_fd);
                }
            }
        }

        if (is_client) {
            grow_subflows(active_subflows_state, &active_subflows_count,
                          client_conenctions,
                          client_proxy, client_dest, &last_fail);
        }
    }
    free(active_subflows_state);
    free(udp_buf);
}

void print_help(char **argv) {
    printf("openvpn udp proxy trunk. Creates multiple TCP connections "
                   "via HTTP Proxy using CONNECT and tunnels UDP packets "
                   "through them.\n");

    fprintf(stderr, "Usage: %s [-ldcsknph]\n", argv[0]);
    fprintf(stderr, "\t-l  <udp_listen_port> Local UDP port to listen.\n");
    fprintf(stderr,
            "\t-d  <addr>:<port> Where to send incoming UDP. If absent, will be determined from the first received packet.\n");
    fprintf(stderr, "\t-c  <dest_host>:<dest_port> Client mode.\n");
    fprintf(stderr, "\t-s  [<listen_addr>:]<listen_port> Server mode.\n");
    fprintf(stderr, "\t-k  <shared_secret> Common shared secret between client and server.\n");
    fprintf(stderr, "\t-n  <client_connection_number> Number of TCP connections to maintain (not more than %d).\n",
            MAX_TUNNEL_CONNECTIONS);
    fprintf(stderr, "\t-p  <client_proxy_host>:<client_proxy_port> HTTP proxy to connect via (if needed).\n");
    fprintf(stderr, "\t-h  Print this help.\n");
}

int main(int argc, char **argv) {
    int udp_local_listen = -1;
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
                udp_local_listen = atoi(optarg);
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
            default:
                help = 1;
        }
    }

    if (udp_local_listen < 0) {
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

    if (help >= 0) {
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
                client_conenctions, client_proxy, client_dest);

    free(shared_secret);
    free(client_proxy);
    free(server_listen);

    return 0;
}