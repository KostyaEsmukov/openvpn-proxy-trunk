#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>


#include "utils.h"
#include "prot.h"

#define BACKLOG 10  // server tcp listen backlog
#define MAX_TUNNEL_CONNECTIONS 20

int quit = 0;
void sighandler(int p) {
    if (!quit)
        syslog(LOG_INFO, "Signal %d received, issuing clean shutdown\n", p);
    else
        syslog(LOG_INFO, "Signal %d received, forcing shutdown\n", p);

    quit++;
}


int bind_local_udp(int port) {
    struct sockaddr_in si_bind;
    int sock_fd;

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        die("Unable to create listening UDP socket", errno);

    memset(&si_bind, 0, sizeof(si_bind));
    si_bind.sin_family = AF_INET;
    si_bind.sin_port = htons(port);
    si_bind.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(sock_fd, (struct sockaddr *) &si_bind, sizeof(si_bind)) == -1)
        die("Unable to bind UDP socket", errno);

    set_noblock(sock_fd);
    return sock_fd;
}


int bind_server_tcp_socket(const char *server_listen) {
    struct sockaddr_in si_bind;
    int sock_fd;
    socklen_t clen;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        die("Unable to create server listening TCP socket", errno);
    }

    clen = 1;
    setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &clen, sizeof(clen));

    memset(&si_bind, 0, sizeof(si_bind));
    si_bind.sin_family = AF_INET;
    if (!resolve_host(server_listen, &si_bind.sin_addr, &si_bind.sin_port)) {
        die("Unable to resolve server TCP listen address", errno);
    }

    if (bind(sock_fd, (struct sockaddr *) &si_bind, sizeof(struct sockaddr)) == -1) {
        die("Unable to bind server listening TCP socket", errno);
    }

    if (listen(sock_fd, BACKLOG) == -1) {
        die("Unable to listen server listening TCP socket", errno);
    }

    set_noblock(sock_fd);
    return sock_fd;
}

int server_accept_client(int server_tcp_sock_fd) {
    struct sockaddr_in clientaddr;
    socklen_t clientlen;

    int childfd = accept(server_tcp_sock_fd,
                         (struct sockaddr *) &clientaddr, &clientlen);
    if (childfd < 0) {
        syslog(LOG_INFO, "ERROR on accept, skipping that connection. (%d: %s)", errno, strerror(errno));
    }

    return childfd;
}


void add_subflow(int *active_tcp_conns_fd, int *active_tcp_conns_count, int new_fd) {
    if (*active_tcp_conns_count >= MAX_TUNNEL_CONNECTIONS) {
        fprintf(stderr, "Assertion error. Tried to add more connections than expected\n");
        exit(1);
    }

    active_tcp_conns_fd[(*active_tcp_conns_count)++] = new_fd;
}

void remove_subflow(int *active_tcp_conns_fd, int *active_tcp_conns_count, int delete_fd) {
    int pos;
    for (pos = 0; pos < *active_tcp_conns_count; pos++) {
        if (active_tcp_conns_fd[pos] == delete_fd)
            break;
    }
    if (pos >= *active_tcp_conns_count)
        return; // not found

    for (; pos + 1 < *active_tcp_conns_count; pos++) {
        active_tcp_conns_fd[pos] = active_tcp_conns_fd[pos + 1];
    }
    active_tcp_conns_fd[--(*active_tcp_conns_count)] = -1;
}


void run_forever(int udp_local_listen, int is_client, const char * server_listen, const char * shared_secret) {
    uint32_t active_tunnel_id = secure_random();
    uint32_t latest_subflow_id = 0;
    int *active_tcp_conns_fd = (int *) malloc(sizeof(int) * MAX_TUNNEL_CONNECTIONS);
    int active_tcp_conns_count = 0;

    int server_tcp_sock_fd;

    if (!is_client)
        server_tcp_sock_fd = bind_server_tcp_socket(server_listen);

    // todo client grow

    int local_udp_sock_fd = bind_local_udp(udp_local_listen);

    fd_set readfds, errorfds;
    int maxfd;

    while (quit == 0) {
        FD_ZERO(&readfds);
        FD_ZERO(&errorfds);

        FD_SET(local_udp_sock_fd, &readfds);
        FD_SET(local_udp_sock_fd, &errorfds);
        maxfd = local_udp_sock_fd;

        if (!is_client) {
            FD_SET(server_tcp_sock_fd, &readfds);
            FD_SET(server_tcp_sock_fd, &errorfds);
            maxfd = MAX(maxfd, server_tcp_sock_fd);
        }

        for (int i = 0; i < active_tcp_conns_count; i++) {
            FD_SET(active_tcp_conns_fd[i], &readfds);
            FD_SET(active_tcp_conns_fd[i], &errorfds);
            maxfd = MAX(maxfd, active_tcp_conns_fd[i]);
        }

        if (select(maxfd + 1, &readfds, 0, &errorfds, 0) < 0) {
            die("ERROR in select", errno);
        }

        // todo local_udp_sock_fd

        /**
         * Accept new TCP subflows on the server TCP listening socket
         */
        if (!is_client) {
            if (FD_ISSET(server_tcp_sock_fd, &readfds)) {
                int childfd = server_accept_client(server_tcp_sock_fd);
                if (active_tcp_conns_count >= MAX_TUNNEL_CONNECTIONS) {  // drop extra connections
                    close(childfd);
                } else {
                    if (accept_subflow(childfd, &active_tunnel_id, active_tcp_conns_count > 0,
                                       &latest_subflow_id, shared_secret)) {
                        add_subflow(active_tcp_conns_fd, &active_tcp_conns_count, childfd);
                    } else {
                        close(childfd);
                    }
                }
            }
            if (FD_ISSET(server_tcp_sock_fd, &errorfds)) {
                die("Server TCP listening socket has failed", errno);
            }
        }

        if (is_client) {
            // todo grow if needed
        }

        // todo read connected sockets pool

    }
    free(active_tcp_conns_fd);
}

void print_help(char **argv) {
    printf("openvpn udp proxy trunk. Creates multiple TCP connections "
                   "via HTTP Proxy using CONNECT and tunnels UDP packets "
                   "through them.\n");

    fprintf(stderr, "Usage: %s [-lcsknph]\n", argv[0]);
    fprintf(stderr, "\t-l  Local UDP port to listen.\n");
    fprintf(stderr, "\t-c  <addr>:<port> Client mode.\n");
    fprintf(stderr, "\t-s  [<laddr>:]<lport> Server mode.\n");
    fprintf(stderr, "\t-k  <shared_secret> Common shared secret between client and server.\n");
    fprintf(stderr, "\t-n  <client_connection_number> Number of TCP connections to maintain (not more than %d).\n", MAX_TUNNEL_CONNECTIONS);
    fprintf(stderr, "\t-p  <client_proxy_host>:<client_proxy_port> HTTP proxy to connect via.\n");
    fprintf(stderr, "\t-h  Print this help.\n");
}

int main(int argc, char **argv) {
    int udp_local_listen = -1;
    int is_client = -1;
    char * shared_secret = NULL;
    int client_conenctions = 1;
    char * client_proxy = NULL;
    char * client_dest = NULL;
    char * server_listen = NULL;
    int help = 0;

    int i;
    while ((i = getopt(argc, argv, "l:c:s:k:n:p:h")) != -1) {
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
        if (client_proxy == NULL) {
            fprintf(stderr, "-p is required\n");
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

    run_forever(udp_local_listen, is_client, server_listen, shared_secret);

    free(shared_secret);
    free(client_proxy);
    free(server_listen);

    return 0;
}