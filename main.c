#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>

#include "utils.h"

#define BACKLOG 10  // server tcp listen backlog

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



void init_client() {

}

int init_server(const char * server_listen) {
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

void run_forever(int udp_local_listen, int is_client, const char * server_listen) {

    int local_udp_sock_fd = bind_local_udp(udp_local_listen);

    if (is_client) {
        init_client();
    } else {
        int server_tcp_sock_fd = init_server(server_listen);
    }

}

void print_help(char **argv) {
    printf("openvpn udp proxy trunk. Creates multiple TCP connections "
                   "via HTTP Proxy using CONNECT and tunnels UDP packets "
                   "thru them.\n");

    fprintf(stderr, "Usage: %s [-lcsknph]\n", argv[0]);
    fprintf(stderr, "\t-l  Local UDP port to listen.\n");
    fprintf(stderr, "\t-c  Client mode.\n");
    fprintf(stderr, "\t-s  [<laddr>:]<lport> Server mode.\n");
    fprintf(stderr, "\t-k  <shared_secret> Common shared secret between client and server.\n");
    fprintf(stderr, "\t-n  <client_connection_number> Number of TCP connections to maintain.\n");
    fprintf(stderr, "\t-p  <client_proxy_host>:<client_proxy_port> HTTP proxy to connect via.\n");
    fprintf(stderr, "\t-h  Print this help.\n");
}

int main(int argc, char **argv) {
    int udp_local_listen = -1;
    int is_client = -1;
    char * common_secret = NULL;
    int client_conenctions = 1;
    char * client_proxy = NULL;
    char * server_listen = NULL;
    int help = 0;

    int i;
    while ((i = getopt(argc, argv, "l:cs:k:n:p:h")) != -1) {
        switch (i) {
            case 'l':
                udp_local_listen = atoi(optarg);
                break;
            case 'c':
                is_client = 1;
                break;
            case 's':
                is_client = 0;
                server_listen = strdup(optarg);
                break;
            case 'k':
                common_secret = strdup(optarg);
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

    if (common_secret == NULL) {
        fprintf(stderr, "-k is required\n");
        help = 1;
    }

    if (is_client && client_proxy == NULL) {
        fprintf(stderr, "-p is required\n");
        help = 1;
    }

    if (help >= 0) {
        print_help(argv);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, &sighandler);
    signal(SIGTERM, &sighandler);
    signal(SIGHUP, &sighandler);

    run_forever(udp_local_listen, is_client, server_listen);

    free(common_secret);
    free(client_proxy);
    free(server_listen);

    return 0;
}