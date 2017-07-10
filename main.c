#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

# define MIN(a, b)		((a) < (b) ? (a) : (b))

#define BACKLOG 10  // server tcp listen backlog

int quit = 0;
void sighandler(int p) {
    if (!quit)
        syslog(LOG_INFO, "Signal %d received, issuing clean shutdown\n", p);
    else
        syslog(LOG_INFO, "Signal %d received, forcing shutdown\n", p);

    quit++;
}

void die(const char * msg, int errno_) {
    fprintf(stderr, "%s\n", msg);
    if (errno_ > 0)
        fprintf(stderr, "%s\n", strerror(errno_));
    exit(1);
}


void set_noblock(int sock_fd) {
    int flags;
    if ((flags = fcntl(sock_fd, F_GETFL, 0)) < 0) {
        die("get flags", errno);
    }
    if (fcntl(sock_fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        die("set blocking", errno);
    }
}

/*
 * gethostbyname() wrapper. Return 1 if OK, otherwise 0.
 *
 * from cntlm
 */
int so_resolv(struct in_addr *host, const char *name) {

    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(name, NULL, &hints, &res);
    if (rc != 0) {
        syslog(LOG_INFO, "so_resolv: %s failed (%d: %s)\n", name, rc, gai_strerror(rc));
        return 0;
    }
    int addr_set = 0;
    for (p = res; p != NULL; p = p->ai_next) {
        struct sockaddr_in *ad = (struct sockaddr_in*)(p->ai_addr);
        if (ad == NULL) {
            freeaddrinfo(res);
            return 0;
        }
        if (!addr_set) {
            memcpy(host, &ad->sin_addr, p->ai_addrlen);
            addr_set = 1;
        }
    }

    freeaddrinfo(res);

    return 1;
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

/*
 * Shortcut for malloc/memset zero.
 */
char *new(size_t size) {
    char *tmp;

    tmp = malloc(size);
    memset(tmp, 0, size);

    return tmp;
}

/*
 * Standard substr. To prevent modification of the source
 * (terminating \x0), return the result in a new memory.
 */
char *substr(const char *src, int pos, int len) {
    int l;
    char *tmp;

    if (len == 0)
        len = strlen(src);

    l = MIN(len, strlen(src) - pos);
    if (l <= 0) {
        return new(1);
    }

    tmp = new(l + 1);
    strlcpy(tmp, src + pos, l + 1);

    return tmp;
}

int resolve_host(const char * host, struct in_addr * addr, in_port_t * port) {
    int len, p;
    char * addr_str;

    len = strlen(host);
    p = strcspn(host, ":");
    if (p < len-1) {
        addr_str = substr(host, 0, p);
        if (!so_resolv(addr, addr_str)) {
            syslog(LOG_ERR, "Cannot resolve address %s\n", addr_str);
            return 0;
        }
        free(addr_str);
        *port = atoi(host+p+1);
    } else {
        addr->s_addr = htonl(INADDR_ANY);
        *port = atoi(host);
    }

    if (!*port) {
        fprintf(stderr, "Invalid port %s.", host);
        exit(1);
    }
    return 1;
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