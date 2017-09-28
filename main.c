#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "conf.h"
#include "run_forever.h"
#include "utils.h"


void daemonize() {
    // how to daemonize:
    // https://stackoverflow.com/a/3095624
    int pid;
    pid = fork();
    if (pid == -1) {
        die("Unable to fork", errno);
    }
    if (pid) {  // parent
        exit(0);
    }

    logger_daemonize();

    setsid();

    pid = fork();
    if (pid == -1) {
        die("Unable to fork", errno);
    }
    if (pid) {  // parent
        exit(0);
    }
    chdir("/");
    umask(0);

    // redirect stdin, stdout, stderr to /dev/null
    int devnull_fd = open("/dev/null", O_RDWR);
    if (devnull_fd >= 0) {
        dup2(devnull_fd, 0);
        dup2(devnull_fd, 1);
        dup2(devnull_fd, 2);
        if (devnull_fd > 2)
            close(devnull_fd);
    }
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
    fprintf(stderr, "\t-b  Daemonize.\n");
    fprintf(stderr, "\t-P  <pidfile> Create pidfile upon successful start.\n");
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
    char *pidfile_path = NULL;
    int background = 0;
    int help = 0;

    int i;
    while ((i = getopt(argc, argv, "l:c:s:k:n:p:d:bP:h")) != -1) {
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
            case 'b':
                background = 1;
                break;
            case 'P':
                pidfile_path = strdup(optarg);
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

    if (background) {
        daemonize();
    }
    umask(0);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, &sighandler);
    signal(SIGTERM, &sighandler);
    signal(SIGHUP, &sighandler);

    run_forever(udp_local_listen, udp_local_dest,
                is_client, server_listen,
                shared_secret,
                client_conenctions,
                client_proxy, client_dest,
                pidfile_path);

    if (pidfile_path != NULL)
        unlink(pidfile_path);

    free(udp_local_listen);
    free(udp_local_dest);
    free(shared_secret);
    free(client_proxy);
    free(client_dest);
    free(server_listen);
    free(pidfile_path);

    return 0;
}