#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/tcp.h>

#include "conf.h"
#include "run_forever.h"
#include "subflow.h"
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
    fprintf(stderr, "Usage: %s [-hCmldbP]\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t-h  Print this help.\n");
    fprintf(stderr, "\t-C  Config file path.\n");
    fprintf(stderr, "\t-m  mode: 'client' or 'server'.\n");
    fprintf(stderr, "\t-l  tunneled_udp_listen: <udp_listen_host>:<udp_listen_port> UDP address to listen.\n");
    fprintf(stderr, "\t-d  tunneled_udp_dest: <addr>:<port> Where to send incoming UDP."
            " If absent, will be determined from the first received packet.\n");
    fprintf(stderr, "\t-b  daemonize: Daemonize.\n");
    fprintf(stderr, "\t-P  pidfile: <pidfile> Create pidfile upon successful start.\n");
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    char *tunneled_udp_listen = NULL;
    char *tunneled_udp_dest = NULL;
    int is_client = -1;
    char *shared_secret = NULL;
    char *server_listen = NULL;
    char *pidfile_path = NULL;
    int background = 0;
    int help = 0;
    char *config_path = NULL;
    subflows_group_config *subflows_group_configs = (subflows_group_config *)
            malloc(sizeof(subflows_group_config) * MAX_TUNNEL_CONNECTIONS);
    size_t subflows_group_configs_len = 0;

    int i;
    while ((i = getopt(argc, argv, "hC:m:l:d:bP:")) != -1) {
        switch (i) {
            case 'h':
                help = 2;
                break;
            case 'C':
                config_path = strdup(optarg);
                break;
            case 'm':
                is_client = strcasecmp(optarg, "client") == 0;
                break;
            case 'l':
                tunneled_udp_listen = strdup(optarg);
                break;
            case 'd':
                tunneled_udp_dest = strdup(optarg);
                break;
            case 'b':
                background = 1;
                break;
            case 'P':
                pidfile_path = strdup(optarg);
                break;
            default:
                help = 1;
        }
    }

    if (help != 2) {  // don't validate args when help is asked

        if (config_path != NULL) {
            char key[100]; // config pair. (key, val)
            char val[500];
            FILE * file;
            file = fopen(config_path , "r");
            if (!file) {
                fprintf(stderr, "Unable to read config %s:\n", config_path);
                fprintf(stderr, "%s\n", strerror(errno));
                exit(1);
            }
            while (fscanf(file, "%100s %500[^\n]", key, val) != EOF) {
                if (key[0] == '#')
                    continue; // skip comments
                if (strcasecmp(key, "mode") == 0) {
                    if (is_client < 0)
                        is_client = strcasecmp(val, "client") == 0;
                } else if (strcasecmp("server_listen", key) == 0) {
                    if (server_listen == NULL)
                        server_listen = strdup(val);
                } else if (strcasecmp("tunneled_udp_listen", key) == 0) {
                    if (tunneled_udp_listen == NULL)
                        tunneled_udp_listen = strdup(val);
                } else if (strcasecmp("tunneled_udp_dest", key) == 0) {
                    if (tunneled_udp_dest == NULL)
                        tunneled_udp_dest = strdup(val);
                } else if (strcasecmp("shared_secret", key) == 0) {
                    if (shared_secret == NULL)
                        shared_secret = strdup(val);
                } else if (strcasecmp("daemonize", key) == 0) {
                    background = 1;
                } else if (strcasecmp("pidfile", key) == 0) {
                    if (pidfile_path == NULL)
                        pidfile_path = strdup(val);
                } else if (strcasecmp("subflows_group[]", key) == 0) {
                    if (subflows_group_configs_len >= MAX_TUNNEL_CONNECTIONS) {
                        fprintf(stderr, "too many 'subflows_group[]' defined in the config."
                                " max is %d\n", MAX_TUNNEL_CONNECTIONS);
                        help = 1;
                        continue;
                    }
                    subflows_group_config * sg = &subflows_group_configs[subflows_group_configs_len++];
                    sg->proxy = NULL;
                    sg->dest = NULL;
                    sg->number = 0;
                    char * ctx;
                    // read subflows_group options
                    for (char * sg_option = strtok_r(val, " ", &ctx); sg_option != NULL;
                         sg_option = strtok_r(NULL, " ", &ctx)) {
                        char sg_key[100];
                        char sg_val[100];
                        if (2 != sscanf(sg_option, "%100[^= ]%*[ =]%100[^\n]", sg_key, sg_val)) {
                            // that is not an option: it's an arg
                            sg->dest = strdup(sg_option);
                        } else {
                            if (strcasecmp("number", sg_key) == 0) {
                                sg->number = atoi(sg_val);
                            } else if (strcasecmp("proxy", sg_key) == 0) {
                                sg->proxy = strdup(sg_val);
                            } else if (strcasecmp("dest", sg_key) == 0) {
                                sg->dest = strdup(sg_val);
                            } else {
                                fprintf(stderr, "unknown 'subflows_group[]' option: %s\n", sg_key);
                                help = 1;
                            }
                        }
                    }
                    if (sg->number <= 0 || sg->number > MAX_TUNNEL_CONNECTIONS) {
                        fprintf(stderr, "'subflows_group[]' number option must be within"
                                " range 1..%d\n", MAX_TUNNEL_CONNECTIONS);
                        help = 1;
                    }
                    if (sg->dest == NULL) {
                        fprintf(stderr, "'subflows_group[]' must define destination.\n");
                        help = 1;
                    }
                } else if (strcasecmp("\0", key) != 0) {
                    fprintf(stderr, "unknown config option: %s\n", key);
                    help = 1;
                }
                key[0] = '\0';
            }
            fclose(file);
        }

        if (tunneled_udp_listen == NULL) {
            fprintf(stderr, "-l is required (or the 'tunneled_udp_listen' config option)\n");
            help = 1;
        }
        if (is_client < 0) {
            fprintf(stderr, "-m is required (or the 'mode' config option)\n");
            help = 1;
        }
        if (shared_secret == NULL) {
            fprintf(stderr, "'shared_secret' config option is required\n");
            help = 1;
        }
        if (is_client && subflows_group_configs_len == 0) {
            fprintf(stderr, "client must have at least one 'subflows_group[]' defined in the config\n");
            help = 1;
        }
        if (!is_client && server_listen == NULL) {
            fprintf(stderr, "'server_listen' config option is required\n");
            help = 1;
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

    run_forever(tunneled_udp_listen, tunneled_udp_dest,
                is_client,
                server_listen,
                shared_secret,
                subflows_group_configs,
                subflows_group_configs_len,
                pidfile_path);

    if (pidfile_path != NULL)
        unlink(pidfile_path);

    free(tunneled_udp_listen);
    free(tunneled_udp_dest);
    free(shared_secret);
    for (int j = 0; j < subflows_group_configs_len; j++) {
        if (subflows_group_configs[j].dest)
            free(subflows_group_configs[j].dest);
        if (subflows_group_configs[j].proxy)
            free(subflows_group_configs[j].proxy);
    }
    free(subflows_group_configs);
    free(server_listen);
    free(pidfile_path);

    return 0;
}