#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <getopt.h>

// Include our modules
#include "../../server/src/server.h"
#include "../../logger/src/logger.h"

// Configuration structure
typedef struct {
    char tun_if[32];
    char tun_cidr[64];
    int tun_mtu;
    char bind_ip[INET_ADDRSTRLEN];
    uint16_t bind_port;
    char wan_if[32];
    char vpn_subnet[64];
    char auth_mode[16];
    char psk[65];
    char token_issuer[256];
    char server_cert[256];
    char server_key[256];
    char ca_cert[256];
    int enable_nat;
    int enable_ip_forward;
    char local_subnet[64];
    int max_clients;
    int client_timeout;
    int enable_stats;
    char log_level[16];
    char log_file[256];
    int log_color;
    int connection_backlog;
    int select_timeout;
    int buffer_size;
    int rate_limit;
    int max_connections_per_minute;
    int log_connections;
} server_config_t;

// Global variables
static server_ctx_t g_server;
static int g_running = 1;

// Signal handlers
static void handle_sigint(int signo) {
    (void)signo;
    LOG_INFO("SIGINT received. Stopping VPN server...");
    g_running = 0;
    server_stop(&g_server);
}

static void handle_sigterm(int signo) {
    (void)signo;
    LOG_INFO("SIGTERM received. Stopping VPN server...");
    g_running = 0;
    server_stop(&g_server);
}

// Configuration parsing functions
static int parse_auth_mode(const char *mode_str) {
    if (strcasecmp(mode_str, "PSK") == 0) return AUTH_PSK;
    if (strcasecmp(mode_str, "TOKEN") == 0) return AUTH_TOKEN;
    if (strcasecmp(mode_str, "MUTUALCERT") == 0) return AUTH_MUTUALCERT;
    return AUTH_PSK; // default
}

static int parse_log_level(const char *level_str) {
    if (strcasecmp(level_str, "TRACE") == 0) return LOG_LEVEL_TRACE;
    if (strcasecmp(level_str, "DEBUG") == 0) return LOG_LEVEL_DEBUG;
    if (strcasecmp(level_str, "INFO") == 0) return LOG_LEVEL_INFO;
    if (strcasecmp(level_str, "WARN") == 0) return LOG_LEVEL_WARN;
    if (strcasecmp(level_str, "ERROR") == 0) return LOG_LEVEL_ERROR;
    if (strcasecmp(level_str, "FATAL") == 0) return LOG_LEVEL_FATAL;
    return LOG_LEVEL_INFO; // default
}

static int parse_yes_no(const char *value) {
    if (strcasecmp(value, "yes") == 0 || strcasecmp(value, "true") == 0 || strcasecmp(value, "1") == 0) {
        return 1;
    }
    return 0;
}

// Read configuration from file
static int read_config(const char *config_file, server_config_t *config) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open config file '%s': %s\n", config_file, strerror(errno));
        return -1;
    }

    // Set defaults
    memset(config, 0, sizeof(*config));
    strcpy(config->tun_if, "tun0");
    strcpy(config->tun_cidr, "10.8.0.1/24");
    config->tun_mtu = 1400;
    strcpy(config->bind_ip, "0.0.0.0");
    config->bind_port = 8080;
    strcpy(config->wan_if, "eth0");
    strcpy(config->vpn_subnet, "10.8.0.0/24");
    strcpy(config->auth_mode, "PSK");
    strcpy(config->psk, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    config->enable_nat = 1;
    config->enable_ip_forward = 1;
    strcpy(config->local_subnet, "192.168.1.0/24");
    config->max_clients = 10;
    config->client_timeout = 300;
    config->enable_stats = 1;
    strcpy(config->log_level, "INFO");
    config->log_color = 1;
    config->connection_backlog = 5;
    config->select_timeout = 1;
    config->buffer_size = 4096;
    config->rate_limit = 0;
    config->max_connections_per_minute = 60;
    config->log_connections = 1;

    char line[1024];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') {
            continue;
        }

        // Remove newline
        line[strcspn(line, "\n")] = 0;

        char *equals = strchr(line, '=');
        if (!equals) {
            fprintf(stderr, "Warning: Invalid line %d in config file\n", line_num);
            continue;
        }

        *equals = '\0';
        char *key = line;
        char *value = equals + 1;

        // Remove quotes from value
        if (value[0] == '"') {
            value++;
            char *end_quote = strrchr(value, '"');
            if (end_quote) *end_quote = '\0';
        }

        // Parse configuration values
        if (strcmp(key, "TUN_IF") == 0) {
            strncpy(config->tun_if, value, sizeof(config->tun_if) - 1);
        } else if (strcmp(key, "TUN_CIDR") == 0) {
            strncpy(config->tun_cidr, value, sizeof(config->tun_cidr) - 1);
        } else if (strcmp(key, "TUN_MTU") == 0) {
            config->tun_mtu = atoi(value);
        } else if (strcmp(key, "BIND_IP") == 0) {
            strncpy(config->bind_ip, value, sizeof(config->bind_ip) - 1);
        } else if (strcmp(key, "BIND_PORT") == 0) {
            config->bind_port = atoi(value);
        } else if (strcmp(key, "WAN_IF") == 0) {
            strncpy(config->wan_if, value, sizeof(config->wan_if) - 1);
        } else if (strcmp(key, "VPN_SUBNET") == 0) {
            strncpy(config->vpn_subnet, value, sizeof(config->vpn_subnet) - 1);
        } else if (strcmp(key, "AUTH_MODE") == 0) {
            strncpy(config->auth_mode, value, sizeof(config->auth_mode) - 1);
        } else if (strcmp(key, "PSK") == 0) {
            strncpy(config->psk, value, sizeof(config->psk) - 1);
        } else if (strcmp(key, "TOKEN_ISSUER") == 0) {
            strncpy(config->token_issuer, value, sizeof(config->token_issuer) - 1);
        } else if (strcmp(key, "SERVER_CERT") == 0) {
            strncpy(config->server_cert, value, sizeof(config->server_cert) - 1);
        } else if (strcmp(key, "SERVER_KEY") == 0) {
            strncpy(config->server_key, value, sizeof(config->server_key) - 1);
        } else if (strcmp(key, "CA_CERT") == 0) {
            strncpy(config->ca_cert, value, sizeof(config->ca_cert) - 1);
        } else if (strcmp(key, "ENABLE_NAT") == 0) {
            config->enable_nat = parse_yes_no(value);
        } else if (strcmp(key, "ENABLE_IP_FORWARD") == 0) {
            config->enable_ip_forward = parse_yes_no(value);
        } else if (strcmp(key, "LOCAL_SUBNET") == 0) {
            strncpy(config->local_subnet, value, sizeof(config->local_subnet) - 1);
        } else if (strcmp(key, "MAX_CLIENTS") == 0) {
            config->max_clients = atoi(value);
        } else if (strcmp(key, "CLIENT_TIMEOUT") == 0) {
            config->client_timeout = atoi(value);
        } else if (strcmp(key, "ENABLE_STATS") == 0) {
            config->enable_stats = parse_yes_no(value);
        } else if (strcmp(key, "LOG_LEVEL") == 0) {
            strncpy(config->log_level, value, sizeof(config->log_level) - 1);
        } else if (strcmp(key, "LOG_FILE") == 0) {
            strncpy(config->log_file, value, sizeof(config->log_file) - 1);
        } else if (strcmp(key, "LOG_COLOR") == 0) {
            config->log_color = parse_yes_no(value);
        } else if (strcmp(key, "CONNECTION_BACKLOG") == 0) {
            config->connection_backlog = atoi(value);
        } else if (strcmp(key, "SELECT_TIMEOUT") == 0) {
            config->select_timeout = atoi(value);
        } else if (strcmp(key, "BUFFER_SIZE") == 0) {
            config->buffer_size = atoi(value);
        } else if (strcmp(key, "RATE_LIMIT") == 0) {
            config->rate_limit = parse_yes_no(value);
        } else if (strcmp(key, "MAX_CONNECTIONS_PER_MINUTE") == 0) {
            config->max_connections_per_minute = atoi(value);
        } else if (strcmp(key, "LOG_CONNECTIONS") == 0) {
            config->log_connections = parse_yes_no(value);
        }
    }

    fclose(fp);
    return 0;
}

// Print usage information
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nOptions:\n");
    printf("  -c, --config FILE     Configuration file (default: config/server.conf)\n");
    printf("  -d, --daemon          Run as daemon\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -c /etc/vpn/server.conf\n", program_name);
    printf("  %s --daemon --config ./server.conf\n", program_name);
}

int main(int argc, char *argv[]) {
    server_config_t config;
    char config_file[256] = "config/server.conf";
    int daemon_mode = 0;
    int verbose = 0;

    // Parse command line arguments
    int opt;
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"daemon", no_argument, 0, 'd'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:dv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                strncpy(config_file, optarg, sizeof(config_file) - 1);
                break;
            case 'd':
                daemon_mode = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Check if config file exists
    if (access(config_file, R_OK) != 0) {
        fprintf(stderr, "Error: Configuration file '%s' not found or not readable\n", config_file);
        return 1;
    }

    // Read configuration
    if (read_config(config_file, &config) < 0) {
        return 1;
    }

    // Initialize logger
    const char *log_file = (strlen(config.log_file) > 0) ? config.log_file : NULL;
    if (logger_init(log_file, parse_log_level(config.log_level)) < 0) {
        fprintf(stderr, "Error: Failed to initialize logger\n");
        return 1;
    }

    // Configure logger
    logger_enable_timestamp(1);
    logger_enable_thread_id(1);
    logger_enable_file_line(1);

    LOG_INFO("VPN Server starting...");
    LOG_INFO("Configuration file: %s", config_file);
    LOG_INFO("Bind: %s:%u", config.bind_ip, config.bind_port);
    LOG_INFO("TUN: %s (%s), MTU: %d", config.tun_if, config.tun_cidr, config.tun_mtu);
    LOG_INFO("WAN: %s, VPN Subnet: %s", config.wan_if, config.vpn_subnet);

    // Set up signal handlers
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigterm);

    // Run as daemon if requested
    if (daemon_mode) {
        if (daemon(0, 0) < 0) {
            LOG_ERROR("Failed to daemonize: %s", strerror(errno));
            return 1;
        }
        LOG_INFO("Running as daemon");
    }

    // Determine authentication secret
    const char *auth_secret = config.psk;
    if (strcasecmp(config.auth_mode, "TOKEN") == 0) {
        auth_secret = config.token_issuer;
    } else if (strcasecmp(config.auth_mode, "MUTUALCERT") == 0) {
        // For mutual cert, we'll use the cert path as secret
        auth_secret = config.server_cert;
    }

    // Initialize server
    int ret = server_init(&g_server, 
                         config.tun_cidr,
                         config.tun_mtu,
                         config.bind_ip,
                         config.bind_port,
                         parse_auth_mode(config.auth_mode),
                         auth_secret,
                         config.wan_if,
                         config.vpn_subnet);

    if (ret < 0) {
        LOG_ERROR("Failed to initialize VPN server");
        return 1;
    }

    LOG_INFO("VPN Server initialized successfully");

    // Run server loop
    ret = server_loop(&g_server);

    LOG_INFO("VPN Server stopped");
    logger_cleanup();

    return ret;
}
