#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>
#include <getopt.h>

// Include our modules
#include "../../client/src/client.h"
#include "../../logger/src/logger.h"

// Configuration structure
typedef struct {
    char tun_if[32];
    char tun_cidr[64];
    int tun_mtu;
    char server_ip[INET_ADDRSTRLEN];
    uint16_t server_port;
    char auth_mode[16];
    char psk[65];
    char token[256];
    char client_cert[256];
    char client_key[256];
    char ca_cert[256];
    int use_vpn_as_default;
    char vpn_routes[512];
    char exclude_routes[512];
    char log_level[16];
    char log_file[256];
    int log_color;
    int max_reconnect_attempts;
    int reconnect_delay;
    int max_reconnect_delay;
    int connection_timeout;
    int keepalive_interval;
    int buffer_size;
} client_config_t;

// Global variables
static client_ctx_t g_client;
static int g_running = 1;

// Signal handlers
static void handle_sigint(int signo) {
    (void)signo;
    LOG_INFO("SIGINT received. Stopping VPN client...");
    g_running = 0;
    client_stop(&g_client);
}

static void handle_sigterm(int signo) {
    (void)signo;
    LOG_INFO("SIGTERM received. Stopping VPN client...");
    g_running = 0;
    client_stop(&g_client);
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
static int read_config(const char *config_file, client_config_t *config) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open config file '%s': %s\n", config_file, strerror(errno));
        return -1;
    }

    // Set defaults
    memset(config, 0, sizeof(*config));
    strcpy(config->tun_if, "tun0");
    strcpy(config->tun_cidr, "10.8.0.2/24");
    config->tun_mtu = 1400;
    strcpy(config->server_ip, "127.0.0.1");
    config->server_port = 8080;
    strcpy(config->auth_mode, "PSK");
    strcpy(config->psk, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    config->use_vpn_as_default = 1;
    strcpy(config->vpn_routes, "10.8.0.0/24");
    strcpy(config->log_level, "INFO");
    config->log_color = 1;
    config->max_reconnect_attempts = 10;
    config->reconnect_delay = 5;
    config->max_reconnect_delay = 60;
    config->connection_timeout = 10;
    config->keepalive_interval = 30;
    config->buffer_size = 4096;

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
        } else if (strcmp(key, "SERVER_IP") == 0) {
            strncpy(config->server_ip, value, sizeof(config->server_ip) - 1);
        } else if (strcmp(key, "SERVER_PORT") == 0) {
            config->server_port = atoi(value);
        } else if (strcmp(key, "AUTH_MODE") == 0) {
            strncpy(config->auth_mode, value, sizeof(config->auth_mode) - 1);
        } else if (strcmp(key, "PSK") == 0) {
            strncpy(config->psk, value, sizeof(config->psk) - 1);
        } else if (strcmp(key, "TOKEN") == 0) {
            strncpy(config->token, value, sizeof(config->token) - 1);
        } else if (strcmp(key, "CLIENT_CERT") == 0) {
            strncpy(config->client_cert, value, sizeof(config->client_cert) - 1);
        } else if (strcmp(key, "CLIENT_KEY") == 0) {
            strncpy(config->client_key, value, sizeof(config->client_key) - 1);
        } else if (strcmp(key, "CA_CERT") == 0) {
            strncpy(config->ca_cert, value, sizeof(config->ca_cert) - 1);
        } else if (strcmp(key, "USE_VPN_AS_DEFAULT") == 0) {
            config->use_vpn_as_default = parse_yes_no(value);
        } else if (strcmp(key, "VPN_ROUTES") == 0) {
            strncpy(config->vpn_routes, value, sizeof(config->vpn_routes) - 1);
        } else if (strcmp(key, "EXCLUDE_ROUTES") == 0) {
            strncpy(config->exclude_routes, value, sizeof(config->exclude_routes) - 1);
        } else if (strcmp(key, "LOG_LEVEL") == 0) {
            strncpy(config->log_level, value, sizeof(config->log_level) - 1);
        } else if (strcmp(key, "LOG_FILE") == 0) {
            strncpy(config->log_file, value, sizeof(config->log_file) - 1);
        } else if (strcmp(key, "LOG_COLOR") == 0) {
            config->log_color = parse_yes_no(value);
        } else if (strcmp(key, "MAX_RECONNECT_ATTEMPTS") == 0) {
            config->max_reconnect_attempts = atoi(value);
        } else if (strcmp(key, "RECONNECT_DELAY") == 0) {
            config->reconnect_delay = atoi(value);
        } else if (strcmp(key, "MAX_RECONNECT_DELAY") == 0) {
            config->max_reconnect_delay = atoi(value);
        } else if (strcmp(key, "CONNECTION_TIMEOUT") == 0) {
            config->connection_timeout = atoi(value);
        } else if (strcmp(key, "KEEPALIVE_INTERVAL") == 0) {
            config->keepalive_interval = atoi(value);
        } else if (strcmp(key, "BUFFER_SIZE") == 0) {
            config->buffer_size = atoi(value);
        }
    }

    fclose(fp);
    return 0;
}

// Print usage information
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nOptions:\n");
    printf("  -c, --config FILE     Configuration file (default: config/client.conf)\n");
    printf("  -d, --daemon          Run as daemon\n");
    printf("  -v, --verbose         Verbose output\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -c /etc/vpn/client.conf\n", program_name);
    printf("  %s --daemon --config ./client.conf\n", program_name);
}

int main(int argc, char *argv[]) {
    client_config_t config;
    char config_file[256] = "config/client.conf";
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

    LOG_INFO("VPN Client starting...");
    LOG_INFO("Configuration file: %s", config_file);
    LOG_INFO("Server: %s:%u", config.server_ip, config.server_port);
    LOG_INFO("TUN: %s (%s), MTU: %d", config.tun_if, config.tun_cidr, config.tun_mtu);

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
        auth_secret = config.token;
    } else if (strcasecmp(config.auth_mode, "MUTUALCERT") == 0) {
        // For mutual cert, we'll use the cert path as secret
        auth_secret = config.client_cert;
    }

    // Initialize client
    int ret = client_init(&g_client, 
                         config.tun_cidr,
                         config.tun_mtu,
                         config.server_ip,
                         config.server_port,
                         parse_auth_mode(config.auth_mode),
                         auth_secret,
                         config.use_vpn_as_default);

    if (ret < 0) {
        LOG_ERROR("Failed to initialize VPN client");
        return 1;
    }

    LOG_INFO("VPN Client initialized successfully");

    // Run client loop
    ret = client_loop(&g_client);

    LOG_INFO("VPN Client stopped");
    logger_cleanup();

    return ret;
}
