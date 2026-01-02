/*************************************************
**************************************************
**              Name: AD VPN Main               **
**              Author: Arkaprava Das           **
**************************************************
**************************************************/

#include "../include/ad_vpn.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <limits.h>

/* -------------------------
 * Globals
 * ------------------------- */
static volatile int g_running = 1;
static ad_vpn_state_t g_state = AD_VPN_STATE_STOPPED;
static ad_vpn_config_t g_config = {0};
static int g_epfd = -1;

/* -------------------------
 * Signal handling
 * ------------------------- */
static void handle_signal(int sig)
{
    (void)sig;
    AD_LOG_GENERAL_INFO("Received signal, shutting down...");
    g_running = 0;
}

/* -------------------------
 * Helper: Get absolute path
 * ------------------------- */
static char* get_absolute_path(const char *path)
{
    if (!path) return NULL;
    
    char *abs_path = realpath(path, NULL);
    if (!abs_path) {
        /* If realpath fails, try to construct absolute path */
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            abs_path = malloc(PATH_MAX);
            if (abs_path) {
                snprintf(abs_path, PATH_MAX, "%s/%s", cwd, path);
            }
        }
    }
    return abs_path;
}

/* -------------------------
 * VPN Initialization
 * ------------------------- */
int ad_vpn_init(const ad_vpn_config_t *config)
{
    if (!config || !config->config_path) {
        AD_LOG_GENERAL_ERROR("Invalid VPN configuration");
        return -1;
    }

    if (g_state != AD_VPN_STATE_STOPPED) {
        AD_LOG_GENERAL_WARN("VPN already initialized");
        return -1;
    }

    g_state = AD_VPN_STATE_INITIALIZING;
    g_config = *config;

    /* Get absolute paths */
    char *abs_config = get_absolute_path(config->config_path);
    char *abs_logger_config = config->logger_config_path ? 
                               get_absolute_path(config->logger_config_path) : NULL;

    /* Initialize logger */
    const char *logger_path = abs_logger_config ? abs_logger_config : 
                              (abs_config ? "../configs/ad_zlog_config.conf" : 
                               "configs/ad_zlog_config.conf");
    
    int err = ad_logger_init(logger_path);
    if (err != 0) {
        AD_LOG_GENERAL_ERROR("Failed to initialize logger: %d", err);
        free(abs_config);
        free(abs_logger_config);
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    AD_LOG_GENERAL_INFO("Logger initialized");

    /* Initialize TUN interface */
    ad_tun_config_t tun_cfg;
    const char *tun_config_path = abs_config ? abs_config : config->config_path;
    
    if (ad_tun_load_config(tun_config_path, &tun_cfg) != AD_TUN_OK) {
        AD_LOG_GENERAL_ERROR("Failed to load TUN configuration");
        free(abs_config);
        free(abs_logger_config);
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    if (ad_tun_init(&tun_cfg) != AD_TUN_OK) {
        AD_LOG_GENERAL_ERROR("Failed to initialize TUN interface");
        ad_tun_free_config(&tun_cfg);
        free(abs_config);
        free(abs_logger_config);
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    AD_LOG_GENERAL_INFO("TUN interface initialized: %s", tun_cfg.ifname);

    /* Initialize routing module */
    if (ad_routing_init(tun_cfg.ifname) != AD_ROUTING_OK) {
        AD_LOG_GENERAL_ERROR("Failed to initialize routing module");
        ad_tun_free_config(&tun_cfg);
        free(abs_config);
        free(abs_logger_config);
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    AD_LOG_GENERAL_INFO("Routing module initialized");

    /* Initialize transport */
    ad_transport_config_t transport_cfg = {
        .config_path = abs_config ? abs_config : config->config_path
    };

    if (ad_transport_init_with_config(&transport_cfg) != AD_TRANSPORT_OK) {
        AD_LOG_GENERAL_ERROR("Failed to initialize transport");
        ad_routing_cleanup();
        ad_tun_cleanup();
        ad_tun_free_config(&tun_cfg);
        free(abs_config);
        free(abs_logger_config);
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    AD_LOG_GENERAL_INFO("Transport module initialized");

    /* Free config strings */
    ad_tun_free_config(&tun_cfg);
    free(abs_config);
    free(abs_logger_config);

    g_state = AD_VPN_STATE_STOPPED;
    AD_LOG_GENERAL_INFO("VPN initialization complete");
    return 0;
}

/* -------------------------
 * VPN Start
 * ------------------------- */
int ad_vpn_start(void)
{
    if (g_state != AD_VPN_STATE_STOPPED) {
        AD_LOG_GENERAL_ERROR("VPN not in stopped state");
        return -1;
    }

    g_state = AD_VPN_STATE_INITIALIZING;

    /* Start transport (this will start TUN and UDP) */
    if (ad_transport_start() != AD_TRANSPORT_OK) {
        AD_LOG_GENERAL_ERROR("Transport start failed");
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    AD_LOG_GENERAL_INFO("Transport started");

    /* Sync routes from peer table */
    if (ad_routing_sync_from_peer_table() != AD_ROUTING_OK) {
        AD_LOG_GENERAL_WARN("Failed to sync some routes, continuing anyway");
    }

    AD_LOG_GENERAL_INFO("Routes synchronized");

    /* Get file descriptors */
    int tun_fd, udp_fd;
    if (ad_transport_get_tun_fd(&tun_fd) != AD_TRANSPORT_OK ||
        ad_transport_get_udp_fd(&udp_fd) != AD_TRANSPORT_OK) {
        AD_LOG_GENERAL_ERROR("Failed to get transport FDs");
        ad_transport_stop();
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    /* Setup epoll */
    g_epfd = epoll_create1(0);
    if (g_epfd < 0) {
        AD_LOG_GENERAL_ERROR("epoll_create1() failed (errno=%d)", errno);
        ad_transport_stop();
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    struct epoll_event ev = {0};

    ev.events = EPOLLIN;
    ev.data.fd = tun_fd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0) {
        AD_LOG_GENERAL_ERROR("Failed to add TUN FD to epoll (errno=%d)", errno);
        close(g_epfd);
        g_epfd = -1;
        ad_transport_stop();
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.fd = udp_fd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, udp_fd, &ev) < 0) {
        AD_LOG_GENERAL_ERROR("Failed to add UDP FD to epoll (errno=%d)", errno);
        close(g_epfd);
        g_epfd = -1;
        ad_transport_stop();
        g_state = AD_VPN_STATE_ERROR;
        return -1;
    }

    /* Setup signal handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    g_state = AD_VPN_STATE_RUNNING;
    AD_LOG_GENERAL_INFO("AD VPN started (TUN=%d UDP=%d)", tun_fd, udp_fd);

    /* Main event loop */
    while (g_running && g_state == AD_VPN_STATE_RUNNING) {
        struct epoll_event events[8];
        int n = epoll_wait(g_epfd, events, 8, 1000); /* 1 second timeout */

        if (n < 0) {
            if (errno == EINTR)
                continue;
            AD_LOG_GENERAL_ERROR("epoll_wait failed (errno=%d)", errno);
            break;
        }

        if (n == 0) {
            /* Timeout - continue loop */
            continue;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == tun_fd) {
                ad_transport_error_t err = ad_transport_handle_tun_event();
                if (err != AD_TRANSPORT_OK && err != AD_TRANSPORT_ERR_NOT_FOUND) {
                    AD_LOG_GENERAL_WARN("TUN event handling error: %d", err);
                }
            }
            else if (fd == udp_fd) {
                ad_transport_error_t err = ad_transport_handle_udp_event();
                if (err != AD_TRANSPORT_OK) {
                    AD_LOG_GENERAL_WARN("UDP event handling error: %d", err);
                }
            }
        }
    }

    AD_LOG_GENERAL_INFO("Event loop exited, shutting down...");
    return ad_vpn_stop();
}

/* -------------------------
 * VPN Stop
 * ------------------------- */
int ad_vpn_stop(void)
{
    if (g_state == AD_VPN_STATE_STOPPED || g_state == AD_VPN_STATE_STOPPING) {
        return 0;
    }

    g_state = AD_VPN_STATE_STOPPING;
    AD_LOG_GENERAL_INFO("Stopping VPN...");

    /* Close epoll */
    if (g_epfd >= 0) {
        close(g_epfd);
        g_epfd = -1;
    }

    /* Remove routes */
    ad_routing_remove_all();
    AD_LOG_GENERAL_INFO("Routes removed");

    /* Stop transport */
    ad_transport_stop();
    AD_LOG_GENERAL_INFO("Transport stopped");

    g_state = AD_VPN_STATE_STOPPED;
    AD_LOG_GENERAL_INFO("VPN stopped");
    return 0;
}

/* -------------------------
 * VPN Cleanup
 * ------------------------- */
int ad_vpn_cleanup(void)
{
    ad_vpn_stop();

    /* Cleanup routing */
    ad_routing_cleanup();

    /* Cleanup TUN */
    ad_tun_cleanup();

    /* Cleanup logger */
    ad_logger_fini();

    g_state = AD_VPN_STATE_STOPPED;
    AD_LOG_GENERAL_INFO("VPN cleanup complete");
    return 0;
}

/* -------------------------
 * Get VPN State
 * ------------------------- */
ad_vpn_state_t ad_vpn_get_state(void)
{
    return g_state;
}

/* -------------------------
 * Main Entry Point
 * ------------------------- */
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Default configuration */
    ad_vpn_config_t config = {
        .config_path = "configs/ad_vpn_config.ini",
        .logger_config_path = "configs/ad_zlog_config.conf"
    };

    /* Allow override via environment variables */
    const char *config_env = getenv("AD_VPN_CONFIG");
    const char *logger_env = getenv("AD_VPN_LOGGER_CONFIG");

    if (config_env) {
        config.config_path = config_env;
    }
    if (logger_env) {
        config.logger_config_path = logger_env;
    }

    /* Initialize VPN */
    if (ad_vpn_init(&config) != 0) {
        fprintf(stderr, "Failed to initialize VPN\n");
        return EXIT_FAILURE;
    }

    /* Start VPN (this will run the event loop) */
    if (ad_vpn_start() != 0) {
        fprintf(stderr, "Failed to start VPN\n");
        ad_vpn_cleanup();
        return EXIT_FAILURE;
    }

    /* Cleanup */
    ad_vpn_cleanup();
    return EXIT_SUCCESS;
}
