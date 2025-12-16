/*************************************************
**************************************************
**              Name: AD VPN Main               **
**              Author: Arkaprava Das           **
**************************************************
**************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>

#include "../include/ad_vpn.h"

/* -------------------------
 * Globals
 * ------------------------- */
static volatile int g_running = 1;

/* -------------------------
 * Signal handling
 * ------------------------- */
static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* -------------------------
 * Main
 * ------------------------- */
int main(int argc, char **argv)
{
    int err = ad_logger_init("../configs/ad_zlog_config.conf");
    if (err != 0) {
        fprintf(stderr, "Failed to initialize logger: %d\n", err);
        return err;
    }

    /* Handle SIGINT / SIGTERM */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* -------------------------
     * Transport init
     * ------------------------- */
    ad_transport_config_t cfg = {
        .config_path = "../configs/ad_vpn_config.ini"
    };

    if (ad_transport_init_with_config(&cfg) != AD_TRANSPORT_OK) {
        AD_LOG_GENERAL_ERROR("Transport init failed");
        fprintf(stderr, "Transport init failed\n");
        return EXIT_FAILURE;
    }

    if (ad_transport_start() != AD_TRANSPORT_OK) {
        AD_LOG_GENERAL_ERROR("Transport start failed");
        fprintf(stderr, "Transport start failed\n");
        return EXIT_FAILURE;
    }

    /* -------------------------
     * Get FDs
     * ------------------------- */
    int tun_fd, udp_fd;

    if (ad_transport_get_tun_fd(&tun_fd) != AD_TRANSPORT_OK ||
        ad_transport_get_udp_fd(&udp_fd) != AD_TRANSPORT_OK) {
        AD_LOG_GENERAL_ERROR("Failed to get transport FDs");
        fprintf(stderr, "Failed to get transport FDs\n");
        goto shutdown;
    }

    /* -------------------------
     * epoll setup
     * ------------------------- */
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        AD_LOG_GENERAL_ERROR("epoll_create1() failed (errno=%d)", errno);
        perror("epoll_create1");
        goto shutdown;
    }

    struct epoll_event ev = {0};

    ev.events = EPOLLIN;
    ev.data.fd = tun_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev);

    ev.events = EPOLLIN;
    ev.data.fd = udp_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, udp_fd, &ev);

    AD_LOG_GENERAL_INFO("AD VPN started (TUN=%d UDP=%d)", tun_fd, udp_fd);
    printf("AD VPN started (TUN=%d UDP=%d)\n", tun_fd, udp_fd);

    /* -------------------------
     * Event loop
     * ------------------------- */
    while (g_running) {
        struct epoll_event events[8];
        int n = epoll_wait(epfd, events, 8, -1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == tun_fd) {
                ad_transport_handle_tun_event();
            }
            else if (fd == udp_fd) {
                ad_transport_handle_udp_event();
            }
        }
    }

    AD_LOG_GENERAL_INFO("Shutting down AD VPN...");
    printf("Shutting down AD VPN...\n");

shutdown:
    ad_transport_stop();
    return EXIT_SUCCESS;
}
