#define _GNU_SOURCE
#include "client.h"
#include "../logger/src/logger.h"
#include "../tun/src/tun_utils.h"
#include "../secure_channel/src/secure_channel.h"
#include <stdio.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <net/if.h>
#include <stdlib.h>

// Default reconnection parameters
#define DEFAULT_MAX_RECONNECT_ATTEMPTS 10
#define DEFAULT_RECONNECT_DELAY_SEC 5
#define MAX_BACKOFF_DELAY_SEC 60

static void handle_sigint(int signo) {
    (void)signo;
    LOG_INFO("SIGINT received. Stopping client...");
}

static void handle_sigterm(int signo) {
    (void)signo;
    LOG_INFO("SIGTERM received. Stopping client...");
}

int client_init(client_ctx_t *c, 
                const char *tun_cidr, 
                int mtu, 
                const char *server_ip, 
                uint16_t server_port, 
                auth_mode_t auth, 
                const char *secret_or_token,
                int set_default_route)
{
    memset(c, 0, sizeof(*c));
    
    // Set up signal handlers
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigterm);
    
    // Initialize configuration
    strncpy(c->tun_cidr, tun_cidr, sizeof(c->tun_cidr) - 1);
    c->mtu = mtu;
    strncpy(c->server_ip, server_ip, sizeof(c->server_ip) - 1);
    c->server_port = server_port;
    c->auth_mode = auth;
    strncpy(c->secret_or_token, secret_or_token, sizeof(c->secret_or_token) - 1);
    c->set_default_route = set_default_route;
    
    // Initialize reconnection parameters
    c->max_reconnect_attempts = DEFAULT_MAX_RECONNECT_ATTEMPTS;
    c->reconnect_delay_sec = DEFAULT_RECONNECT_DELAY_SEC;
    c->current_reconnect_attempt = 0;
    c->last_reconnect_time = 0;
    
    // Initialize state
    c->running = 1;
    c->connected = 0;
    c->sock_fd = -1;
    
    LOG_INFO("Initializing VPN client...");
    LOG_INFO("Server: %s:%u", c->server_ip, c->server_port);
    LOG_INFO("TUN: %s, MTU: %d", c->tun_cidr, c->mtu);
    
    // 1. Create and configure TUN interface
    if (tun_create(c->tun.ifname, sizeof(c->tun.ifname)) < 0) {
        LOG_ERROR("Failed to create TUN interface");
        return -1;
    }
    
    // Configure TUN interface
    char ip_str[32], mask_str[32];
    cidr_to_addr_mask(c->tun_cidr, ip_str, sizeof(ip_str), mask_str, sizeof(mask_str));
    
    if (if_set_addr_netmask(c->tun.ifname, ip_str, mask_str) < 0) {
        LOG_ERROR("Failed to set TUN IP/netmask");
        return -1;
    }
    
    if (if_set_mtu(c->tun.ifname, c->mtu) < 0) {
        LOG_ERROR("Failed to set TUN MTU");
        return -1;
    }
    
    if (if_set_flags(c->tun.ifname, IFF_UP | IFF_RUNNING, 1) < 0) {
        LOG_ERROR("Failed to bring up TUN interface");
        return -1;
    }
    
    LOG_INFO("TUN interface configured: %s (%s/%s), MTU=%d", 
             c->tun.ifname, ip_str, mask_str, c->mtu);
    
    // 2. Setup routing if requested
    if (c->set_default_route) {
        if (client_setup_routing(c) < 0) {
            LOG_ERROR("Failed to setup routing");
            return -1;
        }
    }
    
    // 3. Initial connection attempt
    if (client_connect(c) < 0) {
        LOG_ERROR("Initial connection failed");
        return -1;
    }
    
    LOG_INFO("Client initialization complete");
    return 0;
}

int client_connect(client_ctx_t *c) {
    if (c->connected) {
        LOG_WARN("Already connected");
        return 0;
    }
    
    // Create socket
    c->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->sock_fd < 0) {
        LOG_ERROR("Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(c->sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_WARN("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    // Set non-blocking for connection timeout
    int flags = fcntl(c->sock_fd, F_GETFL, 0);
    fcntl(c->sock_fd, F_SETFL, flags | O_NONBLOCK);
    
    // Connect
    struct sockaddr_in srv_addr = {0};
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(c->server_port);
    if (inet_pton(AF_INET, c->server_ip, &srv_addr.sin_addr) <= 0) {
        LOG_ERROR("Invalid server IP: %s", c->server_ip);
        close(c->sock_fd);
        c->sock_fd = -1;
        return -1;
    }
    
    LOG_INFO("Connecting to server %s:%u", c->server_ip, c->server_port);
    
    int ret = connect(c->sock_fd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if (ret < 0 && errno != EINPROGRESS) {
        LOG_ERROR("Connect failed: %s", strerror(errno));
        close(c->sock_fd);
        c->sock_fd = -1;
        return -1;
    }
    
    // Wait for connection with timeout
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(c->sock_fd, &write_fds);
    
    struct timeval timeout = {10, 0}; // 10 second timeout
    ret = select(c->sock_fd + 1, NULL, &write_fds, NULL, &timeout);
    
    if (ret <= 0) {
        LOG_ERROR("Connection timeout");
        close(c->sock_fd);
        c->sock_fd = -1;
        return -1;
    }
    
    // Check for connection errors
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(c->sock_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
        LOG_ERROR("Connection failed: %s", strerror(error));
        close(c->sock_fd);
        c->sock_fd = -1;
        return -1;
    }
    
    // Restore blocking mode
    fcntl(c->sock_fd, F_SETFL, flags);
    
    // Initialize secure channel
    if (sc_client_begin(&c->sc, c->sock_fd, c->auth_mode, c->secret_or_token) < 0) {
        LOG_ERROR("Secure channel handshake begin failed");
        close(c->sock_fd);
        c->sock_fd = -1;
        return -1;
    }
    
    if (sc_client_finish(&c->sc) < 0) {
        LOG_ERROR("Secure channel handshake finish failed");
        close(c->sock_fd);
        c->sock_fd = -1;
        return -1;
    }
    
    c->connected = 1;
    c->current_reconnect_attempt = 0;
    LOG_INFO("Connected to server and secure channel established");
    
    return 0;
}

int client_disconnect(client_ctx_t *c) {
    if (!c->connected) {
        return 0;
    }
    
    LOG_INFO("Disconnecting from server");
    
    if (c->sock_fd >= 0) {
        sc_close(&c->sc);
        close(c->sock_fd);
        c->sock_fd = -1;
    }
    
    c->connected = 0;
    return 0;
}

int client_loop(client_ctx_t *c) {
    LOG_INFO("Entering client loop...");
    uint8_t buf[4096];
    
    while (c->running) {
        if (!c->connected) {
            // Try to reconnect
            time_t now = time(NULL);
            if (now - c->last_reconnect_time >= c->reconnect_delay_sec) {
                if (c->current_reconnect_attempt < c->max_reconnect_attempts) {
                    LOG_INFO("Attempting reconnection %d/%d", 
                             c->current_reconnect_attempt + 1, c->max_reconnect_attempts);
                    
                    if (client_connect(c) == 0) {
                        LOG_INFO("Reconnection successful");
                    } else {
                        c->current_reconnect_attempt++;
                        c->last_reconnect_time = now;
                        
                        // Exponential backoff
                        int backoff = c->reconnect_delay_sec * (1 << (c->current_reconnect_attempt - 1));
                        if (backoff > MAX_BACKOFF_DELAY_SEC) {
                            backoff = MAX_BACKOFF_DELAY_SEC;
                        }
                        c->reconnect_delay_sec = backoff;
                        
                        LOG_WARN("Reconnection failed, will retry in %d seconds", backoff);
                    }
                } else {
                    LOG_ERROR("Max reconnection attempts reached, giving up");
                    break;
                }
            }
            
            // Sleep before next reconnection attempt
            sleep(1);
            continue;
        }
        
        // Setup select for data transfer
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(c->tun.fd, &fds);
        FD_SET(c->sock_fd, &fds);
        int max_fd = (c->tun.fd > c->sock_fd) ? c->tun.fd : c->sock_fd;
        
        struct timeval timeout = {1, 0}; // 1 second timeout for responsiveness
        int ret = select(max_fd + 1, &fds, NULL, NULL, &timeout);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("select() failed: %s", strerror(errno));
            break;
        }
        
        if (ret == 0) {
            // Timeout, check if we should continue
            continue;
        }
        
        // Data from TUN → Secure Channel
        if (FD_ISSET(c->tun.fd, &fds)) {
            ssize_t n = tun_read(c->tun.fd, buf, sizeof(buf));
            if (n > 0) {
                if (sc_send_data(&c->sc, buf, n) < 0) {
                    LOG_WARN("Failed to send data to server, connection may be lost");
                    client_disconnect(c);
                }
            } else if (n < 0) {
                LOG_ERROR("TUN read error: %s", strerror(errno));
                break;
            }
        }
        
        // Data from Secure Channel → TUN
        if (FD_ISSET(c->sock_fd, &fds)) {
            ssize_t n = sc_recv_data(&c->sc, buf, sizeof(buf));
            if (n > 0) {
                if (tun_write(c->tun.fd, buf, n) < 0) {
                    LOG_WARN("Failed to write data to TUN");
                }
            } else if (n == 0) {
                LOG_WARN("Server closed connection");
                client_disconnect(c);
            } else if (n < 0) {
                LOG_WARN("Secure channel receive error, connection may be lost");
                client_disconnect(c);
            }
        }
    }
    
    LOG_INFO("Client loop terminated");
    return 0;
}

int client_setup_routing(client_ctx_t *c) {
    LOG_INFO("Setting up routing via TUN interface");
    
    // Get current default gateway
    FILE *fp = popen("ip route show default | awk '/default/ {print $3}'", "r");
    if (fp) {
        if (fgets(c->original_gateway, sizeof(c->original_gateway), fp)) {
            // Remove newline
            c->original_gateway[strcspn(c->original_gateway, "\n")] = 0;
            LOG_INFO("Original gateway: %s", c->original_gateway);
        }
        pclose(fp);
    }
    
    // Add route for VPN subnet via TUN
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip route add %s dev %s", c->tun_cidr, c->tun.ifname);
    if (system(cmd) != 0) {
        LOG_WARN("Failed to add route for %s", c->tun_cidr);
    }
    
    // Set default route via TUN if requested
    if (c->set_default_route) {
        snprintf(cmd, sizeof(cmd), "ip route replace default dev %s", c->tun.ifname);
        if (system(cmd) != 0) {
            LOG_ERROR("Failed to set default route via TUN");
            return -1;
        }
        LOG_INFO("Default route set via TUN interface");
    }
    
    return 0;
}

int client_restore_routing(client_ctx_t *c) {
    LOG_INFO("Restoring original routing");
    
    // Remove default route via TUN
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip route del default dev %s 2>/dev/null", c->tun.ifname);
    (void) system(cmd);
    
    // Restore original default route if we had one
    if (strlen(c->original_gateway) > 0) {
        snprintf(cmd, sizeof(cmd), "ip route add default via %s", c->original_gateway);
        if (system(cmd) == 0) {
            LOG_INFO("Restored original default route via %s", c->original_gateway);
        }
    }
    
    // Remove VPN subnet route
    snprintf(cmd, sizeof(cmd), "ip route del %s dev %s 2>/dev/null", c->tun_cidr, c->tun.ifname);
    (void) system(cmd);
    
    return 0;
}

void client_stop(client_ctx_t *c) {
    LOG_INFO("Stopping VPN client...");
    
    c->running = 0;
    
    // Disconnect from server
    client_disconnect(c);
    
    // Restore routing
    if (c->set_default_route) {
        client_restore_routing(c);
    }
    
    // Close TUN interface
    if (c->tun.fd >= 0) {
        close(c->tun.fd);
        c->tun.fd = -1;
    }
    
    LOG_INFO("VPN client stopped");
}
