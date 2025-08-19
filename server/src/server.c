#include "server.h"
#include "../logger/logger.h"
#include "../tun/tun_utils.h"
#include "../secure_channel/secure_channel.h"
#include <stdio.h>
#include <sys/wait.h>
#include <sys/stat.h>

// Default server parameters
#define DEFAULT_BACKLOG 5
#define DEFAULT_SELECT_TIMEOUT 1
#define MAX_CLIENTS 1  // Simple MVP: one client

static void handle_sigint(int signo) {
    (void)signo;
    LOG_INFO("SIGINT received. Stopping server...");
}

static void handle_sigterm(int signo) {
    (void)signo;
    LOG_INFO("SIGTERM received. Stopping server...");
}

int server_init(server_ctx_t *s, 
                const char *tun_cidr, 
                int mtu, 
                const char *bind_ip, 
                uint16_t bind_port, 
                auth_mode_t mode, 
                const char *psk_or_issuer, 
                const char *wan_if, 
                const char *vpn_subnet)
{
    memset(s, 0, sizeof(*s));
    
    // Set up signal handlers
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigterm);
    
    // Initialize configuration
    strncpy(s->tun_cidr, tun_cidr, sizeof(s->tun_cidr) - 1);
    s->mtu = mtu;
    strncpy(s->bind_ip, bind_ip, sizeof(s->bind_ip) - 1);
    s->bind_port = bind_port;
    s->auth_mode = mode;
    strncpy(s->psk_or_issuer, psk_or_issuer, sizeof(s->psk_or_issuer) - 1);
    strncpy(s->wan_if, wan_if, sizeof(s->wan_if) - 1);
    strncpy(s->vpn_subnet, vpn_subnet, sizeof(s->vpn_subnet) - 1);
    
    // Initialize state
    s->running = 1;
    s->client_connected = 0;
    s->listen_fd = -1;
    s->conn_fd = -1;
    s->nat_enabled = 0;
    s->ip_forwarding_enabled = 0;
    
    LOG_INFO("Initializing VPN server...");
    LOG_INFO("Bind: %s:%u", s->bind_ip, s->bind_port);
    LOG_INFO("TUN: %s, MTU: %d", s->tun_cidr, s->mtu);
    LOG_INFO("WAN: %s, VPN Subnet: %s", s->wan_if, s->vpn_subnet);
    
    // 1. Create and configure TUN interface
    if (tun_create(s->tun.ifname, sizeof(s->tun.ifname)) < 0) {
        LOG_ERROR("Failed to create TUN interface");
        return -1;
    }
    
    // Configure TUN interface
    char ip_str[32], mask_str[32];
    cidr_to_addr_mask(s->tun_cidr, ip_str, sizeof(ip_str), mask_str, sizeof(mask_str));
    
    if (if_set_addr_netmask(s->tun.ifname, ip_str, mask_str) < 0) {
        LOG_ERROR("Failed to set TUN IP/netmask");
        return -1;
    }
    
    if (if_set_mtu(s->tun.ifname, s->mtu) < 0) {
        LOG_ERROR("Failed to set TUN MTU");
        return -1;
    }
    
    if (if_set_flags(s->tun.ifname, IFF_UP | IFF_RUNNING, 1) < 0) {
        LOG_ERROR("Failed to bring up TUN interface");
        return -1;
    }
    
    LOG_INFO("TUN interface configured: %s (%s/%s), MTU=%d", 
             s->tun.ifname, ip_str, mask_str, s->mtu);
    
    // 2. Setup networking (IP forwarding, NAT)
    if (server_setup_networking(s) < 0) {
        LOG_ERROR("Failed to setup networking");
        return -1;
    }
    
    // 3. Create listening socket
    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_fd < 0) {
        LOG_ERROR("Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_WARN("Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    // Bind socket
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(s->bind_port);
    if (inet_pton(AF_INET, s->bind_ip, &server_addr.sin_addr) <= 0) {
        LOG_ERROR("Invalid bind IP: %s", s->bind_ip);
        close(s->listen_fd);
        s->listen_fd = -1;
        return -1;
    }
    
    if (bind(s->listen_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        LOG_ERROR("Bind failed: %s", strerror(errno));
        close(s->listen_fd);
        s->listen_fd = -1;
        return -1;
    }
    
    // Listen for connections
    if (listen(s->listen_fd, DEFAULT_BACKLOG) < 0) {
        LOG_ERROR("Listen failed: %s", strerror(errno));
        close(s->listen_fd);
        s->listen_fd = -1;
        return -1;
    }
    
    LOG_INFO("Server listening on %s:%u", s->bind_ip, s->bind_port);
    LOG_INFO("Server initialization complete");
    
    return 0;
}

int server_accept_and_handshake(server_ctx_t *s) {
    if (s->client_connected) {
        LOG_WARN("Client already connected");
        return 0;
    }
    
    LOG_INFO("Waiting for client connection...");
    
    // Accept client connection
    struct sockaddr_in client_addr = {0};
    socklen_t client_len = sizeof(client_addr);
    
    s->conn_fd = accept(s->listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (s->conn_fd < 0) {
        LOG_ERROR("Accept failed: %s", strerror(errno));
        return -1;
    }
    
    // Get client information
    inet_ntop(AF_INET, &client_addr.sin_addr, s->client_ip, sizeof(s->client_ip));
    s->client_port = ntohs(client_addr.sin_port);
    s->client_connect_time = time(NULL);
    
    LOG_INFO("Client connected from %s:%u", s->client_ip, s->client_port);
    
    // Initialize secure channel for server
    memset(&s->sc, 0, sizeof(s->sc));
    s->sc.sock_fd = s->conn_fd;
    s->sc.auth_mode = s->auth_mode;
    
    if (s->auth_mode == AUTH_PSK) {
        strcpy(s->sc.psk_hex, s->psk_or_issuer);
    } else if (s->auth_mode == AUTH_TOKEN) {
        strcpy(s->sc.token, s->psk_or_issuer);
    }
    
    // Perform server handshake
    int ret = sc_server_accept(&s->sc, s->conn_fd, s->auth_mode, s->psk_or_issuer);
    if (ret < 0) {
        LOG_ERROR("Secure channel handshake failed");
        close(s->conn_fd);
        s->conn_fd = -1;
        return -1;
    }
    
    s->client_connected = 1;
    LOG_INFO("Secure channel established with client");
    
    return 0;
}

int server_loop(server_ctx_t *s) {
    LOG_INFO("Entering server loop...");
    uint8_t buf[4096];
    
    while (s->running) {
        if (!s->client_connected) {
            // Wait for client connection
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(s->listen_fd, &fds);
            
            struct timeval timeout = {DEFAULT_SELECT_TIMEOUT, 0};
            int ret = select(s->listen_fd + 1, &fds, NULL, NULL, &timeout);
            
            if (ret < 0) {
                if (errno == EINTR) continue;
                LOG_ERROR("select() failed: %s", strerror(errno));
                break;
            }
            
            if (ret > 0 && FD_ISSET(s->listen_fd, &fds)) {
                if (server_accept_and_handshake(s) == 0) {
                    LOG_INFO("Client connected and handshake completed");
                }
            }
            
            continue;
        }
        
        // Setup select for data transfer
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(s->tun.fd, &fds);
        FD_SET(s->conn_fd, &fds);
        int max_fd = (s->tun.fd > s->conn_fd) ? s->tun.fd : s->conn_fd;
        
        struct timeval timeout = {DEFAULT_SELECT_TIMEOUT, 0};
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
        
        // Data from TUN → Secure Channel (to client)
        if (FD_ISSET(s->tun.fd, &fds)) {
            ssize_t n = tun_read(s->tun.fd, buf, sizeof(buf));
            if (n > 0) {
                if (sc_send_data(&s->sc, buf, n) < 0) {
                    LOG_WARN("Failed to send data to client, connection may be lost");
                    s->client_connected = 0;
                    close(s->conn_fd);
                    s->conn_fd = -1;
                    sc_close(&s->sc);
                    continue;
                }
                s->bytes_sent += n;
                s->packets_sent++;
            } else if (n < 0) {
                LOG_ERROR("TUN read error: %s", strerror(errno));
                break;
            }
        }
        
        // Data from Secure Channel → TUN (from client)
        if (FD_ISSET(s->conn_fd, &fds)) {
            ssize_t n = sc_recv_data(&s->sc, buf, sizeof(buf));
            if (n > 0) {
                if (tun_write(s->tun.fd, buf, n) < 0) {
                    LOG_WARN("Failed to write data to TUN");
                } else {
                    s->bytes_received += n;
                    s->packets_received++;
                }
            } else if (n == 0) {
                LOG_WARN("Client disconnected");
                s->client_connected = 0;
                close(s->conn_fd);
                s->conn_fd = -1;
                sc_close(&s->sc);
            } else if (n < 0) {
                LOG_WARN("Secure channel receive error, client may have disconnected");
                s->client_connected = 0;
                close(s->conn_fd);
                s->conn_fd = -1;
                sc_close(&s->sc);
            }
        }
    }
    
    LOG_INFO("Server loop terminated");
    return 0;
}

int server_setup_networking(server_ctx_t *s) {
    LOG_INFO("Setting up server networking...");
    
    // Enable IP forwarding
    if (server_enable_ip_forwarding(s) < 0) {
        LOG_ERROR("Failed to enable IP forwarding");
        return -1;
    }
    
    // Setup NAT
    if (server_setup_nat(s) < 0) {
        LOG_ERROR("Failed to setup NAT");
        return -1;
    }
    
    LOG_INFO("Networking setup complete");
    return 0;
}

int server_restore_networking(server_ctx_t *s) {
    LOG_INFO("Restoring original networking configuration...");
    
    // Remove NAT rules
    if (s->nat_enabled) {
        server_remove_nat(s);
    }
    
    // Disable IP forwarding
    if (s->ip_forwarding_enabled) {
        server_disable_ip_forwarding(s);
    }
    
    LOG_INFO("Networking configuration restored");
    return 0;
}

int server_setup_nat(server_ctx_t *s) {
    LOG_INFO("Setting up NAT masquerade for %s via %s", s->vpn_subnet, s->wan_if);
    
    char cmd[512];
    
    // Add NAT masquerade rule
    snprintf(cmd, sizeof(cmd), 
             "iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE",
             s->vpn_subnet, s->wan_if);
    if (system(cmd) != 0) {
        LOG_ERROR("Failed to add NAT masquerade rule");
        return -1;
    }
    
    // Add forward rules
    snprintf(cmd, sizeof(cmd), 
             "iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT",
             s->wan_if, s->tun.ifname);
    if (system(cmd) != 0) {
        LOG_WARN("Failed to add forward rule (established connections)");
    }
    
    snprintf(cmd, sizeof(cmd), 
             "iptables -A FORWARD -i %s -o %s -j ACCEPT",
             s->tun.ifname, s->wan_if);
    if (system(cmd) != 0) {
        LOG_WARN("Failed to add forward rule (VPN to WAN)");
    }
    
    s->nat_enabled = 1;
    LOG_INFO("NAT configuration complete");
    
    return 0;
}

int server_remove_nat(server_ctx_t *s) {
    LOG_INFO("Removing NAT configuration...");
    
    char cmd[512];
    
    // Remove forward rules
    snprintf(cmd, sizeof(cmd), 
             "iptables -D FORWARD -i %s -o %s -j ACCEPT 2>/dev/null",
             s->tun.ifname, s->wan_if);
    system(cmd);
    
    snprintf(cmd, sizeof(cmd), 
             "iptables -D FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null",
             s->wan_if, s->tun.ifname);
    system(cmd);
    
    // Remove NAT masquerade rule
    snprintf(cmd, sizeof(cmd), 
             "iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null",
             s->vpn_subnet, s->wan_if);
    system(cmd);
    
    s->nat_enabled = 0;
    LOG_INFO("NAT configuration removed");
    
    return 0;
}

int server_enable_ip_forwarding(server_ctx_t *s) {
    LOG_INFO("Enabling IP forwarding...");
    
    // Enable IP forwarding
    if (system("echo 1 > /proc/sys/net/ipv4/ip_forward") != 0) {
        LOG_ERROR("Failed to enable IP forwarding");
        return -1;
    }
    
    s->ip_forwarding_enabled = 1;
    LOG_INFO("IP forwarding enabled");
    
    return 0;
}

int server_disable_ip_forwarding(server_ctx_t *s) {
    LOG_INFO("Disabling IP forwarding...");
    
    // Disable IP forwarding
    if (system("echo 0 > /proc/sys/net/ipv4/ip_forward") != 0) {
        LOG_WARN("Failed to disable IP forwarding");
    }
    
    s->ip_forwarding_enabled = 0;
    LOG_INFO("IP forwarding disabled");
    
    return 0;
}

void server_print_statistics(server_ctx_t *s) {
    LOG_INFO("=== Server Statistics ===");
    LOG_INFO("Client connected: %s", s->client_connected ? "Yes" : "No");
    if (s->client_connected) {
        LOG_INFO("Client: %s:%u", s->client_ip, s->client_port);
        LOG_INFO("Connected since: %s", ctime(&s->client_connect_time));
    }
    LOG_INFO("Bytes received: %lu", (unsigned long)s->bytes_received);
    LOG_INFO("Bytes sent: %lu", (unsigned long)s->bytes_sent);
    LOG_INFO("Packets received: %lu", (unsigned long)s->packets_received);
    LOG_INFO("Packets sent: %lu", (unsigned long)s->packets_sent);
    LOG_INFO("NAT enabled: %s", s->nat_enabled ? "Yes" : "No");
    LOG_INFO("IP forwarding: %s", s->ip_forwarding_enabled ? "Yes" : "No");
    LOG_INFO("========================");
}

void server_stop(server_ctx_t *s) {
    LOG_INFO("Stopping VPN server...");
    
    s->running = 0;
    
    // Disconnect client
    if (s->client_connected) {
        LOG_INFO("Disconnecting client %s:%u", s->client_ip, s->client_port);
        sc_close(&s->sc);
        close(s->conn_fd);
        s->conn_fd = -1;
        s->client_connected = 0;
    }
    
    // Close listening socket
    if (s->listen_fd >= 0) {
        close(s->listen_fd);
        s->listen_fd = -1;
    }
    
    // Print final statistics
    server_print_statistics(s);
    
    // Restore networking configuration
    server_restore_networking(s);
    
    // Close TUN interface
    if (s->tun.fd >= 0) {
        close(s->tun.fd);
        s->tun.fd = -1;
    }
    
    LOG_INFO("VPN server stopped");
}
