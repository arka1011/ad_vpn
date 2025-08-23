#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>

// Include the required headers for type definitions
#include "../tun/src/tun_utils.h"
#include "../secure_channel/src/secure_channel.h"

// Server context structure
typedef struct {
    tun_handle_t   tun;
    int            listen_fd;   // UDP: not used, TCP: accept()
    int            conn_fd;     // per-client (simple MVP: one client)
    secure_chan_t  sc;
    int            running;
    
    // Session management
    int            client_connected;
    time_t         client_connect_time;
    char           client_ip[INET_ADDRSTRLEN];
    uint16_t       client_port;
    
    // Configuration
    char           bind_ip[INET_ADDRSTRLEN];
    uint16_t       bind_port;
    auth_mode_t    auth_mode;
    char           psk_or_issuer[256];
    char           tun_cidr[64];
    int            mtu;
    char           wan_if[32];
    char           vpn_subnet[64];
    
    // NAT and routing
    int            nat_enabled;
    int            ip_forwarding_enabled;
    char           original_gateway[INET_ADDRSTRLEN];
    
    // Statistics
    uint64_t       bytes_received;
    uint64_t       bytes_sent;
    uint64_t       packets_received;
    uint64_t       packets_sent;
} server_ctx_t;

// Initialize server context
int server_init(server_ctx_t *s, 
                const char *tun_cidr, 
                int mtu, 
                const char *bind_ip, 
                uint16_t bind_port, 
                auth_mode_t mode, 
                const char *psk_or_issuer, 
                const char *wan_if, 
                const char *vpn_subnet);

// Accept client connection and perform handshake
int server_accept_and_handshake(server_ctx_t *s);

// Main server loop with packet forwarding
int server_loop(server_ctx_t *s);

// Stop server and cleanup
void server_stop(server_ctx_t *s);

// Internal functions
int server_setup_networking(server_ctx_t *s);
int server_restore_networking(server_ctx_t *s);
int server_setup_nat(server_ctx_t *s);
int server_remove_nat(server_ctx_t *s);
int server_enable_ip_forwarding(server_ctx_t *s);
int server_disable_ip_forwarding(server_ctx_t *s);
void server_print_statistics(server_ctx_t *s);

#endif // SERVER_H
