#ifndef CLIENT_H
#define CLIENT_H

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

// auth_mode_t is already defined in secure_channel.h

// Client context structure
typedef struct {
    tun_handle_t   tun;
    secure_chan_t  sc;
    int            sock_fd;
    int            running;
    int            connected;
    
    // Reconnection parameters
    int            max_reconnect_attempts;
    int            reconnect_delay_sec;
    int            current_reconnect_attempt;
    time_t         last_reconnect_time;
    
    // Configuration
    char           server_ip[INET_ADDRSTRLEN];
    uint16_t       server_port;
    auth_mode_t    auth_mode;
    char           secret_or_token[256];
    char           tun_cidr[64];
    int            mtu;
    
    // Route management
    int            set_default_route;
    char           original_gateway[INET_ADDRSTRLEN];
} client_ctx_t;

// Initialize client context
int client_init(client_ctx_t *c, 
                const char *tun_cidr, 
                int mtu, 
                const char *server_ip, 
                uint16_t server_port, 
                auth_mode_t auth, 
                const char *secret_or_token,
                int set_default_route);

// Main client loop with reconnection logic
int client_loop(client_ctx_t *c);

// Stop client and cleanup
void client_stop(client_ctx_t *c);

// Internal functions
int client_connect(client_ctx_t *c);
int client_disconnect(client_ctx_t *c);
int client_setup_routing(client_ctx_t *c);
int client_restore_routing(client_ctx_t *c);

#endif // CLIENT_H
