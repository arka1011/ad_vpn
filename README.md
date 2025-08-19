# AD VPN - Advanced VPN Implementation

A modular, secure VPN implementation written in C with support for TUN devices, encrypted communication, and robust client-server architecture.

## Project Overview

This VPN implementation provides:
- **TUN/TAP device support** for IP packet tunneling
- **End-to-end encryption** using AEAD ciphers (ChaCha20-Poly1305, AES-256-GCM)
- **Perfect forward secrecy** with X25519 key exchange
- **Multiple authentication methods** (PSK, tokens, certificates)
- **Robust reconnection logic** with exponential backoff
- **Comprehensive logging** with multiple levels and outputs
- **Modular architecture** with shared library support
- **Complete test suite** for all components

## Project Structure

```
ad_vpn/
├── logger/           # Logging system with multiple levels
├── tun/             # TUN/TAP device utilities
├── crypto/          # Cryptographic primitives
├── secure_channel/  # Encrypted communication layer
├── client/          # VPN client implementation
├── net_config/      # Network configuration scripts
├── tests/           # Comprehensive test suite
└── Makefile         # Main build system
```

## Modules

### Logger Module (`logger/`)
- Multi-level logging (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
- Thread-safe with timestamps, thread IDs, and file/line info
- Console output with colors and file output
- Conditional logging and assertion macros

### TUN Module (`tun/`)
- TUN device creation and configuration
- Network interface management (IP, netmask, MTU, flags)
- CIDR to address/mask conversion utilities
- Read/write operations for TUN devices

### Crypto Module (`crypto/`)
- ChaCha20-Poly1305 AEAD encryption/decryption
- X25519 key generation and shared secret computation
- HKDF key derivation
- Cryptographically secure random number generation

### Secure Channel Module (`secure_channel/`)
- TLS 1.3-style handshake with X25519 key exchange
- AEAD encryption with anti-replay protection
- Multiple authentication modes (PSK, token, mutual cert)
- Sequence number management for replay protection

### Client Module (`client/`)
- **Robust VPN client implementation** with reconnection logic
- **Signal handling** for graceful shutdown (SIGINT, SIGTERM)
- **Automatic reconnection** with exponential backoff
- **Routing management** with automatic setup/restoration
- **Connection timeout handling** with non-blocking sockets
- **Error recovery** and state management

### Server Module (`server/`)
- **VPN server implementation** with session management
- **NAT configuration** with automatic iptables setup
- **IP forwarding** management for packet routing
- **Client connection handling** with secure channel establishment
- **Statistics tracking** for monitoring and debugging
- **Graceful shutdown** with cleanup and restoration

## Client Module Features

### Key Types
```c
typedef struct {
    tun_handle_t   tun;           // TUN device handle
    secure_chan_t  sc;            // Secure channel context
    int            sock_fd;       // Socket file descriptor
    int            running;       // Main loop control flag
    int            connected;     // Connection state
    
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
```

### Functions

#### `client_init()`
- Creates and configures TUN interface
- Opens TCP socket and connects to server
- Performs secure channel handshake
- Optionally sets up routing via TUN interface
- Handles signal setup for graceful shutdown

#### `client_loop()`
- Main event loop with `select()` multiplexing
- Handles data transfer between TUN and secure channel
- Implements automatic reconnection with exponential backoff
- Manages connection state and error recovery

#### `client_stop()`
- Graceful shutdown and cleanup
- Restores original routing configuration
- Closes all file descriptors and connections

### Signal Handling & Robustness
- **SIGINT/SIGTERM handling** for graceful shutdown
- **Automatic reconnection** when connection drops
- **Exponential backoff** to prevent server overload
- **Connection timeouts** with non-blocking socket operations
- **State preservation** during reconnection attempts

## Build System

### Shared Library Support
All modules build both static (`.a`) and shared (`.so`) libraries:

```bash
# Build all modules with shared libraries
make all

# Build only shared libraries
make shared

# Build only static libraries
make static

# Build individual modules
make logger
make tun
make crypto
make secure_channel
make client
```

### Installation
```bash
# Install all modules to system
sudo make install

# Uninstall all modules
sudo make uninstall
```

### Dependencies
- **Build dependencies**: `build-essential`, `libssl-dev`
- **Runtime dependencies**: `libcrypto`, `libpthread`
- **System requirements**: Linux with TUN/TAP support

## Testing

### Comprehensive Test Suite
```bash
# Build and run all tests
make test

# Build tests only
make tests

# Run individual module tests
cd tests
./test_logger
./test_tun
./test_crypto
./test_client
./test_secure_channel
```

### Test Coverage
- **Logger tests**: Logging levels, output formats, thread safety
- **TUN tests**: Device creation, configuration, CIDR parsing
- **Crypto tests**: Key generation, encryption/decryption, replay protection
- **Client tests**: Initialization, connection, routing, reconnection
- **Secure channel tests**: Handshake, data transfer, authentication

## Usage

### Basic Client Usage
```c
#include "client.h"

int main() {
    client_ctx_t client;
    
    // Initialize client
    int ret = client_init(&client, 
                         "10.8.0.2/24",    // TUN CIDR
                         1400,             // MTU
                         "192.168.1.100",  // Server IP
                         8080,             // Server port
                         AUTH_PSK,         // Auth mode
                         "secret_key",     // Secret/token
                         1);               // Set default route
    
    if (ret < 0) {
        fprintf(stderr, "Client initialization failed\n");
        return 1;
    }
    
    // Run client loop
    ret = client_loop(&client);
    
    // Cleanup
    client_stop(&client);
    
    return ret;
}

### Basic Server Usage
```c
#include "server.h"

int main() {
    server_ctx_t server;
    
    // Initialize server
    int ret = server_init(&server, 
                         "10.8.0.1/24",    // TUN CIDR
                         1400,             // MTU
                         "0.0.0.0",        // Bind IP (all interfaces)
                         8080,             // Bind port
                         AUTH_PSK,         // Auth mode
                         "secret_key",     // Secret/token
                         "eth0",           // WAN interface
                         "10.8.0.0/24");   // VPN subnet
    
    if (ret < 0) {
        fprintf(stderr, "Server initialization failed\n");
        return 1;
    }
    
    // Run server loop
    ret = server_loop(&server);
    
    // Cleanup
    server_stop(&server);
    
    return ret;
}
```
```

### Network Configuration
```bash
# Server setup
sudo ./net_config/setup_server.sh

# Client setup
sudo ./net_config/setup_client.sh

# Teardown
sudo ./net_config/teardown_server.sh
sudo ./net_config/teardown_client.sh
```

## Configuration

### VPN Configuration (`net_config/vpn.conf`)
```bash
# TUN interface name
TUN_IF="tun0"

# VPN subnet
VPN_SUBNET="10.8.0.0/24"

# Server/client IPs
SERVER_TUN_IP="10.8.0.1"
CLIENT_TUN_IP="10.8.0.2"

# Network interfaces
WAN_IF="eth0"
LOCAL_SUBNET="192.168.1.0/24"

# Routing options
USE_VPN_AS_DEFAULT="yes"
```

## Security Features

- **End-to-end encryption** with AEAD ciphers
- **Perfect forward secrecy** via X25519 key exchange
- **Anti-replay protection** with sequence numbers
- **Multiple authentication methods** for flexibility
- **Secure random number generation** for cryptographic operations

## Performance

- **Efficient packet forwarding** with minimal overhead
- **Optimized MTU handling** for different network conditions
- **Non-blocking I/O** for responsive operation
- **Memory-efficient** with minimal allocations

## Development

### Adding New Modules
1. Create module directory with source files
2. Add `Makefile` with shared library targets
3. Create test file in `tests/` directory
4. Update main `Makefile` to include new module
5. Add module to `.gitignore` if needed

### Code Style
- C99 standard compliance
- Comprehensive error handling
- Detailed logging for debugging
- Thread-safe implementations
- Memory leak prevention

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues and questions:
- Check the test suite for usage examples
- Review the logging output for debugging
- Ensure proper system permissions for TUN devices
- Verify network configuration and routing
