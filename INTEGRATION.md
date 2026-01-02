# AD VPN Integration Guide

This document describes the complete integration of all modules for the AD VPN system.

## Architecture Overview

The AD VPN system consists of the following modules:

1. **ad_logger** - Logging infrastructure using zlog
2. **ad_tun** - TUN interface management
3. **ad_transport** - UDP transport and peer table management
4. **ad_auth** - Peer authentication using digital signatures
5. **ad_kex** - Key exchange for session key derivation
6. **ad_crypt** - Encryption/decryption using libsodium (ChaCha20-Poly1305)
7. **ad_routing** - System route management

## Module Integration

### Main Orchestrator (ad_vpn.c)

The `ad_vpn.c` file serves as the main orchestrator that:

1. **Initializes all modules** in the correct order:
   - Logger (first, for logging)
   - TUN interface
   - Routing module
   - Transport module (which depends on TUN)

2. **Manages the event loop**:
   - Uses epoll to monitor TUN and UDP file descriptors
   - Handles TUN events (packets from local network)
   - Handles UDP events (packets from remote peers)

3. **Manages routes**:
   - Syncs routes from peer table on startup
   - Removes routes on shutdown

4. **Handles lifecycle**:
   - Proper initialization sequence
   - Graceful shutdown on SIGINT/SIGTERM
   - Resource cleanup

### Module Dependencies

```
ad_vpn (orchestrator)
├── ad_logger (logging)
├── ad_tun (TUN interface)
│   └── ad_logger
├── ad_routing (route management)
│   ├── ad_transport (for peer table access)
│   └── ad_logger
├── ad_transport (UDP transport)
│   ├── ad_tun
│   ├── ad_logger
│   └── (ad_crypt - for encryption, currently stubbed)
├── ad_auth (authentication)
│   └── ad_logger
├── ad_kex (key exchange)
│   └── ad_logger
└── ad_crypt (encryption)
    └── ad_logger
```

## Current Implementation Status

### ✅ Fully Integrated

- **Logger**: Initialized first, used by all modules
- **TUN Interface**: Created and managed by transport module
- **Transport**: Handles UDP and TUN I/O, peer table management
- **Routing**: Creates system routes from peer table configuration
- **Event Loop**: Epoll-based event handling for TUN and UDP

### ⚠️ Partially Integrated

- **Encryption/Decryption**: Currently stubbed in transport layer
  - `ad_transport_encrypt_message()` and `ad_transport_decrypt_message()` 
    are placeholders that just copy data
  - Real encryption can be integrated by:
    1. Creating crypto contexts per peer session
    2. Using `ad_crypt_ctx_create()` with session keys from `ad_kex`
    3. Calling `ad_crypt_encrypt()`/`ad_crypt_decrypt()` in transport handlers

- **Authentication**: Module exists but not yet integrated into handshake
  - Can be used to verify peer identity during connection setup
  - Should be called before key exchange

- **Key Exchange**: Module exists but not yet integrated
  - Should be called during peer handshake to derive session keys
  - Session keys should be used to initialize crypto contexts

## Configuration

The VPN is configured via `configs/ad_vpn_config.ini`:

```ini
[ad_tun]
ifname = ad_tun0
ipv4 = 10.10.0.1/24
mtu = 1500
persist = 1

[peer_table]
capacity = 256
persist_interval = 10
db_path = ./peer_table.db

[peer:peer-id]
real_addr = 203.0.113.10:5000
routes = 20.8.0.0/24, 10.8.10.0/28
active = 1
```

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Running

### Manual Execution

```bash
# Set configuration paths (optional)
export AD_VPN_CONFIG=configs/ad_vpn_config.ini
export AD_VPN_LOGGER_CONFIG=configs/ad_zlog_config.conf

# Run VPN
sudo ./bin/ad_vpn
```

### As Systemd Service

```bash
# Install service
sudo ./scripts/install_systemd.sh

# Start service
sudo systemctl start ad_vpn

# Check status
sudo systemctl status ad_vpn

# View logs
sudo journalctl -u ad_vpn -f
```

## Testing

```bash
cd build
cmake -DBUILD_TESTS=ON ..
make
ctest
```

## Packet Flow

### Outgoing (TUN → UDP)

1. Packet arrives on TUN interface
2. `ad_transport_handle_tun_event()` is called
3. Extract destination IP from packet header
4. Lookup peer using `ad_transport_peer_table_lookup()`
5. (Future) Encrypt packet using peer's crypto context
6. Send encrypted packet via UDP to peer's `real_addr`

### Incoming (UDP → TUN)

1. Packet arrives on UDP socket
2. `ad_transport_handle_udp_event()` is called
3. (Future) Decrypt packet using peer's crypto context
4. Write decrypted packet to TUN interface
5. Packet is injected into local network stack

## Route Management

The `ad_routing` module:

1. Reads routes from peer table configuration
2. Creates system routes using `ip route add` commands
3. Routes are created for all active peers
4. Routes are removed on shutdown

Example routes created:
```bash
ip route add 20.8.0.0/24 dev ad_tun0
ip route add 10.8.10.0/28 dev ad_tun0
```

## Future Enhancements

1. **Full Encryption Integration**:
   - Implement per-peer crypto contexts
   - Integrate key exchange during handshake
   - Use authenticated encryption for all packets

2. **Authentication Integration**:
   - Verify peer identity during connection
   - Use digital signatures for handshake messages

3. **Handshake Protocol**:
   - Implement full handshake with auth + key exchange
   - Handle session establishment and teardown

4. **Route Updates**:
   - Dynamic route updates when peers are added/removed
   - Route health monitoring

## Troubleshooting

### Routes not created

- Check if running as root (required for `ip route` commands)
- Verify peer table has active peers with routes
- Check logs: `journalctl -u ad_vpn`

### TUN interface not created

- Check if running as root (required for TUN device creation)
- Verify configuration file path is correct
- Check interface name doesn't conflict with existing interfaces

### UDP not receiving packets

- Check firewall rules (UDP port 6000 by default)
- Verify peer configuration has correct `real_addr`
- Check network connectivity to peer addresses

