# Network Configuration Module

This module contains network configuration files and scripts for setting up VPN client and server networking on Linux systems.

## Directory Structure

```
net_config/
├── client.conf          # Client network configuration
├── server.conf          # Server network configuration
├── vpn.conf             # Legacy general VPN configuration
├── setup_client.sh      # Client network setup script
├── setup_server.sh      # Server network setup script
├── teardown_client.sh   # Client network teardown script
├── teardown_server.sh   # Server network teardown script
├── README.md            # This file
└── .gitignore          # Git ignore rules
```

## Configuration Files

### client.conf
Comprehensive client-side network configuration including:
- TUN interface settings
- Server connection parameters
- Routing configuration
- DNS settings
- Firewall rules
- Performance tuning

### server.conf
Comprehensive server-side network configuration including:
- TUN interface settings
- Server binding parameters
- NAT and routing configuration
- Client management settings
- Firewall rules
- Security settings

### vpn.conf (Legacy)
General VPN configuration file for backward compatibility.

## Setup Scripts

### setup_client.sh
Sets up client-side networking:
- Creates TUN interface
- Configures IP address and routing
- Sets up firewall rules
- Configures DNS

### setup_server.sh
Sets up server-side networking:
- Creates TUN interface
- Enables IP forwarding
- Configures NAT rules
- Sets up firewall rules

### teardown_client.sh
Removes client-side networking configuration:
- Removes routes
- Restores original DNS
- Cleans up firewall rules

### teardown_server.sh
Removes server-side networking configuration:
- Removes NAT rules
- Disables IP forwarding
- Cleans up firewall rules

## Usage

### Server Setup
```bash
# Setup server networking
sudo ./setup_server.sh

# Start VPN server
./build/bin/vpn_server -c config/server.conf

# Teardown server networking
sudo ./teardown_server.sh
```

### Client Setup
```bash
# Setup client networking
sudo ./setup_client.sh

# Start VPN client
./build/bin/vpn_client -c config/client.conf

# Teardown client networking
sudo ./teardown_client.sh
```

## Configuration Parameters

### Client Configuration
- `TUN_IF`: TUN interface name
- `CLIENT_TUN_IP`: Client TUN IP address
- `SERVER_IP`: Server IP address
- `USE_VPN_AS_DEFAULT`: Set VPN as default route
- `VPN_ROUTES`: Routes to add via VPN
- `VPN_DNS_SERVERS`: DNS servers for VPN

### Server Configuration
- `TUN_IF`: TUN interface name
- `SERVER_TUN_IP`: Server TUN IP address
- `BIND_IP`: Server bind IP address
- `WAN_IF`: WAN interface for NAT
- `ENABLE_NAT`: Enable NAT masquerade
- `MAX_CLIENTS`: Maximum concurrent clients

## Requirements

- Linux kernel with TUN/TAP support
- iptables for firewall rules
- iproute2 for network configuration
- Root privileges for network setup

## Security Considerations

- All scripts require root privileges
- Firewall rules are configured for security
- NAT rules isolate client traffic
- Rate limiting prevents abuse

## Troubleshooting

### Common Issues
1. **Permission denied**: Run scripts with sudo
2. **TUN device not found**: Ensure TUN module is loaded
3. **Route conflicts**: Check existing routes before setup
4. **Firewall blocks**: Ensure iptables rules are correct

### Debugging
- Check system logs: `dmesg | grep tun`
- Verify routes: `ip route show`
- Check firewall rules: `iptables -L -n -v`
- Test connectivity: `ping -I tun0 8.8.8.8`

## License

This module is part of the AD VPN project and follows the same license terms.
