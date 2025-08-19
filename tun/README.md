# TUN Utilities Module

A Linux-specific module for creating and managing TUN/TAP network interfaces, providing utilities for VPN tunnel creation and network configuration.

## Features

- **TUN Interface Creation**: Create virtual network interfaces
- **Interface Configuration**: Set IP addresses, netmasks, and MTU
- **Interface Management**: Bring interfaces up/down and configure flags
- **CIDR Parsing**: Convert CIDR notation to IP and netmask
- **Cross-platform Support**: Linux-specific implementation

## Directory Structure

```
tun/
├── src/                    # Source code
│   ├── tun_utils.c        # Main TUN utilities implementation
│   └── tun_utils.h        # Public header file
├── tests/                 # Test suite
│   ├── test_tun.c         # Unit tests
│   └── Makefile          # Test build configuration
├── build/                 # Local build artifacts
│   ├── lib/              # Libraries
│   ├── bin/              # Executables
│   └── include/          # Headers
├── Makefile              # Build configuration
├── README.md             # This file
└── .gitignore           # Git ignore rules
```

## Building

### Build Everything
```bash
make all
```

### Build Libraries Only
```bash
make lib
```

### Run Tests
```bash
make -C tests test
```

### Clean Build Artifacts
```bash
make clean
```

## Usage

### Basic Usage
```c
#include "src/tun_utils.h"

int main() {
    tun_handle_t tun;
    char ifname[IFNAMSIZ];
    
    // Create TUN interface
    if (tun_create(ifname, sizeof(ifname)) < 0) {
        fprintf(stderr, "Failed to create TUN interface\n");
        return 1;
    }
    
    // Configure interface
    if (if_set_addr_netmask(ifname, "10.8.0.1", "255.255.255.0") < 0) {
        fprintf(stderr, "Failed to set IP/netmask\n");
        return 1;
    }
    
    if (if_set_mtu(ifname, 1400) < 0) {
        fprintf(stderr, "Failed to set MTU\n");
        return 1;
    }
    
    if (if_set_flags(ifname, IFF_UP | IFF_RUNNING, 1) < 0) {
        fprintf(stderr, "Failed to bring up interface\n");
        return 1;
    }
    
    printf("TUN interface %s created and configured\n", ifname);
    return 0;
}
```

### CIDR Parsing
```c
char ip_str[32], mask_str[32];
cidr_to_addr_mask("10.8.0.1/24", ip_str, sizeof(ip_str), mask_str, sizeof(mask_str));
printf("IP: %s, Netmask: %s\n", ip_str, mask_str);
```

### Data Transfer
```c
uint8_t buffer[4096];
ssize_t n = tun_read(tun.fd, buffer, sizeof(buffer));
if (n > 0) {
    // Process packet data
    tun_write(tun.fd, buffer, n);
}
```

## API Reference

### Interface Creation
- `tun_create(char *ifname, size_t ifname_len)` - Create TUN interface
- `tun_read(int fd, void *buf, size_t len)` - Read from TUN interface
- `tun_write(int fd, const void *buf, size_t len)` - Write to TUN interface

### Interface Configuration
- `if_set_addr_netmask(const char *ifname, const char *ip, const char *netmask)` - Set IP/netmask
- `if_set_mtu(const char *ifname, int mtu)` - Set MTU
- `if_set_flags(const char *ifname, unsigned int flags, int set)` - Set interface flags

### Utility Functions
- `cidr_to_addr_mask(const char *cidr, char *ip, size_t ip_len, char *netmask, size_t netmask_len)` - Parse CIDR

## Dependencies

- **Linux kernel headers**: For TUN/TAP support
- **Standard C library**: For system calls and string operations

## Requirements

- Linux kernel with TUN/TAP support
- Root privileges for interface creation
- Kernel module `tun` loaded

## Installation

### System-wide Installation
```bash
sudo make install
```

### Uninstall
```bash
sudo make uninstall
```

## Testing

Run the test suite to verify functionality:
```bash
make -C tests test
```

## Platform Support

This module is **Linux-specific** and requires:
- Linux kernel with TUN/TAP support
- `/dev/net/tun` device
- Root privileges for interface creation

## License

This module is part of the AD VPN project and follows the same license terms.
