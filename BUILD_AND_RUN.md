# AD VPN - Build and Run Guide

## Prerequisites

- Linux system (tested on Ubuntu/Debian)
- CMake 3.16 or higher
- GCC with C11 support
- Root/sudo access (for TUN interface and route management)
- Required libraries:
  - libsodium (included in prebuilt/)
  - zlog (included in prebuilt/)
  - sqlite3 (system package)
  - inih (included in prebuilt/)

## Building

```bash
# Create build directory
mkdir -p build
cd build

# Configure
cmake ..

# Build
make -j$(nproc)

# Build with tests
cmake -DBUILD_TESTS=ON ..
make -j$(nproc)
```

The executable will be at: `build/bin/ad_vpn`

## Configuration

1. Edit `configs/ad_vpn_config.ini`:
   - Set TUN interface name and IP
   - Configure peer table
   - Add peer entries with routes

2. Edit `configs/ad_zlog_config.conf` (optional):
   - Adjust logging levels and formats

## Running

### Manual Run

```bash
# Must run as root for TUN interface and routes
sudo ./build/bin/ad_vpn

# Or with custom config paths
sudo AD_VPN_CONFIG=/path/to/config.ini ./build/bin/ad_vpn
```

### Systemd Service

```bash
# Install service
sudo ./scripts/install_systemd.sh

# Start service
sudo systemctl start ad_vpn

# Enable on boot
sudo systemctl enable ad_vpn

# Check status
sudo systemctl status ad_vpn

# View logs
sudo journalctl -u ad_vpn -f

# Stop service
sudo systemctl stop ad_vpn
```

## Testing

```bash
cd build

# Run unit tests
ctest

# Or run directly
./tests/test_ad_vpn
```

## Verification

After starting the VPN:

1. **Check TUN interface**:
   ```bash
   ip addr show ad_tun0
   ```

2. **Check routes**:
   ```bash
   ip route show dev ad_tun0
   ```

3. **Check UDP socket**:
   ```bash
   sudo netstat -ulnp | grep ad_vpn
   ```

4. **Check logs**:
   ```bash
   # If running as service
   sudo journalctl -u ad_vpn -f
   
   # If running manually, logs go to configured zlog output
   ```

## Troubleshooting

### Permission Denied

- Ensure running as root (sudo)
- Check capabilities: `getcap ./build/bin/ad_vpn`

### TUN Interface Not Created

- Check if interface name conflicts: `ip link show`
- Verify config file path is correct
- Check logs for specific error messages

### Routes Not Created

- Verify peer table has active peers
- Check if routes already exist: `ip route show`
- Ensure sufficient permissions for `ip route` command

### UDP Not Working

- Check firewall: `sudo iptables -L`
- Verify UDP port (default 6000) is not in use: `sudo netstat -ulnp`
- Check peer configuration has correct `real_addr`

### Module Initialization Failures

- Check all prebuilt libraries are present
- Verify config file syntax is correct
- Check logs for specific module errors

## Development

### Adding New Features

1. Module structure follows pattern in `modules/`
2. Add module to main `CMakeLists.txt`
3. Update `ad_vpn.c` to initialize new module
4. Add tests in `tests/`

### Debugging

- Enable debug logging in `configs/ad_zlog_config.conf`
- Use `gdb` for debugging:
  ```bash
  sudo gdb ./build/bin/ad_vpn
  ```
- Check system logs: `dmesg | tail`

## File Structure

```
ad_vpn/
├── src/
│   └── ad_vpn.c          # Main orchestrator
├── include/
│   └── ad_vpn.h          # VPN API
├── modules/              # All VPN modules
│   ├── ad_logger/
│   ├── ad_tun/
│   ├── ad_transport/
│   ├── ad_auth/
│   ├── ad_kex/
│   ├── ad_crypt/
│   └── ad_routing/       # New routing module
├── configs/              # Configuration files
├── systemd/              # Systemd service file
├── scripts/              # Installation scripts
└── tests/                # Unit tests
```

