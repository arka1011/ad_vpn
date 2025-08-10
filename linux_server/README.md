# Linux VPN Server

This directory contains the Linux VPN server implementation with integrated logging capabilities.

## Features

- **TCP Socket Server**: Listens for incoming VPN connections
- **Multi-threaded**: Handles multiple client connections simultaneously
- **Integrated Logging**: Comprehensive logging with different levels
- **Error Handling**: Robust error handling and recovery
- **Configurable**: Easy to modify port, buffer sizes, and other parameters

## Build

### Prerequisites

- GCC compiler
- pthread library
- Logger library (in `../logger/`)

### Build Commands

```bash
# Build server
make

# Build with debug symbols
make debug

# Build optimized release version
make release

# Clean build files
make clean
```

## Usage

### Run Server

```bash
# Run the server
make run

# Or run directly
./linux_server
```

### Configuration

The server can be configured by modifying these constants in `linux_server.c`:

```c
#define PORT 8080              // Server port
#define BUFFER_SIZE 1024       // Buffer size for messages
#define MAX_CONNECTIONS 3      // Maximum pending connections
```

### Log Files

The server creates log files:
- `server.log` - Main server log file
- Console output with colored log levels

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client 1      │    │   Client 2      │    │   Client N      │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼─────────────┐
                    │      Main Server          │
                    │  ┌─────────────────────┐  │
                    │  │   Accept Thread     │  │
                    │  └─────────────────────┘  │
                    │  ┌─────────────────────┐  │
                    │  │   Client Handler    │  │
                    │  │   (per client)     │  │
                    │  └─────────────────────┘  │
                    └───────────────────────────┘
```

## Development

### Adding Features

1. **New Protocol Support**: Add new message types and handlers
2. **Authentication**: Implement client authentication
3. **Encryption**: Add data encryption/decryption
4. **Configuration**: Add configuration file support
5. **Monitoring**: Add performance metrics and monitoring

### Testing

```bash
# Test with netcat
nc localhost 8080

# Test with custom client
../linux_client/linux_client
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**: Change PORT constant or kill existing process
2. **Permission Denied**: Check if port requires root privileges
3. **Connection Refused**: Verify server is running and listening

### Debug Mode

Enable debug logging:
```bash
make debug
```

The server will output detailed debug information including:
- Socket creation steps
- Connection details
- Data transfer information
- Error conditions

## Dependencies

- **Logger Library**: `../logger/logger.h` and `../logger/logger.c`
- **System Libraries**: pthread, socket, netinet, arpa/inet

## License

This server implementation is part of the AD VPN project.
