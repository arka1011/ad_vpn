# Linux VPN Client

This directory contains the Linux VPN client implementation with integrated logging capabilities.

## Features

- **TCP Socket Client**: Connects to VPN server endpoints
- **Configurable**: Easy to modify server IP, port, and connection parameters
- **Integrated Logging**: Comprehensive logging with different levels
- **Error Handling**: Robust error handling and connection recovery
- **Interactive Mode**: Can send messages and receive server responses

## Build

### Prerequisites

- GCC compiler
- pthread library
- Logger library (in `../logger/`)

### Build Commands

```bash
# Build client
make

# Build with debug symbols
make debug

# Build optimized release version
make release

# Clean build files
make clean
```

## Usage

### Run Client

```bash
# Run the client (will prompt for server details)
make run

# Or run directly
./linux_client

# Test connection to local server
make test
```

### Configuration

The client can be configured by modifying these constants in `linux_client.c`:

```c
#define DEFAULT_SERVER_IP "127.0.0.1"  // Default server IP
#define DEFAULT_PORT 8080               // Default server port
#define BUFFER_SIZE 1024                // Buffer size for messages
```

### Command Line Arguments

```bash
# Connect to specific server
./linux_client <server_ip> <port>

# Examples:
./linux_client 192.168.1.100 8080
./linux_client localhost 9000
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Input    │    │   Network I/O   │    │   Server        │
│                 │    │                 │    │                 │
│  - Commands     │───▶│  - Socket      │───▶│  - Accept      │
│  - Messages     │    │  - Connect      │    │  - Process      │
│  - Quit         │    │  - Send/Recv    │    │  - Respond      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Logger        │    │   Error Handler │    │   Connection    │
│                 │    │                 │    │   Manager       │
│  - Log levels   │    │  - Network      │    │  - Timeout      │
│  - Timestamps   │    │  - Socket       │    │  - Reconnect    │
│  - Thread ID    │    │  - System       │    │  - Cleanup      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Development

### Adding Features

1. **Authentication**: Implement client authentication with server
2. **Encryption**: Add data encryption/decryption
3. **Protocol**: Implement custom VPN protocol
4. **Configuration**: Add configuration file support
5. **GUI**: Add graphical user interface

### Testing

```bash
# Test with local server
make test

# Test with remote server
./linux_client 192.168.129.131 8080

# Test with netcat server
nc -l 8080 &
./linux_client 127.0.0.1 8080
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Verify server is running and port is correct
2. **Timeout**: Check network connectivity and firewall settings
3. **Permission Denied**: Check if port requires elevated privileges
4. **Address Not Found**: Verify server IP address is correct

### Debug Mode

Enable debug logging:
```bash
make debug
```

The client will output detailed debug information including:
- Connection attempts
- Socket operations
- Data transfer details
- Error conditions

## Dependencies

- **Logger Library**: `../logger/logger.h` and `../logger/logger.c`
- **System Libraries**: pthread, socket, netinet, arpa/inet

## License

This client implementation is part of the AD VPN project.
