# AD VPN Project with Comprehensive Logging

This project includes a robust logging library for C/C++ applications with support for multiple log levels, file output, thread safety, and colored terminal output.

## Features

- **Multiple Log Levels**: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- **Thread-Safe**: Uses pthread mutex for concurrent logging
- **File Output**: Can log to both console and file simultaneously
- **Colored Output**: Terminal output with color-coded log levels
- **Timestamp Support**: Microsecond precision timestamps
- **Thread ID**: Shows which thread generated each log message
- **File/Line/Function**: Source code location information
- **Conditional Logging**: Log only when conditions are met
- **Assertion Support**: LOG_ASSERT macro with logging

## Files

- `logger.h` - Header file with logging interface
- `logger.c` - Implementation of logging functions
- `logger_example.c` - Example program demonstrating all features
- `linux_server.c` - VPN server with logging integration
- `linux_client.c` - VPN client with logging integration
- `Makefile` - Build configuration

## Quick Start

### 1. Compile the logger

```bash
make clean
make
```

### 2. Run the example

```bash
make run
```

### 3. Test the VPN server/client

```bash
# Terminal 1: Start server
./linux_server

# Terminal 2: Start client
./linux_client
```

## Usage

### Basic Logging

```c
#include "logger.h"

int main() {
    // Initialize logger
    logger_init("app.log", LOG_LEVEL_INFO);
    
    // Log messages
    LOG_INFO("Application started");
    LOG_DEBUG("Debug information");
    LOG_WARN("Warning message");
    LOG_ERROR("Error occurred");
    
    // Cleanup
    logger_cleanup();
    return 0;
}
```

### Log Levels

```c
// Set minimum log level
logger_set_level(LOG_LEVEL_DEBUG);

// Only messages at DEBUG level and above will be shown
LOG_TRACE("This won't be shown");  // Below DEBUG level
LOG_DEBUG("This will be shown");   // At DEBUG level
LOG_INFO("This will be shown");    // Above DEBUG level
```

### Conditional Logging

```c
int debug_mode = 1;
LOG_DEBUG_IF(debug_mode, "Debug mode is enabled");
LOG_INFO_IF(!debug_mode, "Debug mode is disabled");

// Custom conditions
LOG_ERROR_IF(errno != 0, "System error: %s", strerror(errno));
```

### Assertions with Logging

```c
int value = 42;
LOG_ASSERT(value > 0, "Value must be positive");
LOG_ASSERT(ptr != NULL, "Pointer cannot be NULL");
```

### Configuration Options

```c
// Enable/disable features
logger_enable_timestamp(0);    // Disable timestamps
logger_enable_thread_id(0);    // Disable thread IDs
logger_enable_file_line(0);    // Disable file/line info

// Re-enable features
logger_enable_timestamp(1);
logger_enable_thread_id(1);
logger_enable_file_line(1);
```

## Log Output Format

The logger produces output in this format:

```
[2024-01-15 14:30:25.123] [TID:12345] [INFO ] [main.c:42:main] Application started
[2024-01-15 14:30:25.124] [TID:12345] [DEBUG] [main.c:43:main] Debug information
[2024-01-15 14:30:25.125] [TID:12345] [WARN ] [main.c:44:main] Warning message
```

Components:
- `[timestamp]` - Date and time with milliseconds
- `[TID:thread_id]` - Thread identifier
- `[LEVEL]` - Log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
- `[file:line:function]` - Source code location
- `message` - The actual log message

## Building Your Own Project

### 1. Include the logger files

```bash
cp logger.h logger.c /path/to/your/project/
```

### 2. Add to your Makefile

```makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LDFLAGS = -lpthread

your_program: your_program.c logger.c
	$(CC) $(CFLAGS) -o your_program your_program.c logger.c $(LDFLAGS)
```

### 3. Use in your code

```c
#include "logger.h"

int main() {
    logger_init("myapp.log", LOG_LEVEL_INFO);
    
    LOG_INFO("Your application is running");
    
    // Your code here...
    
    logger_cleanup();
    return 0;
}
```

## Thread Safety

The logger is fully thread-safe and can be used in multi-threaded applications:

```c
#include <pthread.h>

void* worker_thread(void* arg) {
    int id = *(int*)arg;
    LOG_INFO("Worker thread %d started", id);
    
    // Thread-safe logging
    LOG_DEBUG("Thread %d processing", id);
    
    LOG_INFO("Worker thread %d completed", id);
    return NULL;
}
```

## Error Handling

The logger provides comprehensive error handling:

```c
if (logger_init("app.log", LOG_LEVEL_INFO) != 0) {
    fprintf(stderr, "Failed to initialize logger\n");
    return 1;
}

// Check for specific errors
if (some_operation_failed) {
    LOG_ERROR("Operation failed: %s", error_message);
    // Handle error...
}
```

## Performance Considerations

- **Log Level Filtering**: Messages below the current level are filtered out early
- **Efficient Formatting**: Uses stack-based buffers to minimize memory allocation
- **Line Buffering**: File output is line-buffered for better performance
- **Conditional Compilation**: Consider using `#ifdef DEBUG` for debug logs in production

## Troubleshooting

### Common Issues

1. **Compilation Error**: Make sure you have `-lpthread` in your linker flags
2. **Permission Denied**: Check if you have write permissions for the log file directory
3. **No Output**: Verify the log level is set appropriately
4. **File Not Created**: Ensure the directory exists and is writable

### Debug Mode

To enable debug logging:

```c
logger_set_level(LOG_LEVEL_DEBUG);
logger_enable_file_line(1);
logger_enable_thread_id(1);
```

## License

This logging library is provided as-is for educational and development purposes.

## Contributing

Feel free to extend the logger with additional features:
- Log rotation
- Network logging (syslog, remote servers)
- Structured logging (JSON, XML)
- Performance metrics
- Log compression