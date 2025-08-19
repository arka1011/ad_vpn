# Logger Module

A thread-safe, feature-rich logging library for C applications with support for multiple log levels, colored output, file logging, and comprehensive debugging information.

## Features

- **Multiple Log Levels**: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- **Thread Safety**: Safe for use in multi-threaded applications
- **Colored Output**: ANSI color codes for different log levels
- **File Logging**: Optional logging to files with rotation
- **Debug Information**: Automatic inclusion of file, line, and function names
- **Timestamp Support**: Configurable timestamp formatting
- **Thread ID Display**: Shows thread ID for debugging multi-threaded applications

## Directory Structure

```
logger/
├── src/                    # Source code
│   ├── logger.c           # Main logger implementation
│   └── logger.h           # Public header file
├── examples/              # Example applications
│   └── logger_example.c   # Example usage
├── tests/                 # Test suite
│   ├── test_logger.c      # Unit tests
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

### Build Example Only
```bash
make example
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
#include "src/logger.h"

int main() {
    // Initialize logger
    logger_init(NULL, LOG_LEVEL_INFO);
    
    // Enable features
    logger_enable_timestamp(1);
    logger_enable_thread_id(1);
    logger_enable_file_line(1);
    
    // Log messages
    LOG_INFO("Application started");
    LOG_DEBUG("Debug information: %d", 42);
    LOG_ERROR("An error occurred: %s", "connection failed");
    
    // Cleanup
    logger_cleanup();
    return 0;
}
```

### File Logging
```c
// Initialize with file output
logger_init("/var/log/myapp.log", LOG_LEVEL_DEBUG);
```

### Log Levels
```c
LOG_TRACE("Detailed trace information");
LOG_DEBUG("Debug information");
LOG_INFO("General information");
LOG_WARN("Warning message");
LOG_ERROR("Error message");
LOG_FATAL("Fatal error - application will exit");
```

## API Reference

### Initialization
- `logger_init(const char *log_file, log_level_t level)` - Initialize logger
- `logger_cleanup()` - Cleanup logger resources

### Configuration
- `logger_enable_timestamp(int enable)` - Enable/disable timestamps
- `logger_enable_thread_id(int enable)` - Enable/disable thread ID display
- `logger_enable_file_line(int enable)` - Enable/disable file/line information

### Logging Macros
- `LOG_TRACE(fmt, ...)` - Trace level logging
- `LOG_DEBUG(fmt, ...)` - Debug level logging
- `LOG_INFO(fmt, ...)` - Info level logging
- `LOG_WARN(fmt, ...)` - Warning level logging
- `LOG_ERROR(fmt, ...)` - Error level logging
- `LOG_FATAL(fmt, ...)` - Fatal level logging

## Dependencies

- **pthread**: For thread safety
- **Standard C library**: For file I/O and string operations

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

## License

This module is part of the AD VPN project and follows the same license terms.
