#include "logger.h"
#include <unistd.h>
#include <sys/time.h>

// Global logger configuration
static logger_config_t g_logger = {
    .level = LOG_LEVEL_INFO,
    .enable_timestamp = 1,
    .enable_thread_id = 1,
    .enable_file_line = 1,
    .log_file = NULL,
    .file_handle = NULL
};

// Log level names
static const char* level_names[] = {
    "TRACE",
    "DEBUG", 
    "INFO ",
    "WARN ",
    "ERROR",
    "FATAL"
};

// Log level colors (for terminal output)
static const char* level_colors[] = {
    "\033[36m", // Cyan for TRACE
    "\033[32m", // Green for DEBUG
    "\033[34m", // Blue for INFO
    "\033[33m", // Yellow for WARN
    "\033[31m", // Red for ERROR
    "\033[35m"  // Magenta for FATAL
};

static const char* reset_color = "\033[0m";

int logger_init(const char* log_file, log_level_t level) {
    // Initialize mutex
    if (pthread_mutex_init(&g_logger.mutex, NULL) != 0) {
        fprintf(stderr, "Failed to initialize logger mutex\n");
        return -1;
    }
    
    // Set log level
    g_logger.level = level;
    
    // Open log file if specified
    if (log_file && strlen(log_file) > 0) {
        g_logger.log_file = log_file;
        g_logger.file_handle = fopen(log_file, "a");
        if (!g_logger.file_handle) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file);
            return -1;
        }
        // Set file to line buffered
        setvbuf(g_logger.file_handle, NULL, _IOLBF, 0);
    }
    
    LOG_INFO("Logger initialized with level: %s", level_names[level]);
    return 0;
}

void logger_set_level(log_level_t level) {
    if (level >= LOG_LEVEL_TRACE && level <= LOG_LEVEL_FATAL) {
        g_logger.level = level;
        LOG_INFO("Log level changed to: %s", level_names[level]);
    }
}

void logger_enable_timestamp(int enable) {
    g_logger.enable_timestamp = enable;
}

void logger_enable_thread_id(int enable) {
    g_logger.enable_thread_id = enable;
}

void logger_enable_file_line(int enable) {
    g_logger.enable_file_line = enable;
}

void logger_log(log_level_t level, const char* file, int line, const char* func, const char* format, ...) {
    if (level < g_logger.level) {
        return;
    }
    
    pthread_mutex_lock(&g_logger.mutex);
    
    // Get current time
    struct timeval tv;
    struct tm* tm_info;
    char time_str[26];
    
    if (g_logger.enable_timestamp) {
        gettimeofday(&tv, NULL);
        tm_info = localtime(&tv.tv_sec);
        strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    }
    
    // Get thread ID
    pthread_t thread_id = pthread_self();
    
    // Format the log message
    char log_buffer[4096];
    int offset = 0;
    
    // Add timestamp
    if (g_logger.enable_timestamp) {
        offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, 
                          "[%s.%03d] ", time_str, (int)(tv.tv_usec / 1000));
    }
    
    // Add thread ID
    if (g_logger.enable_thread_id) {
        offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, 
                          "[TID:%lu] ", (unsigned long)thread_id);
    }
    
    // Add log level
    offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, 
                      "[%s] ", level_names[level]);
    
    // Add file and line
    if (g_logger.enable_file_line) {
        const char* filename = strrchr(file, '/');
        filename = filename ? filename + 1 : file;
        offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, 
                          "[%s:%d:%s] ", filename, line, func);
    }
    
    // Add the actual message
    va_list args;
    va_start(args, format);
    offset += vsnprintf(log_buffer + offset, sizeof(log_buffer) - offset, format, args);
    va_end(args);
    
    // Add newline
    offset += snprintf(log_buffer + offset, sizeof(log_buffer) - offset, "\n");
    
    // Output to console with colors
    if (isatty(STDOUT_FILENO)) {
        printf("%s%s%s", level_colors[level], log_buffer, reset_color);
    } else {
        printf("%s", log_buffer);
    }
    
    // Output to file if available
    if (g_logger.file_handle) {
        fwrite(log_buffer, 1, offset, g_logger.file_handle);
        fflush(g_logger.file_handle);
    }
    
    pthread_mutex_unlock(&g_logger.mutex);
}

void logger_cleanup(void) {
    pthread_mutex_lock(&g_logger.mutex);
    
    if (g_logger.file_handle) {
        LOG_INFO("Logger shutting down");
        fclose(g_logger.file_handle);
        g_logger.file_handle = NULL;
    }
    
    pthread_mutex_unlock(&g_logger.mutex);
    pthread_mutex_destroy(&g_logger.mutex);
}
