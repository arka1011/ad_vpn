#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Log levels
typedef enum {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} log_level_t;

// Log configuration
typedef struct {
    log_level_t level;
    int enable_timestamp;
    int enable_thread_id;
    int enable_file_line;
    const char* log_file;
    FILE* file_handle;
    pthread_mutex_t mutex;
} logger_config_t;

// Initialize logger
int logger_init(const char* log_file, log_level_t level);

// Set log level
void logger_set_level(log_level_t level);

// Enable/disable features
void logger_enable_timestamp(int enable);
void logger_enable_thread_id(int enable);
void logger_enable_file_line(int enable);

// Logging functions
void logger_log(log_level_t level, const char* file, int line, const char* func, const char* format, ...);

// Cleanup
void logger_cleanup(void);

// Convenience macros
#define LOG_TRACE(...) logger_log(LOG_LEVEL_TRACE, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_DEBUG(...) logger_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_INFO(...)  logger_log(LOG_LEVEL_INFO,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_WARN(...)  logger_log(LOG_LEVEL_WARN,  __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_ERROR(...) logger_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define LOG_FATAL(...) logger_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__)

// Conditional logging macros
#define LOG_IF(condition, level, ...) do { \
    if (condition) { \
        logger_log(level, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } \
} while(0)

#define LOG_TRACE_IF(condition, ...) LOG_IF(condition, LOG_LEVEL_TRACE, __VA_ARGS__)
#define LOG_DEBUG_IF(condition, ...) LOG_IF(condition, LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO_IF(condition, ...)  LOG_IF(condition, LOG_LEVEL_INFO,  __VA_ARGS__)
#define LOG_WARN_IF(condition, ...)  LOG_IF(condition, LOG_LEVEL_WARN,  __VA_ARGS__)
#define LOG_ERROR_IF(condition, ...) LOG_IF(condition, LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_FATAL_IF(condition, ...) LOG_IF(condition, LOG_LEVEL_FATAL, __VA_ARGS__)

// Assert with logging
#define LOG_ASSERT(condition, ...) do { \
    if (!(condition)) { \
        LOG_FATAL("Assertion failed: %s", #condition); \
        LOG_FATAL(__VA_ARGS__); \
        abort(); \
    } \
} while(0)

#ifdef __cplusplus
}
#endif

#endif // LOGGER_H
