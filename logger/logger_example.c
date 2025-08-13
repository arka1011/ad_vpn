#include <stdio.h>
#include <unistd.h>
#include "logger.h"
#include <pthread.h>

void* worker_thread(void* arg) {
    int thread_id = *(int*)arg;

    LOG_INFO("Worker thread %d started", thread_id);

    for (int i = 0; i < 3; i++) {
        LOG_DEBUG("Thread %d processing item %d", thread_id, i);
        sleep(1); // 1 second delay instead of usleep(100000)
        if (i == 1) {
            LOG_WARN("Thread %d encountered a warning at iteration %d", thread_id, i);
        }
    }

    LOG_INFO("Worker thread %d completed", thread_id);
    return NULL;
}

int main() {
    // Initialize logger with file output and DEBUG level
    if (logger_init("app.log", LOG_LEVEL_DEBUG) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }

    LOG_INFO("Application started");
    LOG_DEBUG("Debug logging enabled");
    LOG_TRACE("This trace message won't be shown with DEBUG level");

    // Change log level to show TRACE messages
    logger_set_level(LOG_LEVEL_TRACE);
    LOG_TRACE("Now trace messages are visible");

    // Demonstrate conditional logging
    int debug_mode = 1;
    LOG_DEBUG_IF(debug_mode, "Debug mode is enabled");
    LOG_INFO_IF(!debug_mode, "Debug mode is disabled");

    // Demonstrate assertion with logging
    int value = 42;
    LOG_ASSERT(value > 0, "Value should be positive");

    // Create multiple threads to show thread-safe logging
    pthread_t threads[3];
    int thread_ids[3] = {1, 2, 3};

    for (int i = 0; i < 3; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]) != 0) {
            LOG_ERROR("Failed to create thread %d", i);
        }
    }

    // Wait for all threads to complete
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    // Demonstrate different log levels
    LOG_INFO("This is an informational message");
    LOG_WARN("This is a warning message");
    LOG_ERROR("This is an error message");

    // Test error condition
    if (1) { // Simulate an error condition
        LOG_ERROR("Something went wrong in the application");
        LOG_FATAL("Application cannot continue, shutting down");
    }

    // Cleanup logger
    logger_cleanup();

    return 0;
}
