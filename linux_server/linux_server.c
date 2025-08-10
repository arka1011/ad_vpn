#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../logger/logger.h"

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    
    // Initialize logger
    if (logger_init("server.log", LOG_LEVEL_INFO) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    LOG_INFO("VPN Server starting on port %d", PORT);
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        LOG_ERROR("Socket creation failed");
        logger_cleanup();
        return 1;
    }
    
    LOG_DEBUG("Socket created successfully");
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        LOG_ERROR("Setsockopt failed");
        close(server_fd);
        logger_cleanup();
        return 1;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        LOG_ERROR("Bind failed");
        close(server_fd);
        logger_cleanup();
        return 1;
    }
    
    LOG_INFO("Server bound to port %d", PORT);
    
    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        LOG_ERROR("Listen failed");
        close(server_fd);
        logger_cleanup();
        return 1;
    }
    
    LOG_INFO("Server listening for connections...");
    
    // Accept connections
    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))) {
        if (new_socket < 0) {
            LOG_ERROR("Accept failed");
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
        LOG_INFO("New connection from %s:%d", client_ip, ntohs(address.sin_port));
        
        // Handle client communication
        int valread = read(new_socket, buffer, BUFFER_SIZE);
        if (valread > 0) {
            LOG_DEBUG("Received %d bytes from client", valread);
            LOG_DEBUG("Message: %s", buffer);
            
            // Echo back to client
            send(new_socket, buffer, strlen(buffer), 0);
            LOG_DEBUG("Echoed message back to client");
        }
        
        close(new_socket);
        LOG_INFO("Connection closed");
    }
    
    close(server_fd);
    LOG_INFO("Server shutting down");
    logger_cleanup();
    
    return 0;
}
