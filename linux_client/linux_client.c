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
#define SERVER_IP "127.0.0.1"

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char message[] = "Hello from VPN Client!";
    
    // Initialize logger
    if (logger_init("client.log", LOG_LEVEL_DEBUG) != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    LOG_INFO("VPN Client starting");
    LOG_DEBUG("Attempting to connect to server %s:%d", SERVER_IP, PORT);
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOG_ERROR("Socket creation failed");
        logger_cleanup();
        return 1;
    }
    
    LOG_DEBUG("Socket created successfully");
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        LOG_ERROR("Invalid address / Address not supported");
        close(sock);
        logger_cleanup();
        return 1;
    }
    
    LOG_DEBUG("IP address converted successfully");
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        LOG_ERROR("Connection failed");
        close(sock);
        logger_cleanup();
        return 1;
    }
    
    LOG_INFO("Connected to server successfully");
    
    // Send message to server
    LOG_DEBUG("Sending message: %s", message);
    if (send(sock, message, strlen(message), 0) < 0) {
        LOG_ERROR("Send failed");
        close(sock);
        logger_cleanup();
        return 1;
    }
    
    LOG_DEBUG("Message sent successfully");
    
    // Receive response from server
    int valread = read(sock, buffer, BUFFER_SIZE);
    if (valread > 0) {
        LOG_INFO("Received response from server: %s", buffer);
        LOG_DEBUG("Response length: %d bytes", valread);
    } else if (valread == 0) {
        LOG_WARN("Server closed connection");
    } else {
        LOG_ERROR("Failed to read response from server");
    }
    
    close(sock);
    LOG_INFO("Client shutting down");
    logger_cleanup();
    
    return 0;
}
