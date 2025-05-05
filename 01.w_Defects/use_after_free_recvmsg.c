/********Software Analysis - FY2023*************/
/*
* File Name: use_after_free_recvmsg.c
* Defect Classification
* ---------------------
* Defect Type: Resource management defects
* Defect Sub-type: Use after free with recvmsg from socket
*
* Description: This example demonstrates a use-after-free vulnerability 
* where a message structure received from recvmsg() is freed and then used.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8082
#define BUFFER_SIZE 1024

/* Function to process received message - contains the vulnerability */
void process_message(struct msghdr* msg) {
    if (!msg) return;
    
    printf("[PROCESS] Processing received message\n");
    printf("[PROCESS] Message at address %p with %ld vectors\n", 
           (void*)msg, msg->msg_iovlen);
    
    /* First, let's look at the message content */
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        printf("[PROCESS] Vector %zu: base=%p len=%zu\n", 
               i, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
    }
    
    /* 
     * VULNERABILITY: Free the message vectors but keep using the structure
     * This creates a use-after-free condition
     */
    printf("[PROCESS] Freeing message vectors (VULNERABILITY!)\n");
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_base) {
            printf("[PROCESS] Freeing vector %zu at %p\n", 
                   i, msg->msg_iov[i].iov_base);
            free(msg->msg_iov[i].iov_base);
            /* We don't set iov_base to NULL to make the vulnerability more obvious */
        }
    }
    
    /* 
     * USE-AFTER-FREE: Try to use the freed message vectors
     * This should cause a crash or undefined behavior
     */
    printf("[PROCESS] Attempting to use freed message vectors\n");
    
    for (size_t i = 0; i < msg->msg_iovlen; i++) {
        if (msg->msg_iov[i].iov_base && msg->msg_iov[i].iov_len > 0) {
            /* Try to read and modify the freed memory */
            char* data = (char*)msg->msg_iov[i].iov_base;
            printf("[PROCESS] Vector %zu first byte: %d\n", i, (int)data[0]);
            
            /* Write to the freed memory */
            data[0] = 'X';
            if (msg->msg_iov[i].iov_len > 1) {
                data[1] = 'Y';
            }
            
            /* Try to print the modified data */
            printf("[PROCESS] Modified vector %zu: %.10s\n", i, data);
        }
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    /* Configure server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    /* Bind socket */
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }
    
    /* Listen for connections */
    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }
    
    printf("Server listening on port %d...\n", PORT);
    
    /* Accept client connection */
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("Accept failed");
        close(server_fd);
        return 1;
    }
    
    printf("Client connected: %s\n", inet_ntoa(client_addr.sin_addr));
    
    /* Set up message structure */
    struct msghdr msg;
    struct iovec iov[2];
    char* buffer1 = malloc(BUFFER_SIZE);
    char* buffer2 = malloc(BUFFER_SIZE);
    
    if (!buffer1 || !buffer2) {
        perror("Memory allocation failed");
        close(client_fd);
        close(server_fd);
        free(buffer1);
        free(buffer2);
        return 1;
    }
    
    /* Initialize message structure */
    memset(&msg, 0, sizeof(msg));
    memset(buffer1, 0, BUFFER_SIZE);
    memset(buffer2, 0, BUFFER_SIZE);
    
    /* Set up I/O vectors */
    iov[0].iov_base = buffer1;
    iov[0].iov_len = BUFFER_SIZE;
    iov[1].iov_base = buffer2;
    iov[1].iov_len = BUFFER_SIZE;
    
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    
    /* Receive data */
    ssize_t received = recvmsg(client_fd, &msg, 0);
    if (received > 0) {
        printf("Received %zd bytes\n", received);
        /* Process the message - this will demonstrate the use-after-free */
        process_message(&msg);
    }
    
    /* Try to use the message again after it's been freed */
    printf("\nAttempting to use message again...\n");
    process_message(&msg);
    
    /* Cleanup */
    close(client_fd);
    close(server_fd);
    
    return 0;
} 