/********Software Analysis - FY2023*************/
/*
* File Name: double_free_read.c
* Defect Classification
* ---------------------
* Defect Type: Resource management defects
* Defect Sub-type: Double free with read from socket
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#define PORT 8080
#define BUFFER_SIZE 100
#define TEST_DATA "Test data for double free vulnerability with read()"

/* Global variables */
int server_sockfd = -1;
int client_sockfd = -1;
volatile int server_running = 1;
pthread_t server_thread;

/* Server function to run in a separate thread */
void* server_function(void* arg) {
    struct sockaddr_in server_addr, client_addr;
    int opt = 1;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    printf("[SERVER] Starting server on port %d...\n", PORT);
    
    /* Create socket */
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0) {
        perror("[SERVER] Socket creation failed");
        return NULL;
    }
    
    /* Set socket options to reuse address */
    if (setsockopt(server_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("[SERVER] Setsockopt failed");
        close(server_sockfd);
        return NULL;
    }
    
    /* Configure server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    /* Bind socket to address and port */
    if (bind(server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[SERVER] Bind failed");
        close(server_sockfd);
        return NULL;
    }
    
    /* Listen for connections */
    if (listen(server_sockfd, 1) < 0) {
        perror("[SERVER] Listen failed");
        close(server_sockfd);
        return NULL;
    }
    
    printf("[SERVER] Server started. Waiting for connections...\n");
    
    /* Accept and handle client connections */
    while (server_running) {
        client_sockfd = accept(server_sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sockfd < 0) {
            perror("[SERVER] Accept failed");
            break;
        }
        
        printf("[SERVER] Client connected\n");
        
        /* Prepare data to send */
        strncpy(buffer, TEST_DATA, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
        
        /* Send data to client */
        if (write(client_sockfd, buffer, strlen(buffer)) < 0) {
            perror("[SERVER] Write failed");
        }
        
        printf("[SERVER] Data sent to client\n");
        
        /* Keep connection open for client to read */
        sleep(5);
        
        /* Close client socket */
        close(client_sockfd);
    }
    
    printf("[SERVER] Server shutting down\n");
    close(server_sockfd);
    
    return NULL;
}

/*
* Simple function to setup a socket connection to the local server
*/
int setup_connection() {
    struct sockaddr_in server_addr;
    
    /* Create a socket */
    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd < 0) {
        printf("[CLIENT] Error creating socket\n");
        return -1;
    }
    
    /* Set up the server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);
    
    /* Allow time for server to start */
    sleep(1);
    
    printf("[CLIENT] Connecting to server...\n");
    
    /* Connect to the server */
    if (connect(client_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("[CLIENT] Error connecting to server\n");
        close(client_sockfd);
        return -1;
    }
    
    printf("[CLIENT] Connected to server\n");
    return 0;
}

/*
* Types of defects: Double free
* Complexity: Basic type where pointer is "freed" twice
* Source: read() from socket
*/
void double_free_read_001() {
    char* ptr = (char*) malloc(sizeof(char) * BUFFER_SIZE);
    if (ptr == NULL) {
        printf("[TEST] Memory allocation failed\n");
        return;
    }
    
    /* Read data from socket */
    ssize_t bytes_read = read(client_sockfd, ptr, BUFFER_SIZE-1);
    if (bytes_read < 0) {
        printf("[TEST] Error reading from socket\n");
        free(ptr);
        return;
    }
    
    ptr[bytes_read] = '\0';
    printf("[TEST] Received data: %s\n", ptr);
    
    /* Free the allocated memory */
    free(ptr);
    
    /* Double free vulnerability - freeing the same memory again */
    free(ptr); /*Tool should detect this line as error*/ /*ERROR:Double free*/
}

/*
* Types of defects: Double free
* Complexity: Free in a if condition in a loop
* Source: read() from socket
*/
void double_free_read_002() {
    char* ptr = (char*) malloc(10*sizeof(char));
    if (ptr == NULL) {
        printf("[TEST] Memory allocation failed\n");
        return;
    }
    
    /* Read data from socket */
    ssize_t bytes_read = read(client_sockfd, ptr, 9);
    if (bytes_read < 0) {
        printf("[TEST] Error reading from socket\n");
        free(ptr);
        return;
    }
    
    ptr[bytes_read] = '\0';
    printf("[TEST] Received data: %s\n", ptr);
    
    int i;
    for(i = 0; i < 10; i++) {
        if(i == 9) {
            free(ptr);
        }
    }
    
    free(ptr); /*Tool should detect this line as error*/ /*ERROR:Double free*/
}

/*
* Types of defects: Double free
* Complexity: Free in a loop and then outside the loop
* Source: read() from socket
*/
void double_free_read_003() {
    char* ptr = (char*) malloc(10*sizeof(char));
    if (ptr == NULL) {
        printf("[TEST] Memory allocation failed\n");
        return;
    }
    
    /* Read data from socket */
    ssize_t bytes_read = read(client_sockfd, ptr, 9);
    if (bytes_read < 0) {
        printf("[TEST] Error reading from socket\n");
        free(ptr);
        return;
    }
    
    ptr[bytes_read] = '\0';
    printf("[TEST] Received data: %s\n", ptr);
    
    int i;
    for(i = 0; i < 10; i++) {
        if(i == 9) {
            free(ptr);
        }
    }
    
    free(ptr); /*Tool should detect this line as error*/ /*ERROR:Double free*/
}

/*
* Main function to run double free examples
*/
int main() {
    printf("\n===== Double Free Vulnerability Demo (with read from socket) =====\n\n");
    
    /* Start server thread */
    if (pthread_create(&server_thread, NULL, server_function, NULL) != 0) {
        perror("Server thread creation failed");
        return 1;
    }
    
    /* Setup client connection */
    if (setup_connection() != 0) {
        printf("[MAIN] Failed to setup connection\n");
        server_running = 0;
        pthread_join(server_thread, NULL);
        return 1;
    }
    
    /* Run all test cases - each will attempt a connection and double free */
    
    printf("\n---- Running double_free_read_001 ----\n");
    double_free_read_001();
    
    /* Try to reconnect for next test since last test might have crashed */
    printf("\n---- Running double_free_read_002 ----\n");
    if (setup_connection() == 0) {
        double_free_read_002();
        close(client_sockfd);
    }
    
    /* Try to reconnect for next test since last test might have crashed */
    printf("\n---- Running double_free_read_003 ----\n");
    if (setup_connection() == 0) {
        double_free_read_003();
        close(client_sockfd);
    }
    
    /* Clean up and exit */
    server_running = 0;
    pthread_join(server_thread, NULL);
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
}
