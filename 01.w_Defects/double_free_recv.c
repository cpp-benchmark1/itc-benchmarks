/********Software Analysis - FY2023*************/
/*
* File Name: double_free_recv.c
* Defect Classification
* ---------------------
* Defect Type: Resource management defects
* Defect Sub-type: Double free with recv source
*
*/

/* Include necessary headers directly instead of using HeaderFile.h */
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
#include <errno.h>

#define PORT 8080
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
#define HEADER_SIZE 8
#define TEST_DATA "Complex test data for double free vulnerability demonstration. This includes header information and payload."

typedef struct {
    char header[HEADER_SIZE];
    int data_size;
    char* payload;
} message_t;

typedef struct {
    int socket_fd;
    int client_id;
} client_info_t;

volatile sig_atomic_t server_running = 1;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int client_connected = 0;

/* Signal handler to gracefully shutdown server */
void handle_sigint(int sig) {
    printf("\n[SERVER] Received signal %d. Shutting down...\n", sig);
    server_running = 0;
}

/* Function to parse received message */
message_t* parse_message(char* buffer, int size) {
    message_t* msg = (message_t*)malloc(sizeof(message_t));
    if (!msg) {
        perror("[PARSER] Memory allocation failed for message");
        return NULL;
    }

    if (size < HEADER_SIZE) {
        printf("[PARSER] Buffer too small for header\n");
        free(msg);
        return NULL;
    }

    // Extract header
    memcpy(msg->header, buffer, HEADER_SIZE);
    
    // Extract data size (assume it follows the header)
    memcpy(&msg->data_size, buffer + HEADER_SIZE, sizeof(int));
    
    // Extract payload
    int payload_size = size - HEADER_SIZE - sizeof(int);
    if (payload_size <= 0) {
        printf("[PARSER] No payload in message\n");
        msg->payload = NULL;
        return msg;
    }
    
    msg->payload = (char*)malloc(payload_size + 1);
    if (!msg->payload) {
        perror("[PARSER] Memory allocation failed for payload");
        free(msg);
        return NULL;
    }
    
    memcpy(msg->payload, buffer + HEADER_SIZE + sizeof(int), payload_size);
    msg->payload[payload_size] = '\0';
    
    return msg;
}

/* Function to free message */
void free_message(message_t* msg) {
    if (msg) {
        if (msg->payload) {
            free(msg->payload);
        }
        free(msg);
    }
}

/* Server function to handle client communication */
void* handle_client(void* arg) {
    client_info_t* client_info = (client_info_t*)arg;
    int client_socket = client_info->socket_fd;
    int client_id = client_info->client_id;
    char send_buffer[BUFFER_SIZE];
    
    printf("[SERVER] Handling client %d\n", client_id);
    
    // Prepare data to send
    memset(send_buffer, 0, BUFFER_SIZE);
    strcpy(send_buffer + HEADER_SIZE + sizeof(int), TEST_DATA);
    
    // Set header
    memcpy(send_buffer, "DATAHEAD", HEADER_SIZE);
    
    // Set data size
    int data_size = strlen(TEST_DATA);
    memcpy(send_buffer + HEADER_SIZE, &data_size, sizeof(int));
    
    // Send data to client
    int total_size = HEADER_SIZE + sizeof(int) + data_size;
    printf("[SERVER] Sending %d bytes to client %d\n", total_size, client_id);
    
    if (send(client_socket, send_buffer, total_size, 0) < 0) {
        perror("[SERVER] Send failed");
        close(client_socket);
        free(client_info);
        return NULL;
    }
    
    printf("[SERVER] Data sent to client %d\n", client_id);
    
    // Close connection
    close(client_socket);
    free(client_info);
    
    return NULL;
}

/* Server function to run in a separate thread */
void* server_function(void* arg) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    pthread_t client_threads[MAX_CLIENTS];
    int client_count = 0;
    
    // Set up signal handler
    signal(SIGINT, handle_sigint);
    
    printf("[SERVER] Starting server on port %d...\n", PORT);
    
    // Creating socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[SERVER] Socket creation failed");
        return NULL;
    }
    
    // Set socket options to reuse address
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("[SERVER] Setsockopt failed");
        close(server_fd);
        return NULL;
    }
    
    // Configure server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind socket to address and port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("[SERVER] Bind failed");
        close(server_fd);
        return NULL;
    }
    
    // Listen for connections
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("[SERVER] Listen failed");
        close(server_fd);
        return NULL;
    }
    
    printf("[SERVER] Server started. Waiting for connections...\n");
    
    // Signal that the server is ready
    pthread_mutex_lock(&mutex);
    client_connected = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);
    
    // Accept and handle client connections
    while (server_running && client_count < MAX_CLIENTS) {
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal, try again
            }
            perror("[SERVER] Accept failed");
            break;
        }
        
        printf("[SERVER] New client connected (ID: %d)\n", client_count);
        
        // Prepare client info for the handler thread
        client_info_t* client_info = (client_info_t*)malloc(sizeof(client_info_t));
        if (!client_info) {
            perror("[SERVER] Memory allocation failed");
            close(client_socket);
            continue;
        }
        
        client_info->socket_fd = client_socket;
        client_info->client_id = client_count;
        
        // Create a thread to handle the client
        if (pthread_create(&client_threads[client_count], NULL, handle_client, client_info) != 0) {
            perror("[SERVER] Thread creation failed");
            free(client_info);
            close(client_socket);
            continue;
        }
        
        client_count++;
    }
    
    // Wait for all client threads to finish
    for (int i = 0; i < client_count; i++) {
        pthread_join(client_threads[i], NULL);
    }
    
    // Clean up
    close(server_fd);
    printf("[SERVER] Server shut down.\n");
    return NULL;
}

/* Function that demonstrates double free vulnerability using complex parsing */
void* complex_double_free_client(void* arg) {
    int sockfd;
    struct sockaddr_in server_addr;
    char* recv_buffer = NULL;
    message_t* message = NULL;
    int retry_count = 0;
    const int max_retries = 5;
    
    printf("[CLIENT] Starting client...\n");
    
    // Wait for server to be ready
    pthread_mutex_lock(&mutex);
    while (!client_connected) {
        pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);
    
    // Add a small delay
    sleep(1);
    
    /* Create a socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[CLIENT] Socket creation failed");
        return NULL;
    }
    
    printf("[CLIENT] Socket created.\n");
    
    /* Set up the server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);
    
    printf("[CLIENT] Connecting to server at 127.0.0.1:%d...\n", PORT);
    
    /* Connect to the server with retry logic */
    while (retry_count < max_retries) {
        if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("[CLIENT] Connection failed, retrying");
            retry_count++;
            sleep(1);
        } else {
            break;
        }
    }
    
    if (retry_count == max_retries) {
        printf("[CLIENT] Failed to connect after %d attempts\n", max_retries);
        close(sockfd);
        return NULL;
    }
    
    printf("[CLIENT] Connected to server.\n");
    
    /* Allocate memory for the receive buffer */
    recv_buffer = (char*)malloc(BUFFER_SIZE);
    if (recv_buffer == NULL) {
        perror("[CLIENT] Memory allocation failed for buffer");
        close(sockfd);
        return NULL;
    }
    
    printf("[CLIENT] Memory allocated for buffer.\n");
    
    /* Receive data from the server into the allocated buffer - SOURCE IS RECV */
    printf("[CLIENT] Receiving data from server...\n");
    int bytes_received = recv(sockfd, recv_buffer, BUFFER_SIZE-1, 0);
    if (bytes_received < 0) {
        perror("[CLIENT] Receive failed");
        free(recv_buffer);
        close(sockfd);
        return NULL;
    }
    
    /* Null terminate the buffer */
    recv_buffer[bytes_received] = '\0';
    
    printf("[CLIENT] Received %d bytes from server\n", bytes_received);
    
    /* Parse the received message */
    message = parse_message(recv_buffer, bytes_received);
    if (!message) {
        printf("[CLIENT] Failed to parse message\n");
        free(recv_buffer);
        close(sockfd);
        return NULL;
    }
    
    /* Process the received message */
    printf("[CLIENT] Parsed message header: %.8s\n", message->header);
    if (message->payload) {
        printf("[CLIENT] Parsed message payload: %s\n", message->payload);
    }
    
    /* Free the allocated memory */
    printf("[CLIENT] Freeing message...\n");
    free_message(message);
    
    /* Double free vulnerability - freeing the already freed message again */
    printf("[CLIENT] !!! VULNERABILITY !!! - Double free triggered. Freeing message again...\n");
    free_message(message); /* This is the vulnerability: double free */
    
    printf("[CLIENT] Double free completed!\n");
    
    /* Free receive buffer */
    free(recv_buffer);
    
    /* Close the socket */
    close(sockfd);
    printf("[CLIENT] Client finished.\n");
    
    return NULL;
}

/* Main function that creates server thread and runs client */
int main() {
    pthread_t server_thread;
    pthread_t client_thread;
    int result;
    
    printf("===== Double Free Vulnerability Demo (with recv as source) =====\n\n");
    
    // Initialize synchronization primitives
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&cond, NULL);
    
    // Create thread for server
    result = pthread_create(&server_thread, NULL, server_function, NULL);
    if (result != 0) {
        perror("Server thread creation failed");
        return 1;
    }
    
    // Create thread for client
    result = pthread_create(&client_thread, NULL, complex_double_free_client, NULL);
    if (result != 0) {
        perror("Client thread creation failed");
        return 1;
    }
    
    // Wait for client and server threads to complete
    pthread_join(client_thread, NULL);
    pthread_join(server_thread, NULL);
    
    // Clean up
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&cond);
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 