/********Software Analysis - FY2023*************/
/*
* File Name: use_after_free_recvfrom.c
* Defect Classification
* ---------------------
* Defect Type: Resource management defects
* Defect Sub-type: Use after free with recvfrom from socket
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

#define PORT 8081
#define BUFFER_SIZE 512
#define MAX_PACKET_SIZE 1024
#define TEST_PACKETS 3

typedef struct {
    int id;
    char message[256];
} packet_data_t;

/* Global variables */
volatile int server_running = 1;
pthread_t server_thread;
int server_socket = -1;
int client_socket = -1;

/* Server thread function to send test packets */
void* udp_server_thread(void* arg) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    packet_data_t packet;
    char buffer[MAX_PACKET_SIZE];
    int bytes_sent;
    
    printf("[SERVER] Starting UDP server on port %d\n", PORT);
    
    /* Create UDP socket */
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_socket < 0) {
        perror("[SERVER] Socket creation failed");
        return NULL;
    }
    
    /* Configure server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    /* Bind socket to address and port */
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[SERVER] Bind failed");
        close(server_socket);
        return NULL;
    }
    
    printf("[SERVER] UDP server started. Waiting for client...\n");
    
    /* Server loop to send test packets */
    while (server_running) {
        /* Wait for client to send initial packet to get address */
        memset(buffer, 0, MAX_PACKET_SIZE);
        int recv_len = recvfrom(server_socket, buffer, MAX_PACKET_SIZE, 0, 
                              (struct sockaddr*)&client_addr, &addr_len);
        
        if (recv_len > 0) {
            printf("[SERVER] Received packet from client, sending test data\n");
            
            /* Send multiple test packets */
            for (int i = 0; i < TEST_PACKETS && server_running; i++) {
                /* Prepare packet data */
                packet.id = i + 1;
                snprintf(packet.message, sizeof(packet.message), 
                        "Use-after-free test packet #%d with some random data: %d%d%d", 
                        i + 1, rand() % 100, rand() % 100, rand() % 100);
                
                /* Copy to buffer */
                memcpy(buffer, &packet, sizeof(packet_data_t));
                
                /* Send packet */
                bytes_sent = sendto(server_socket, buffer, sizeof(packet_data_t), 0,
                                  (struct sockaddr*)&client_addr, addr_len);
                                  
                if (bytes_sent < 0) {
                    perror("[SERVER] Send failed");
                    break;
                }
                
                printf("[SERVER] Sent packet %d to client\n", i + 1);
                sleep(1); /* Delay between packets */
            }
        }
    }
    
    /* Clean up */
    if (server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }
    
    printf("[SERVER] UDP server shutdown\n");
    return NULL;
}

/* Initialize UDP client socket */
int setup_udp_client() {
    struct sockaddr_in client_addr;
    int enable = 1;
    
    /* Create UDP socket */
    client_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client_socket < 0) {
        perror("[CLIENT] Socket creation failed");
        return -1;
    }
    
    /* Configure client address */
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(0); /* Any available port */
    
    /* Bind socket to address */
    if (bind(client_socket, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        perror("[CLIENT] Bind failed");
        close(client_socket);
        client_socket = -1;
        return -1;
    }
    
    /* Set timeout for recvfrom */
    struct timeval tv;
    tv.tv_sec = 3;  /* 3 second timeout */
    tv.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    printf("[CLIENT] UDP client initialized\n");
    return 0;
}

/* Send initial packet to server to register client address */
int contact_server() {
    struct sockaddr_in server_addr;
    char ping_msg[] = "PING";
    int bytes_sent;
    
    /* Set up server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);
    
    /* Send ping packet to register with server */
    bytes_sent = sendto(client_socket, ping_msg, strlen(ping_msg), 0,
                       (struct sockaddr*)&server_addr, sizeof(server_addr));
                       
    if (bytes_sent < 0) {
        perror("[CLIENT] Failed to contact server");
        return -1;
    }
    
    printf("[CLIENT] Contacted server successfully\n");
    return 0;
}

/*
* Use After Free Vulnerability Example 1:
* Simple case where memory is freed and then used again
*/
void use_after_free_basic() {
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    char* buffer = NULL;
    void* other_buffer = NULL;
    
    printf("\n[TEST 1] Basic Use-After-Free vulnerability\n");
    
    /* Allocate memory for buffer */
    buffer = (char*)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    /* Set up server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);
    
    /* Receive data using recvfrom */
    printf("Waiting to receive data...\n");
    int bytes_received = recvfrom(client_socket, buffer, BUFFER_SIZE - 1, 0,
                                (struct sockaddr*)&server_addr, &addr_len);
    
    if (bytes_received > 0) {
        /* Add null terminator */
        buffer[bytes_received] = '\0';
        
        /* Print data */
        printf("Received data at address %p\n", buffer);
        printf("First few bytes: %x %x %x %x\n", 
               buffer[0], buffer[1], buffer[2], buffer[3]);
        
        /* Free the memory */
        printf("Freeing buffer memory...\n");
        free(buffer);
        
        /* Allocate other memory to disrupt the heap */
        printf("Allocating other memory to disrupt the heap...\n");
        other_buffer = malloc(BUFFER_SIZE / 2);
        if (other_buffer) {
            /* Fill with recognizable pattern */
            memset(other_buffer, 'A', BUFFER_SIZE / 2);
            printf("New buffer allocated at: %p\n", other_buffer);
        }
        
        /* USE AFTER FREE: Use the freed memory - this should crash with core dump */
        printf("USE AFTER FREE: Attempting to access & modify freed memory...\n");
        buffer[0] = 'X'; /* UAF vulnerability - writing to freed memory */
        buffer[1] = 'Y'; /* UAF vulnerability - writing to freed memory */
        buffer[2] = 'Z'; /* UAF vulnerability - writing to freed memory */
        printf("Modified freed memory: %c%c%c\n", buffer[0], buffer[1], buffer[2]);
        
        /* Free the other buffer */
        if (other_buffer) {
            free(other_buffer);
        }
    } else {
        printf("No data received or error\n");
        free(buffer);
    }
}

/*
* Use After Free Vulnerability Example 2:
* Free memory in a conditional branch, then use it outside
*/
void use_after_free_conditional() {
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    char* buffer = NULL;
    void* other_buffer = NULL;
    
    printf("\n[TEST 2] Conditional Use-After-Free vulnerability\n");
    
    /* Allocate memory for buffer */
    buffer = (char*)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    /* Set up server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);
    
    /* Receive data using recvfrom */
    printf("Waiting to receive data...\n");
    int bytes_received = recvfrom(client_socket, buffer, BUFFER_SIZE - 1, 0,
                                (struct sockaddr*)&server_addr, &addr_len);
    
    if (bytes_received > 0) {
        /* Add null terminator */
        buffer[bytes_received] = '\0';
        
        /* Get first 4 bytes to use as an integer */
        int value = *((int*)buffer);
        printf("Received value: %d\n", value);
        
        /* Free the memory in a condition */
        if (value % 2 == 0) {
            printf("Even value detected, freeing buffer...\n");
            free(buffer);
            
            /* Allocate other memory to disrupt the heap */
            other_buffer = malloc(BUFFER_SIZE / 2);
            if (other_buffer) {
                memset(other_buffer, 'B', BUFFER_SIZE / 2);
                printf("New buffer allocated at: %p\n", other_buffer);
            }
        }
        
        /* USE AFTER FREE: Use the potentially freed memory */
        printf("USE AFTER FREE: Attempting to modify buffer...\n");
        /* Write to the buffer, which may have been freed */
        buffer[0] = '!'; /* Potential UAF vulnerability */
        buffer[1] = '@'; /* Potential UAF vulnerability */
        buffer[2] = '#'; /* Potential UAF vulnerability */
        printf("Modified buffer: %c%c%c\n", buffer[0], buffer[1], buffer[2]);
        
        /* Free other buffer */
        if (other_buffer) {
            free(other_buffer);
        }
    } else {
        printf("No data received or error\n");
        free(buffer);
    }
    
    /* Make sure to free if not freed in the condition */
    if (bytes_received > 0) {
        int value = *((int*)buffer);
        if (value % 2 != 0) {
            free(buffer);
        }
    }
}

/*
* Use After Free Vulnerability Example 3:
* Free memory and then use it in a function
*/
void process_data(char* data, int size) {
    /* USE AFTER FREE: Using already freed memory */
    printf("USE AFTER FREE: Accessing freed memory in separate function\n");
    printf("Writing to freed memory...\n");
    
    /* Write to the freed memory - should crash */
    for (int i = 0; i < 10 && i < size; i++) {
        data[i] = 'Z'; /* UAF vulnerability - writing to freed memory */
    }
    
    printf("First 10 bytes now: %.*s\n", 10, data);
}

void use_after_free_in_function() {
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    char* buffer = NULL;
    void* other_buffer = NULL;
    
    printf("\n[TEST 3] Function Use-After-Free vulnerability\n");
    
    /* Allocate memory for buffer */
    buffer = (char*)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        printf("Memory allocation failed\n");
        return;
    }
    
    /* Set up server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);
    
    /* Receive data using recvfrom */
    printf("Waiting to receive data...\n");
    int bytes_received = recvfrom(client_socket, buffer, BUFFER_SIZE - 1, 0,
                                (struct sockaddr*)&server_addr, &addr_len);
    
    if (bytes_received > 0) {
        /* Add null terminator */
        buffer[bytes_received] = '\0';
        
        printf("Received data at address %p\n", buffer);
        printf("First few bytes: %x %x %x %x\n", 
               buffer[0], buffer[1], buffer[2], buffer[3]);
        
        /* Free the memory */
        printf("Freeing buffer memory...\n");
        free(buffer);
        
        /* Allocate other memory to disrupt the heap */
        other_buffer = malloc(BUFFER_SIZE / 3);
        if (other_buffer) {
            memset(other_buffer, 'C', BUFFER_SIZE / 3);
            printf("New buffer allocated at: %p\n", other_buffer);
        }
        
        /* USE AFTER FREE: Pass freed memory to another function */
        process_data(buffer, bytes_received);
        
        /* Free other buffer */
        if (other_buffer) {
            free(other_buffer);
        }
    } else {
        printf("No data received or error\n");
        free(buffer);
    }
}

/* Main function */
int main() {
    printf("===== Use After Free Vulnerability Demo (with recvfrom source) =====\n\n");
    
    /* Initialize random seed */
    srand(time(NULL));
    
    /* Start UDP server thread */
    if (pthread_create(&server_thread, NULL, udp_server_thread, NULL) != 0) {
        perror("Server thread creation failed");
        return 1;
    }
    
    /* Give server time to start */
    sleep(1);
    
    /* Setup UDP client */
    if (setup_udp_client() != 0) {
        printf("Failed to setup UDP client\n");
        server_running = 0;
        pthread_join(server_thread, NULL);
        return 1;
    }
    
    /* Run the test cases */
    
    /* Test 1: Basic Use After Free */
    if (contact_server() == 0) {
        use_after_free_basic();
    }
    
    /* Test 2: Conditional Use After Free */
    if (contact_server() == 0) {
        use_after_free_conditional();
    }
    
    /* Test 3: Function Use After Free */
    if (contact_server() == 0) {
        use_after_free_in_function();
    }
    
    /* Clean up */
    printf("\nCleaning up resources...\n");
    
    if (client_socket >= 0) {
        close(client_socket);
    }
    
    server_running = 0;
    pthread_join(server_thread, NULL);
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 