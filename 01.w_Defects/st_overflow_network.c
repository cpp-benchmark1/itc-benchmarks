/********Software Analysis - FY2013*************/
/*
* File Name: st_overflow_network.c
* Defect Classification
* ---------------------
* Defect Type: Stack related defects
* Defect Sub-type: Stack overflow
* Description: Network-based stack overflow vulnerability (CWE-121)
*/
#include "HeaderFile.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define BUFFER_SIZE 8  /* Make buffer even smaller to ensure overflow */
#define PORT 8080
/* Define vflag variable */
volatile int vflag = 888;  /* Set to 888 to run both functions */
/*
 * Types of defects: Stack overflow through network socket
 * Complexity: Reading from network socket into fixed buffer and using unsafe string operations
 */
 
void st_overflow_network_001() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int canary = 0x12345678;         /* Add a canary value to detect overflow */
    char small_buffer[BUFFER_SIZE];  /* Small buffer to demonstrate overflow */
    char received_data[256];         /* Larger buffer for receiving data */
    
    printf("Server 1: Buffer address: %p, Canary address: %p\n", small_buffer, &canary);
    printf("Server 1: Distance between buffer and canary: %ld bytes\n", 
           (long)&canary - (long)small_buffer);
    
    /* Create socket */
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        return;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    /* Bind socket */
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        return;
    }
    
    /* Listen for connections */
    if (listen(server_fd, 3) < 0) {
        return;
    }
    
    printf("Server 1: Listening on port %d...\n", PORT);
    
    /* Accept connection */
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        return;
    }
    
    printf("Server 1: Connection accepted\n");
    
    /* Read data from socket */
    int bytes_read = read(new_socket, received_data, sizeof(received_data));
    if (bytes_read > 0) {
        printf("Server 1: Received %d bytes\n", bytes_read);
        printf("Server 1: Canary before overflow: 0x%x\n", canary);
        
        /* Print first few bytes of received data */
        printf("Server 1: First 16 bytes of received data: ");
        for(int i = 0; i < 16 && i < bytes_read; i++) {
            printf("%02x ", (unsigned char)received_data[i]);
        }
        printf("\n");
        
        /* Vulnerable: No size check before strcpy */
        strcpy(small_buffer, received_data); /*Tool should detect this line as error*/ /*ERROR:Stack overflow*/
        
        printf("Server 1: Canary after overflow: 0x%x\n", canary);
        if (canary != 0x12345678) {
            printf("Server 1: BUFFER OVERFLOW DETECTED! Canary was modified!\n");
        }
        
        /* Print buffer contents after overflow */
        printf("Server 1: Buffer contents after overflow: ");
        for(int i = 0; i < BUFFER_SIZE; i++) {
            printf("%02x ", (unsigned char)small_buffer[i]);
        }
        printf("\n");
    }
    
    /* Clean up */
    close(new_socket);
    close(server_fd);
}

/*
 * Types of defects: Stack overflow through network socket
 * Complexity: Multiple buffer operations with network data
 */
void st_overflow_network_002() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int canary = 0x12345678;         /* Add a canary value to detect overflow */
    char small_buffer[32];           /* Even smaller buffer */
    char temp_buffer[BUFFER_SIZE];   /* Temporary buffer */
    char received_data[128];         /* Buffer for receiving data */
    
    printf("\nServer 2: Buffer address: %p, Canary address: %p\n", small_buffer, &canary);
    printf("Server 2: Distance between buffer and canary: %ld bytes\n", 
           (long)&canary - (long)small_buffer);
    
    /* Initialize small_buffer with some data */
    strcpy(small_buffer, "INIT");
    printf("Server 2: Initial buffer contents: %s\n", small_buffer);
    
    /* Create socket */
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        return;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT + 1);  /* Use different port */
    
    /* Bind and listen */
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        return;
    }
    if (listen(server_fd, 3) < 0) {
        return;
    }
    
    printf("Server 2: Listening on port %d...\n", PORT + 1);
    
    /* Accept connection */
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        return;
    }
    
    printf("Server 2: Connection accepted\n");
    
    /* Read data from socket */
    int bytes_read = read(new_socket, received_data, sizeof(received_data));
    if (bytes_read > 0) {
        printf("Server 2: Received %d bytes\n", bytes_read);
        printf("Server 2: Canary before overflow: 0x%x\n", canary);
        
        /* Print first few bytes of received data */
        printf("Server 2: First 16 bytes of received data: ");
        for(int i = 0; i < 16 && i < bytes_read; i++) {
            printf("%02x ", (unsigned char)received_data[i]);
        }
        printf("\n");
        
        /* First vulnerable operation */
        strcpy(temp_buffer, received_data);
        printf("Server 2: After strcpy, temp_buffer: %s\n", temp_buffer);
        
        /* Second vulnerable operation - concatenation without size check */
        printf("Server 2: Before strcat, small_buffer: %s\n", small_buffer);
        strcat(small_buffer, temp_buffer); /*Tool should detect this line as error*/ /*ERROR:Stack overflow*/
        
        printf("Server 2: Canary after overflow: 0x%x\n", canary);
        if (canary != 0x12345678) {
            printf("Server 2: BUFFER OVERFLOW DETECTED! Canary was modified!\n");
        }
        
        /* Print buffer contents after overflow */
        printf("Server 2: Buffer contents after overflow: ");
        for(int i = 0; i < 32; i++) {
            printf("%02x ", (unsigned char)small_buffer[i]);
        }
        printf("\n");
    }
    
    /* Clean up */
    close(new_socket);
    close(server_fd);
}

/* Thread function for the second server */
void* server_thread(void* arg) {
    st_overflow_network_002();
    return NULL;
}

/* Add main function */
int main() {
    pthread_t thread;
    
    /* Start the second server in a separate thread */
    pthread_create(&thread, NULL, server_thread, NULL);
    
    /* Run the first server in the main thread */
    st_overflow_network_001();
    
    /* Wait for the second server thread to finish */
    pthread_join(thread, NULL);
    
    return 0;
} 