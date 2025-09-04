/********Software Analysis - FY2023*************/
/*
* File Name: cwe_789_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-789: Memory Allocation with Excessive Size Value
* Defect Sub-type: Using untrusted input for realloc size leading to excessive memory allocation
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
#include <limits.h>

#define PORT 8092
#define BUFFER_SIZE 100

/*
* Simple UDP server function that receives a datagram and returns a value
*/
char* udp_server() {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        return NULL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock_fd);
        return NULL;
    }

    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t bytes_received = recvfrom(sock_fd, buffer, BUFFER_SIZE - 1, 0,
                                      (struct sockaddr*)&client_addr, &client_len);
    if (bytes_received <= 0) {
        close(sock_fd);
        return NULL;
    }

    buffer[bytes_received] = '\0';

    char* result = (char*)malloc(bytes_received + 1);
    if (!result) {
        close(sock_fd);
        return NULL;
    }
    strcpy(result, buffer);

    close(sock_fd);
    return result;
}

/*
* CWE-789: Memory Allocation with Excessive Size Value vulnerability
* Source: udp_server() function
* Sink: Using untrusted input for realloc size
*/
void cwe_789_vulnerability_002() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that has IF and calls another function */
    int memory_size = analyze_network_packet(network_data);
    
    /* Step 3: Pass to another variable */
    int allocation_size = memory_size;
    
    /* Step 4: Pass through another function */
    int final_size = determine_memory_size(allocation_size);
    
    /* Step 5: Store in another variable */
    int target_size = final_size;
    
    /* Step 6: Sink - Using external value for realloc size */
    char* buffer = (char*)malloc(10); // Initial allocation
    if (buffer == NULL) {
        printf("[TEST] Initial memory allocation failed\n");
        free(network_data);
        return;
    }
    
    // CWE 789
    char* new_buffer = (char*)realloc(buffer, target_size);
    if (new_buffer == NULL) {
        printf("[TEST] Reallocation failed\n");
        free(buffer);
        free(network_data);
        return;
    }
    
    buffer = new_buffer;
    printf("[TEST] Reallocated to %d bytes\n", target_size);
    
    // Use the buffer
    buffer[0] = 'B';
    printf("[TEST] First character: %c\n", buffer[0]);
    
    free(buffer);
    free(network_data);
}

/*
* First function in the chain - has IF and calls another function
*/
int analyze_network_packet(char* packet) {
    int value = 0;
    
    if (packet != NULL) {
        value = atoi(packet);
        if (value > 0) {
            value = evaluate_packet_size(value);
        } else {
            value = process_packet_size(value);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
int evaluate_packet_size(int value) {
    if (value > 2000000) {
        value = restrict_excessive_size(value);
    } else if (value > 200000) {
        value = adjust_large_size(value);
    } else {
        value = process_normal_size(value);
    }
    
    return value;
}

/*
* Third function in the chain - called by second function
*/
int restrict_excessive_size(int value) {
    if (value > 20000000) {
        return value;
    } else {
        value = value / 3;
    }
    
    return value;
}

/*
* Fourth function in the chain - called by second function
*/
int adjust_large_size(int value) {
    if (value > 1000000) {
        value = value - 100;
    } else {
        value = value + 100000;
    }
    
    return value;
}

/*
* Fifth function in the chain - called by second function
*/
int process_normal_size(int value) {
    if (value > 100000) {
        value = value * 3;
    } else {
        value = value + 20000;
    }
    
    return value;
}

/*
* Sixth function in the chain - called by first function
*/
int process_packet_size(int value) {
    if (value < -200000) {
        value = abs(value) / 3;
    } else {
        value = abs(value) + 2000;
    }
    
    return value;
}

/*
* Helper function to determine memory size - called by main vulnerability function
*/
int determine_memory_size(int size) {
    if (size > 2000000) {
        return size;
    } else if (size > 200000) {
        size = size + 20000;
    } else {
        size = size * 3;
    }
    
    return size;
}

/*
* Main function to run CWE-789 example
*/
int main() {
    printf("\n===== CWE-789: Excessive Memory Allocation Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_789_vulnerability_002 ----\n");
    cwe_789_vulnerability_002();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 