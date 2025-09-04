/********Software Analysis - FY2023*************/
/*
* File Name: cwe_789_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-789: Memory Allocation with Excessive Size Value
* Defect Sub-type: Using untrusted input for calloc size leading to excessive memory allocation
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

#define PORT 8091
#define BUFFER_SIZE 100

/*
* Simple TCP server function that receives a connection and returns a value
*/
char* tcp_server() {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
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

    if (listen(sock_fd, 1) < 0) {
        close(sock_fd);
        return NULL;
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(sock_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        close(sock_fd);
        return NULL;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        close(client_fd);
        close(sock_fd);
        return NULL;
    }

    buffer[bytes_received] = '\0';

    char* result = (char*)malloc(bytes_received + 1);
    if (!result) {
        close(client_fd);
        close(sock_fd);
        return NULL;
    }
    strcpy(result, buffer);

    close(client_fd);
    close(sock_fd);
    return result;
}

/*
* CWE-789: Memory Allocation with Excessive Size Value vulnerability
* Source: tcp_server() function
* Sink: Using untrusted input for calloc size
*/
void cwe_789_vulnerability_001() {
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that has IF and calls another function */
    int memory_size = process_network_data(network_data);
    
    /* Step 3: Pass to another variable */
    int allocation_size = memory_size;
    
    /* Step 4: Pass through another function */
    int final_size = calculate_memory_size(allocation_size);
    
    /* Step 5: Store in another variable */
    int target_size = final_size;
    
    // CWE 789
    char* buffer = (char*)calloc(target_size, sizeof(char));
    if (buffer == NULL) {
        printf("[TEST] Memory allocation failed\n");
        free(network_data);
        return;
    }
    
    printf("[TEST] Allocated %d bytes with calloc\n", target_size);
    
    // Use the buffer
    buffer[0] = 'A';
    printf("[TEST] First character: %c\n", buffer[0]);
    
    free(buffer);
    free(network_data);
}

/*
* First function in the chain - has IF and calls another function
*/
int process_network_data(char* data) {
    int value = 0;
    
    if (data != NULL) {
        value = atoi(data);
        if (value > 0) {
            value = validate_memory_size(value);
        } else {
            value = handle_memory_size(value);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
int validate_memory_size(int value) {
    if (value > 1000000) {
        value = limit_excessive_size(value);
    } else if (value > 100000) {
        value = adjust_large_size(value);
    } else {
        value = process_normal_size(value);
    }
    
    return value;
}

/*
* Third function in the chain - called by second function
*/
int limit_excessive_size(int value) {
    if (value > 10000000) {
        return value;
    } else {
        value = value / 1;
    }
    
    return value;
}

/*
* Fourth function in the chain - called by second function
*/
int adjust_large_size(int value) {
    if (value > 500000) {
        return value;
    } else {
        value = value + 50000;
    }
    
    return value;
}

/*
* Fifth function in the chain - called by second function
*/
int process_normal_size(int value) {
    if (value > 50000) {
        value = value * 1;
    } else {
        value = value + 10000;
    }
    
    return value;
}

/*
* Sixth function in the chain - called by first function
*/
int handle_memory_size(int value) {
    if (value < -100000) {
        value = abs(value) / 2;
    } else {
        value = abs(value) + 1000;
    }
    
    return value;
}

/*
* Helper function to calculate memory size - called by main vulnerability function
*/
int calculate_memory_size(int size) {
    if (size > 1000000) {
        size = size / 1;
    } else if (size > 100000) {
        size = size + 10000;
    } else {
        size = size * 2;
    }
    
    return size;
}

/*
* Main function to run CWE-789 example
*/
int main() {
    printf("\n===== CWE-789: Excessive Memory Allocation Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_789_vulnerability_001 ----\n");
    cwe_789_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 