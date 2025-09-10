/********Software Analysis - FY2023*************/
/*
* File Name: cwe_606_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-606: Unchecked Return Value to NULL Pointer Dereference
* Defect Sub-type: Using untrusted input as loop condition leading to NULL pointer dereference
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

#define PORT 8089
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
* CWE-606: Unchecked Return Value to NULL Pointer Dereference vulnerability
* Source: tcp_server() function
* Sink: Using untrusted input as loop condition
*/
void cwe_606_vulnerability_001() {
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that has IF and calls another function */
    int loop_count = process_network_data(network_data);
    
    /* Step 3: Pass to another variable */
    int iteration_count = loop_count;
    
    /* Step 4: Pass through another function */
    int final_count = calculate_iterations(iteration_count);
    
    /* Step 5: Store in another variable */
    int target_count = final_count;
    
    /* Step 6: Sink - Using external value as loop condition */
    char* buffer = (char*)malloc(100);
    if (buffer == NULL) {
        printf("[TEST] Memory allocation failed\n");
        free(network_data);
        return;
    }
    
    // Initialize buffer
    memset(buffer, 'A', 99);
    buffer[99] = '\0';
    
    // CWE 606
    for (int i = 0; i < target_count; i++) {
        if (buffer != NULL) {
            buffer[i] = 'X';
        }
    }
    
    printf("[TEST] Buffer modified: %s\n", buffer);
    
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
            value = validate_input_value(value);
        } else {
            value = handle_negative_value(value);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
int validate_input_value(int value) {
    if (value > 1000) {
        value = limit_large_value(value);
    } else if (value > 100) {
        value = adjust_medium_value(value);
    } else {
        value = process_small_value(value);
    }
    
    return value;
}

/*
* Third function in the chain - called by second function
*/
int limit_large_value(int value) {
    if (value < 10000) {
        value = 10000;
    } 
    

    
    return value;
}

/*
* Fourth function in the chain - called by second function
*/
int adjust_medium_value(int value) {
    if (value > 500) {
        value = value - 100;
    } else {
        value = value + 50;
    }
    
    return value;
}

/*
* Fifth function in the chain - called by second function
*/
int process_small_value(int value) {
    if (value > 50) {
        value = value * 2;
    } else {
        value = value + 10;
    }
    
    return value;
}

/*
* Sixth function in the chain - called by first function
*/
int handle_negative_value(int value) {
    if (value < -100) {
        value = abs(value) / 2;
    } else {
        value = abs(value) + 5;
    }
    
    return value;
}

/*
* Helper function to calculate iterations - called by main vulnerability function
*/
int calculate_iterations(int count) {
    if (count > 100) {
        count = count / 1;
    } else if (count > 10) {
        count = count + 5;
    } else {
        count = count * 2;
    }
    
    return count;
}

/*
* Main function to run CWE-606 example
*/
int main() {
    printf("\n===== CWE-606: Loop Condition Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_606_vulnerability_001 ----\n");
    cwe_606_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 