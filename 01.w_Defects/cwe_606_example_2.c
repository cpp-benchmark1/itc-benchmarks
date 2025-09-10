/********Software Analysis - FY2023*************/
/*
* File Name: cwe_606_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-606: Unchecked Return Value to NULL Pointer Dereference
* Defect Sub-type: Using untrusted input as loop condition leading to buffer overflow
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

#define PORT 8090
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
* CWE-606: Unchecked Return Value to NULL Pointer Dereference vulnerability
* Source: udp_server() function
* Sink: Using untrusted input as loop condition
*/
void cwe_606_vulnerability_002() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that has IF and calls another function */
    int loop_count = analyze_network_packet(network_data);
    
    /* Step 3: Pass to another variable */
    int iteration_count = loop_count;
    
    /* Step 4: Pass through another function */
    int final_count = determine_iteration_count(iteration_count);
    
    /* Step 5: Store in another variable */
    int target_count = final_count;
    
    /* Step 6: Sink - Using external value as loop condition */
    char* data_buffer = (char*)malloc(50);
    if (data_buffer == NULL) {
        printf("[TEST] Memory allocation failed\n");
        free(network_data);
        return;
    }
    
    // Initialize buffer
    memset(data_buffer, 'B', 49);
    data_buffer[49] = '\0';
    
    // CWE 606
    for (int i = 0; i < target_count; i++) {
        if (data_buffer != NULL) {
            data_buffer[i] = 'Y';
        }
    }
    
    printf("[TEST] Data buffer modified: %s\n", data_buffer);
    
    free(data_buffer);
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
            value = evaluate_packet_value(value);
        } else {
            value = process_packet_value(value);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
int evaluate_packet_value(int value) {
    if (value > 2000) {
        value = restrict_large_value(value);
    } else if (value > 200) {
        value = modify_medium_value(value);
    } else {
        value = enhance_small_value(value);
    }
    
    return value;
}

/*
* Third function in the chain - called by second function
*/
int restrict_large_value(int value) {
    if (value < 5000) {
        value = 5000;
    } 
    


    return value;
}

/*
* Fourth function in the chain - called by second function
*/
int modify_medium_value(int value) {
    if (value > 1000) {
        value = value - 200;
    } else {
        value = value + 100;
    }
    
    return value;
}

/*
* Fifth function in the chain - called by second function
*/
int enhance_small_value(int value) {
    if (value > 100) {
        value = value * 3;
    } else {
        value = value + 20;
    }
    
    return value;
}

/*
* Sixth function in the chain - called by first function
*/
int process_packet_value(int value) {
    if (value < -200) {
        value = abs(value) / 3;
    } else {
        value = abs(value) + 10;
    }
    
    return value;
}

/*
* Helper function to determine iteration count - called by main vulnerability function
*/
int determine_iteration_count(int count) {
    if (count > 200) {
        return count;
    } else if (count > 20) {
        count = count + 10;
    } else {
        count = count * 3;
    }
    
    return count;
}

/*
* Main function to run CWE-606 example
*/
int main() {
    printf("\n===== CWE-606: Loop Condition Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_606_vulnerability_002 ----\n");
    cwe_606_vulnerability_002();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 