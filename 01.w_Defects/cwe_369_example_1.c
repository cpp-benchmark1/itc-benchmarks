/********Software Analysis - FY2023*************/
/*
* File Name: cwe_369_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-369: Divide By Zero
* Defect Sub-type: Division operation with untrusted input from network
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

#define PORT 8087
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
* CWE-369: Divide By Zero vulnerability
* Source: tcp_server() function
* Sink: Division operation with untrusted input
*/
void cwe_369_vulnerability_001() {
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int external_value = process_network_information(network_data);
    
    /* Step 3: Pass to another variable */
    int input_value = external_value;
    
    /* Step 4: Pass through another function */
    int processed_value = calculate_division_value(input_value);
    
    /* Step 5: Store in another variable */
    int final_value = processed_value;
    
    /* Step 6: Sink - Division operation that can cause divide by zero */
    int result = 0;
    
    // Add some IFs to make the vulnerability function more complex
    if (final_value < 1000) {
        if (final_value < 100) {
            // CWE 369
            result = 500 / final_value; 
        } else {
            // CWE 369
            result = 1000 % final_value; 
        }
    } else if (final_value > 0) {
        result = 200 / final_value; 
    } else {
        result = 100 / (final_value + 1); 
    }
    
    printf("[TEST] Result of division: %d\n", result);
    
    free(network_data);
}

/*
* Helper function to process network information - Simplified to preserve original values
*/
int process_network_information(char* data) {
    int base_value = 0;
    int result_value = 0;
    
    if (data != NULL) {
        base_value = atoi(data);
        // Simple processing that doesn't prevent zero values
        if (base_value > 0) {
            result_value = base_value + 1;
        } else if (base_value < 0) {
            result_value = base_value - 1;
        } else {
            result_value = base_value; // Keep zero as zero
        }
    }
    
    return result_value;
}

/*
* Helper function to calculate division value - Simplified to preserve original values
*/
int calculate_division_value(int value) {
    int result_value = 0;
    
    // Simple processing that doesn't prevent zero values
    if (value > 10) {
        result_value = value + 2;
    } else if (value < -10) {
        result_value = value - 2;
    } else {
        result_value = value; // Keep small values including zero
    }
    
    return result_value;
}

/*
* Main function to run CWE-369 example
*/
int main() {
    printf("\n===== CWE-369: Divide By Zero Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_369_vulnerability_001 ----\n");
    cwe_369_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 