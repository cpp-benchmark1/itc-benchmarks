/********Software Analysis - FY2023*************/
/*
* File Name: cwe_369_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-369: Divide By Zero
* Defect Sub-type: Mixed arithmetic operations with untrusted input from network
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

#define PORT 8088
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
* CWE-369: Divide By Zero vulnerability - Pattern 1
* Source: udp_server() function
* Sink: Division operation with untrusted input
*/
void cwe_369_vulnerability_002() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int raw_value = extract_network_data(network_data);
    
    /* Step 3: Pass to another variable */
    int extracted_value = raw_value;
    
    /* Step 4: Pass through another function */
    int processed_value = transform_extracted_value(extracted_value);
    
    /* Step 5: Store in another variable */
    int final_value = processed_value;
    
    /* Step 6: Sink - Division operation that can cause divide by zero */
    int result = 0;
    
    // Add multiple IFs to make the vulnerability function more complex
    if (final_value >= 0) {
        if (final_value == 0) {
            // CWE 369
            result = 1000 / final_value; 
        } else if (final_value < 50) {
            result = 250 / final_value; 
        } else if (final_value < 200) {
            result = 500 / final_value; 
        } else {
            result = 1000 / final_value; 
        }
    } else {
        // Handle negative values
        if (final_value > -100) {
            result = 300 / abs(final_value); 
        } else {
            result = 600 / abs(final_value); 
        }
    }
    
    printf("[TEST] Result of division: %d\n", result);
    
    free(network_data);
}

/*
* CWE-369: Divide By Zero vulnerability - Pattern 2
* Source: udp_server() function
* Sink: Mixed arithmetic operation that can cause divide by zero
*/
void cwe_369_vulnerability_003() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int network_value = parse_network_message(network_data);
    
    /* Step 3: Pass to another variable */
    int parsed_value = network_value;
    
    /* Step 4: Pass through another function */
    int computed_value = evaluate_parsed_value(parsed_value);
    
    /* Step 5: Store in another variable */
    int target_value = computed_value;
    
    /* Step 6: Sink - Mixed arithmetic operation that can cause divide by zero */
    int result = 0;
    
    // Complex IF structure with multiple conditions
    if (target_value > 0) {
        if (target_value <= 10) {
            // CWE 369
            result = target_value % 0;
        } else if (target_value <= 100) {
            result = (500 - target_value) / target_value; 
        } else {
            result = (1000 + target_value) / target_value; 
        }
    } else if (target_value == 0) {
        result = 200 / (target_value + 1);
    } else {
        // Handle negative values
        if (target_value >= -50) {
            result = (300 + abs(target_value)) / abs(target_value); 
        } else {
            result = (800 - abs(target_value)) / abs(target_value); 
        }
    }
    
    printf("[TEST] Result of mixed operation: %d\n", result);
    
    free(network_data);
}

/*
* Helper functions for first vulnerability pattern - Simplified to preserve original values
*/
int extract_network_data(char* packet) {
    int packet_value = 0;
    int result_value = 0;
    
    if (packet != NULL && strlen(packet) > 0) {
        packet_value = atoi(packet);
        // Simple processing that doesn't prevent zero values
        if (packet_value > 0) {
            result_value = packet_value + 1;
        } else if (packet_value < 0) {
            result_value = packet_value - 1;
        } else {
            result_value = packet_value; // Keep zero as zero
        }
    }
    
    return result_value;
}

int transform_extracted_value(int value) {
    int result_value = 0;
    
    // Simple processing that doesn't prevent zero values
    if (value > 5) {
        result_value = value + 1;
    } else if (value < -5) {
        result_value = value - 1;
    } else {
        result_value = value; // Keep small values including zero
    }
    
    return result_value;
}

/*
* Helper functions for second vulnerability pattern - Simplified to preserve original values
*/
int parse_network_message(char* message) {
    int message_value = 0;
    int result_value = 0;
    
    if (message != NULL) {
        message_value = atoi(message);
        // Simple processing that doesn't prevent zero values
        if (message_value > 0) {
            result_value = message_value + 1;
        } else if (message_value < 0) {
            result_value = message_value - 1;
        } else {
            result_value = message_value; // Keep zero as zero
        }
    }
    
    return result_value;
}

int evaluate_parsed_value(int value) {
    int result_value = 0;
    
    // Simple processing that doesn't prevent zero values
    if (value > 5) {
        result_value = value + 1;
    } else if (value < -5) {
        result_value = value - 1;
    } else {
        result_value = value; // Keep small values including zero
    }
    
    return result_value;
}

/*
* Main function to run CWE-369 examples
*/
int main() {
    printf("\n===== CWE-369: Divide By Zero Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the first vulnerable function */
    printf("\n---- Running cwe_369_vulnerability_002 ----\n");
    cwe_369_vulnerability_002();
    
    /* Run the second vulnerable function */
    printf("\n---- Running cwe_369_vulnerability_003 ----\n");
    cwe_369_vulnerability_003();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 