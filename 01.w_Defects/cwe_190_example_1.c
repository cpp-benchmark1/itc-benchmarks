/********Software Analysis - FY2023*************/
/*
* File Name: cwe_190_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-190: Integer Overflow or Wraparound
* Defect Sub-type: Addition operation with untrusted input from network
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
#include <limits.h> // Required for INT_MAX

#define PORT 8083
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
* CWE-190: Integer Overflow vulnerability
* Source: tcp_server() function
* Sink: Addition operation with untrusted input
*/
void cwe_190_vulnerability_001() {
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int external_value = process_received_data(network_data);
    
    /* Step 3: Pass to another variable */
    int input_value = external_value;
    
    /* Step 4: Pass through another function */
    int processed_value = calculate_addition_value(input_value);
    
    /* Step 5: Store in another variable */
    int final_value = processed_value;
    
    // CWE 190
    int result = 2147483647 + final_value; /*Tool should detect this line as error*/ /*ERROR:Integer Overflow*/
    
    printf("[TEST] Result of addition: %d\n", result);
    
    free(network_data);
}

/*
* Helper function to process received data - More complex with multiple steps
*/
int process_received_data(char* data) {
    int temp_value = 0;
    int processed_value = 0;
    int final_value = 0;
    
    if (data != NULL) {
        temp_value = atoi(data);
        if (temp_value > 0) {
            // Validation before multiplication: check if temp_value * 2 won't overflow
            if (temp_value <= INT_MAX / 2) {
                processed_value = temp_value * 2;
            } else {
                processed_value = INT_MAX; // Safe fallback
            }
            
            if (processed_value < 100) {
                // Validation before subtraction: check if processed_value - 1 won't underflow
                if (processed_value >= 1) {
                    final_value = processed_value - 1;
                } else {
                    final_value = 0; // Safe fallback
                }
            } else {
                // Validation before division: check if processed_value / 2 won't cause issues
                final_value = processed_value / 2;
            }
        } else {
            // Validation before abs(): check if abs(temp_value) won't cause issues
            // Note: abs() is generally safe, but we ensure temp_value is not INT_MIN
            if (temp_value != INT_MIN) {
                final_value = abs(temp_value);
            } else {
                final_value = INT_MAX; // Safe fallback for INT_MIN
            }
        }
    }
    
    return final_value;
}

/*
* Helper function to calculate addition value - More complex with multiple steps
*/
int calculate_addition_value(int value) {
    int intermediate_value = 0;
    int calculated_value = 0;
    int result_value = 0;
    
    if (value > 10) {
        // Validation before addition: check if value + 5 won't overflow
        if (value <= INT_MAX - 5) {
            intermediate_value = value + 5;
        } else {
            intermediate_value = INT_MAX; // Safe fallback
        }
        
        if (intermediate_value > 20) {
            // Validation before subtraction: check if intermediate_value - 10 won't underflow
            if (intermediate_value >= 10) {
                calculated_value = intermediate_value - 10;
            } else {
                calculated_value = 0; // Safe fallback
            }
        } else {
            // Validation before addition: check if intermediate_value + 2 won't overflow
            if (intermediate_value <= INT_MAX - 2) {
                calculated_value = intermediate_value + 2;
            } else {
                calculated_value = INT_MAX; // Safe fallback
            }
        }
    } else {
        // Validation before multiplication: check if value * 3 won't overflow
        if (value <= INT_MAX / 3) {
            intermediate_value = value * 3;
        } else {
            intermediate_value = INT_MAX; // Safe fallback
        }
        
        if (intermediate_value < 15) {
            // Validation before addition: check if intermediate_value + 5 won't overflow
            if (intermediate_value <= INT_MAX - 5) {
                calculated_value = intermediate_value + 5;
            } else {
                calculated_value = INT_MAX; // Safe fallback
            }
        } else {
            // Validation before subtraction: check if intermediate_value - 5 won't underflow
            if (intermediate_value >= 5) {
                calculated_value = intermediate_value - 5;
            } else {
                calculated_value = 0; // Safe fallback
            }
        }
    }
    
    result_value = calculated_value;
    return result_value;
}

/*
* Main function to run CWE-190 example
*/
int main() {
    printf("\n===== CWE-190: Integer Overflow Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_190_vulnerability_001 ----\n");
    cwe_190_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 