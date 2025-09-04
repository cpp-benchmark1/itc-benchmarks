/********Software Analysis - FY2023*************/
/*
* File Name: cwe_191_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-191: Integer Underflow or Wraparound
* Defect Sub-type: Subtraction operation with untrusted input from network
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

#define PORT 8085
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
* CWE-191: Integer Underflow vulnerability
* Source: tcp_server() function
* Sink: Subtraction operation with untrusted input
*/
void cwe_191_vulnerability_001() {
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int external_value = analyze_network_data(network_data);
    
    /* Step 3: Pass to another variable */
    int input_value = external_value;
    
    /* Step 4: Pass through another function */
    int processed_value = transform_input_value(input_value);
    
    /* Step 5: Store in another variable */
    int final_value = processed_value;
    
    // CWE 191
    int result = final_value - 1; /*Tool should detect this line as error*/ /*ERROR:Integer Underflow*/
    
    printf("[TEST] Result of subtraction: %d\n", result);
    
    free(network_data);
}

/*
* Helper function to analyze network data - Different from CWE-190 examples
*/
int analyze_network_data(char* data) {
    int base_value = 0;
    int analyzed_value = 0;
    int result_value = 0;
    
    if (data != NULL) {
        base_value = atoi(data);
        if (base_value > 100) {
            // Validation before division: check if base_value / 4 won't cause issues
            analyzed_value = base_value / 4;
            if (analyzed_value > 50) {
                // Validation before multiplication: check if analyzed_value * 3 won't overflow
                if (analyzed_value <= INT_MAX / 3) {
                    result_value = analyzed_value * 3;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before addition: check if analyzed_value + 20 won't overflow
                if (analyzed_value <= INT_MAX - 20) {
                    result_value = analyzed_value + 20;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            }
        } else {
            // Validation before multiplication: check if base_value * 5 won't overflow
            if (base_value <= INT_MAX / 5) {
                analyzed_value = base_value * 5;
            } else {
                analyzed_value = INT_MAX; // Safe fallback
            }
            
            if (analyzed_value < 200) {
                // Validation before addition: check if analyzed_value + 15 won't overflow
                if (analyzed_value <= INT_MAX - 15) {
                    result_value = analyzed_value + 15;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before subtraction: check if analyzed_value - 30 won't underflow
                if (analyzed_value >= 30) {
                    result_value = analyzed_value - 30;
                } else {
                    result_value = 0; // Safe fallback
                }
            }
        }
    }
    
    return result_value;
}

/*
* Helper function to transform input value - Different from CWE-190 examples
*/
int transform_input_value(int value) {
    int transformed_value = 0;
    int adjusted_value = 0;
    int final_value = 0;
    
    if (value > 50) {
        // Validation before subtraction: check if value - 25 won't underflow
        if (value >= 25) {
            transformed_value = value - 25;
        } else {
            transformed_value = 0; // Safe fallback
        }
        
        if (transformed_value > 100) {
            // Validation before division: check if transformed_value / 2 won't cause issues
            adjusted_value = transformed_value / 2;
        } else {
            // Validation before addition: check if transformed_value + 40 won't overflow
            if (transformed_value <= INT_MAX - 40) {
                adjusted_value = transformed_value + 40;
            } else {
                adjusted_value = INT_MAX; // Safe fallback
            }
        }
    } else {
        // Validation before multiplication: check if value * 4 won't overflow
        if (value <= INT_MAX / 4) {
            transformed_value = value * 4;
        } else {
            transformed_value = INT_MAX; // Safe fallback
        }
        
        if (transformed_value < 150) {
            // Validation before addition: check if transformed_value + 25 won't overflow
            if (transformed_value <= INT_MAX - 25) {
                adjusted_value = transformed_value + 25;
            } else {
                adjusted_value = INT_MAX; // Safe fallback
            }
        } else {
            // Validation before subtraction: check if transformed_value - 50 won't underflow
            if (transformed_value >= 50) {
                adjusted_value = transformed_value - 50;
            } else {
                adjusted_value = 0; // Safe fallback
            }
        }
    }
    
    final_value = adjusted_value;
    return final_value;
}

/*
* Main function to run CWE-191 example
*/
int main() {
    printf("\n===== CWE-191: Integer Underflow Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_191_vulnerability_001 ----\n");
    cwe_191_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 