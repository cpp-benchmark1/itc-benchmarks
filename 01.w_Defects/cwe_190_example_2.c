/********Software Analysis - FY2023*************/
/*
* File Name: cwe_190_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-190: Integer Overflow or Wraparound
* Defect Sub-type: Multiplication operation with untrusted input from network
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

#define PORT 8084
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
* CWE-190: Integer Overflow vulnerability - Pattern 1
* Source: udp_server() function
* Sink: Multiplication operation with untrusted input
*/
void cwe_190_vulnerability_002() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int raw_value = parse_network_response(network_data);
    
    /* Step 3: Pass to another variable */
    int processed_value = raw_value;
    
    /* Step 4: Pass through another function */
    int validated_value = validate_multiplication_value(processed_value);
    
    /* Step 5: Store in another variable */
    int final_value = validated_value;
    
    // CWE 190
    int result = 1000000 * final_value; /*Tool should detect this line as error*/ /*ERROR:Integer Overflow*/
    
    printf("[TEST] Result of multiplication: %d\n", result);
    
    free(network_data);
}

/*
* CWE-190: Integer Overflow vulnerability - Pattern 2
* Source: udp_server() function
* Sink: Addition operation with untrusted input in different flow
*/
void cwe_190_vulnerability_003() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int network_value = extract_value_from_response(network_data);
    
    /* Step 3: Pass to another variable */
    int temp_value = network_value;
    
    /* Step 4: Pass through another function */
    int computed_value = compute_final_value(temp_value);
    
    /* Step 5: Store in another variable */
    int target_value = computed_value;
    
    // CWE 190
    int result = 2000000000 + target_value; /*Tool should detect this line as error*/ /*ERROR:Integer Overflow*/
    
    printf("[TEST] Result of addition: %d\n", result);
    
    free(network_data);
}

/*
* Helper functions for first vulnerability pattern - More complex with multiple steps
*/
int parse_network_response(char* response) {
    int initial_value = 0;
    int processed_value = 0;
    int final_value = 0;
    
    if (response != NULL && strlen(response) > 0) {
        initial_value = atoi(response);
        if (initial_value > 20) {
            // Validation before subtraction: check if initial_value - 5 won't underflow
            if (initial_value >= 5) {
                processed_value = initial_value - 5;
            } else {
                processed_value = 0; // Safe fallback
            }
            
            if (processed_value > 15) {
                // Validation before addition: check if processed_value + 3 won't overflow
                if (processed_value <= INT_MAX - 3) {
                    final_value = processed_value + 3;
                } else {
                    final_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before multiplication: check if processed_value * 2 won't overflow
                if (processed_value <= INT_MAX / 2) {
                    final_value = processed_value * 2;
                } else {
                    final_value = INT_MAX; // Safe fallback
                }
            }
        } else {
            // Validation before addition: check if initial_value + 10 won't overflow
            if (initial_value <= INT_MAX - 10) {
                processed_value = initial_value + 10;
            } else {
                processed_value = INT_MAX; // Safe fallback
            }
            
            if (processed_value < 25) {
                // Validation before subtraction: check if processed_value - 2 won't underflow
                if (processed_value >= 2) {
                    final_value = processed_value - 2;
                } else {
                    final_value = 0; // Safe fallback
                }
            } else {
                // Validation before division: check if processed_value / 2 won't cause issues
                final_value = processed_value / 2;
            }
        }
    }
    
    return final_value;
}

int validate_multiplication_value(int value) {
    int temp_value = 0;
    int validated_value = 0;
    
    if (value > 0) {
        // Validation before addition: check if value + 1 won't overflow
        if (value <= INT_MAX - 1) {
            temp_value = value + 1;
        } else {
            temp_value = INT_MAX; // Safe fallback
        }
        
        if (temp_value > 30) {
            // Validation before subtraction: check if temp_value - 15 won't underflow
            if (temp_value >= 15) {
                validated_value = temp_value - 15;
            } else {
                validated_value = 0; // Safe fallback
            }
        } else if (temp_value > 20) {
            // Validation before subtraction: check if temp_value - 10 won't underflow
            if (temp_value >= 10) {
                validated_value = temp_value - 10;
            } else {
                validated_value = 0; // Safe fallback
            }
        } else {
            // Validation before addition: check if temp_value + 5 won't overflow
            if (temp_value <= INT_MAX - 5) {
                validated_value = temp_value + 5;
            } else {
                validated_value = INT_MAX; // Safe fallback
            }
        }
    } else {
        // Validation before addition: check if abs(value) + 10 won't overflow
        int abs_value = abs(value);
        if (abs_value <= INT_MAX - 10) {
            validated_value = abs_value + 10;
        } else {
            validated_value = INT_MAX; // Safe fallback
        }
    }
    

    
    return validated_value;
}

/*
* Helper functions for second vulnerability pattern - More complex with multiple steps
*/
int extract_value_from_response(char* response) {
    int base_value = 0;
    int extracted_value = 0;
    int result_value = 0;
    
    if (response != NULL) {
        base_value = atoi(response);
        if (base_value > 25) {
            // Validation before subtraction: check if base_value - 8 won't underflow
            if (base_value >= 8) {
                extracted_value = base_value - 8;
            } else {
                extracted_value = 0; // Safe fallback
            }
            
            if (extracted_value > 20) {
                // Validation before addition: check if extracted_value + 2 won't overflow
                if (extracted_value <= INT_MAX - 2) {
                    result_value = extracted_value + 2;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before multiplication: check if extracted_value * 2 won't overflow
                if (extracted_value <= INT_MAX / 2) {
                    result_value = extracted_value * 2;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            }
        } else {
            // Validation before addition: check if base_value + 12 won't overflow
            if (base_value <= INT_MAX - 12) {
                extracted_value = base_value + 12;
            } else {
                extracted_value = INT_MAX; // Safe fallback
            }
            
            if (extracted_value < 30) {
                // Validation before subtraction: check if extracted_value - 5 won't underflow
                if (extracted_value >= 5) {
                    result_value = extracted_value - 5;
                } else {
                    result_value = 0; // Safe fallback
                }
            } else {
                // Validation before division: check if extracted_value / 3 won't cause issues
                result_value = extracted_value / 3;
            }
        }
    }
    
    
    return result_value;
}

int compute_final_value(int value) {
    int computed_value = 0;
    int final_value = 0;
    
    if (value > 15) {
        // Validation before subtraction: check if value - 5 won't underflow
        if (value >= 5) {
            computed_value = value - 5;
        } else {
            computed_value = 0; // Safe fallback
        }
        
        if (computed_value > 20) {
            // Validation before addition: check if computed_value + 1 won't overflow
            if (computed_value <= INT_MAX - 1) {
                final_value = computed_value + 1;
            } else {
                final_value = INT_MAX; // Safe fallback
            }
        } else {
            // Validation before multiplication: check if computed_value * 2 won't overflow
            if (computed_value <= INT_MAX / 2) {
                final_value = computed_value * 2;
            } else {
                final_value = INT_MAX; // Safe fallback
            }
        }
    } else {
        // Validation before addition: check if value + 8 won't overflow
        if (value <= INT_MAX - 8) {
            computed_value = value + 8;
        } else {
            computed_value = INT_MAX; // Safe fallback
        }
        
        if (computed_value < 25) {
            // Validation before addition: check if computed_value + 3 won't overflow
            if (computed_value <= INT_MAX - 3) {
                final_value = computed_value + 3;
            } else {
                final_value = INT_MAX; // Safe fallback
            }
        } else {
            // Validation before subtraction: check if computed_value - 2 won't underflow
            if (computed_value >= 2) {
                final_value = computed_value - 2;
            } else {
                final_value = 0; // Safe fallback
            }
        }
    }
    
    // Final validation that seems to protect against overflow but doesn't work properly
    if (final_value > 2000000) {
        final_value = final_value / 4; // This reduces the value but doesn't prevent overflow in the sink
    }
    
    return final_value;
}

/*
* Main function to run CWE-190 examples
*/
int main() {
    printf("\n===== CWE-190: Integer Overflow Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the first vulnerable function */
    printf("\n---- Running cwe_190_vulnerability_002 ----\n");
    cwe_190_vulnerability_002();
    
    /* Run the second vulnerable function */
    printf("\n---- Running cwe_190_vulnerability_003 ----\n");
    cwe_190_vulnerability_003();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 