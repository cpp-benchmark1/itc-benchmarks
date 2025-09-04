/********Software Analysis - FY2023*************/
/*
* File Name: cwe_191_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-191: Integer Underflow or Wraparound
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

#define PORT 8086
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
* CWE-191: Integer Underflow vulnerability - Pattern 1
* Source: udp_server() function
* Sink: Subtraction operation with untrusted input
*/
void cwe_191_vulnerability_002() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int raw_value = decode_network_packet(network_data);
    
    /* Step 3: Pass to another variable */
    int decoded_value = raw_value;
    
    /* Step 4: Pass through another function */
    int processed_value = enhance_decoded_value(decoded_value);
    
    /* Step 5: Store in another variable */
    int final_value = processed_value;
    
    // CWE 191
    int result = -1000000 - final_value; /*Tool should detect this line as error*/ /*ERROR:Integer Underflow*/
    
    printf("[TEST] Result of subtraction: %d\n", result);
    
    free(network_data);
}

/*
* CWE-191: Integer Underflow vulnerability - Pattern 2
* Source: udp_server() function
* Sink: Mixed arithmetic operation that can cause underflow
*/
void cwe_191_vulnerability_003() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int network_value = interpret_network_data(network_data);
    
    /* Step 3: Pass to another variable */
    int interpreted_value = network_value;
    
    /* Step 4: Pass through another function */
    int computed_value = calculate_final_result(interpreted_value);
    
    /* Step 5: Store in another variable */
    int target_value = computed_value;
    
    // CWE 191
    int result = (target_value * 2) - 500000; /*Tool should detect this line as error*/ /*ERROR:Integer Underflow*/
    
    printf("[TEST] Result of mixed operation: %d\n", result);
    
    free(network_data);
}

/*
* Helper functions for first vulnerability pattern - Completely different from CWE-190
*/
int decode_network_packet(char* packet) {
    int packet_value = 0;
    int decoded_value = 0;
    int result_value = 0;
    
    if (packet != NULL && strlen(packet) > 0) {
        packet_value = atoi(packet);
        if (packet_value > 150) {
            // Validation before division: check if packet_value / 3 won't cause issues
            decoded_value = packet_value / 3;
            if (decoded_value > 80) {
                // Validation before multiplication: check if decoded_value * 4 won't overflow
                if (decoded_value <= INT_MAX / 4) {
                    result_value = decoded_value * 4;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before addition: check if decoded_value + 35 won't overflow
                if (decoded_value <= INT_MAX - 35) {
                    result_value = decoded_value + 35;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            }
        } else {
            // Validation before multiplication: check if packet_value * 6 won't overflow
            if (packet_value <= INT_MAX / 6) {
                decoded_value = packet_value * 6;
            } else {
                decoded_value = INT_MAX; // Safe fallback
            }
            
            if (decoded_value < 300) {
                // Validation before addition: check if decoded_value + 25 won't overflow
                if (decoded_value <= INT_MAX - 25) {
                    result_value = decoded_value + 25;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before subtraction: check if decoded_value - 40 won't underflow
                if (decoded_value >= 40) {
                    result_value = decoded_value - 40;
                } else {
                    result_value = 0; // Safe fallback
                }
            }
        }
    }
    
    return result_value;
}

int enhance_decoded_value(int value) {
    int enhanced_value = 0;
    int refined_value = 0;
    
    if (value > 75) {
        // Validation before subtraction: check if value - 30 won't underflow
        if (value >= 30) {
            enhanced_value = value - 30;
        } else {
            enhanced_value = 0; // Safe fallback
        }
        
        if (enhanced_value > 120) {
            // Validation before division: check if enhanced_value / 3 won't cause issues
            refined_value = enhanced_value / 3;
        } else {
            // Validation before addition: check if enhanced_value + 45 won't overflow
            if (enhanced_value <= INT_MAX - 45) {
                refined_value = enhanced_value + 45;
            } else {
                refined_value = INT_MAX; // Safe fallback
            }
        }
    } else {
        // Validation before multiplication: check if value * 5 won't overflow
        if (value <= INT_MAX / 5) {
            enhanced_value = value * 5;
        } else {
            enhanced_value = INT_MAX; // Safe fallback
        }
        
        if (enhanced_value < 200) {
            // Validation before addition: check if enhanced_value + 30 won't overflow
            if (enhanced_value <= INT_MAX - 30) {
                refined_value = enhanced_value + 30;
            } else {
                refined_value = INT_MAX; // Safe fallback
            }
        } else {
            // Validation before subtraction: check if enhanced_value - 60 won't underflow
            if (enhanced_value >= 60) {
                refined_value = enhanced_value - 60;
            } else {
                refined_value = 0; // Safe fallback
            }
        }
    }
    
    return refined_value;
}

/*
* Helper functions for second vulnerability pattern - Completely different from CWE-190
*/
int interpret_network_data(char* data) {
    int base_value = 0;
    int interpreted_value = 0;
    int result_value = 0;
    
    if (data != NULL) {
        base_value = atoi(data);
        if (base_value > 200) {
            // Validation before division: check if base_value / 5 won't cause issues
            interpreted_value = base_value / 5;
            if (interpreted_value > 100) {
                // Validation before multiplication: check if interpreted_value * 5 won't overflow
                if (interpreted_value <= INT_MAX / 5) {
                    result_value = interpreted_value * 5;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before addition: check if interpreted_value + 50 won't overflow
                if (interpreted_value <= INT_MAX - 50) {
                    result_value = interpreted_value + 50;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            }
        } else {
            // Validation before multiplication: check if base_value * 7 won't overflow
            if (base_value <= INT_MAX / 7) {
                interpreted_value = base_value * 7;
            } else {
                interpreted_value = INT_MAX; // Safe fallback
            }
            
            if (interpreted_value < 400) {
                // Validation before addition: check if interpreted_value + 40 won't overflow
                if (interpreted_value <= INT_MAX - 40) {
                    result_value = interpreted_value + 40;
                } else {
                    result_value = INT_MAX; // Safe fallback
                }
            } else {
                // Validation before subtraction: check if interpreted_value - 70 won't underflow
                if (interpreted_value >= 70) {
                    result_value = interpreted_value - 70;
                } else {
                    result_value = 0; // Safe fallback
                }
            }
        }
    }
    
    return result_value;
}

int calculate_final_result(int value) {
    int calculated_value = 0;
    int final_value = 0;
    
    if (value > 100) {
        // Validation before subtraction: check if value - 40 won't underflow
        if (value >= 40) {
            calculated_value = value - 40;
        } else {
            calculated_value = 0; // Safe fallback
        }
        
        if (calculated_value > 150) {
            // Validation before division: check if calculated_value / 4 won't cause issues
            final_value = calculated_value / 4;
        } else {
            // Validation before addition: check if calculated_value + 55 won't overflow
            if (calculated_value <= INT_MAX - 55) {
                final_value = calculated_value + 55;
            } else {
                final_value = INT_MAX; // Safe fallback
            }
        }
    } else {
        // Validation before multiplication: check if value * 6 won't overflow
        if (value <= INT_MAX / 6) {
            calculated_value = value * 6;
        } else {
            calculated_value = INT_MAX; // Safe fallback
        }
        
        if (calculated_value < 250) {
            // Validation before addition: check if calculated_value + 35 won't overflow
            if (calculated_value <= INT_MAX - 35) {
                final_value = calculated_value + 35;
            } else {
                final_value = INT_MAX; // Safe fallback
            }
        } else {
            // Validation before subtraction: check if calculated_value - 80 won't underflow
            if (calculated_value >= 80) {
                final_value = calculated_value - 80;
            } else {
                final_value = 0; // Safe fallback
            }
        }
    }
    
    return final_value;
}

/*
* Main function to run CWE-191 examples
*/
int main() {
    printf("\n===== CWE-191: Integer Underflow Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the first vulnerable function */
    printf("\n---- Running cwe_191_vulnerability_002 ----\n");
    cwe_191_vulnerability_002();
    
    /* Run the second vulnerable function */
    printf("\n---- Running cwe_191_vulnerability_003 ----\n");
    cwe_191_vulnerability_003();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 