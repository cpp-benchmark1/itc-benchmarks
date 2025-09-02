/********Software Analysis - FY2023*************/
/*
* File Name: cwe_125_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-125: Out-of-bounds Read
* Defect Sub-type: Array access using untrusted input from UDP network
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

#define PORT 8082
#define BUFFER_SIZE 100
#define ARRAY_SIZE 20

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
* CWE-125: Out-of-bounds Read vulnerability - Pattern 1
* Source: udp_server() function
* Sink: Array access using untrusted input
*/
void cwe_125_vulnerability_002() {
    int data_array[ARRAY_SIZE] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100,
                                  110, 120, 130, 140, 150, 160, 170, 180, 190, 200};
    
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int raw_index = parse_network_response(network_data);
    
    /* Step 3: Pass to another variable */
    int processed_index = raw_index;
    
    /* Step 4: Pass through another function */
    int validated_index = validate_index(processed_index);
    
    /* Step 5: Store in another variable */
    int final_index = validated_index;
    
    // CWE 125
    int result = data_array[final_index]; /*Tool should detect this line as error*/ /*ERROR:Out-of-bounds Read*/
    
    printf("[TEST] Array value at index %d: %d\n", final_index, result);
    
    free(network_data);
}

/*
* CWE-125: Out-of-bounds Read vulnerability - Pattern 2
* Source: udp_server() function
* Sink: Array access using untrusted input with different flow
*/
void cwe_125_vulnerability_003() {
    char string_array[ARRAY_SIZE][20] = {"zero", "one", "two", "three", "four",
                                         "five", "six", "seven", "eight", "nine",
                                         "ten", "eleven", "twelve", "thirteen", "fourteen",
                                         "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"};
    
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int network_index = extract_index_from_response(network_data);
    
    /* Step 3: Pass to another variable */
    int temp_index = network_index;
    
    /* Step 4: Pass through another function */
    int computed_index = compute_array_index(temp_index);
    
    /* Step 5: Store in another variable */
    int target_index = computed_index;
    
    // CWE 125
    char* result = string_array[target_index]; /*Tool should detect this line as error*/ /*ERROR:Out-of-bounds Read*/
    
    printf("[TEST] String at index %d: %s\n", target_index, result);
    
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
            processed_value = initial_value - 5;
            if (processed_value > 15) {
                final_value = processed_value + 3;
            } else {
                final_value = processed_value * 2;
            }
        } else {
            processed_value = initial_value + 10;
            if (processed_value < 25) {
                final_value = processed_value - 2;
            } else {
                final_value = processed_value / 2;
            }
        }
    }
    
    return final_value;
}

int validate_index(int index) {
    int temp_value = 0;
    int validated_value = 0;
    
    if (index > 0) {
        temp_value = index + 1;
        if (temp_value > 30) {
            validated_value = temp_value - 15;
        } else if (temp_value > 20) {
            validated_value = temp_value - 10;
        } else {
            validated_value = temp_value + 5;
        }
    } else {
        validated_value = abs(index) + 10;
    }
    
    return validated_value;
}

/*
* Helper functions for second vulnerability pattern - More complex with multiple steps
*/
int extract_index_from_response(char* response) {
    int base_value = 0;
    int extracted_value = 0;
    int result_value = 0;
    
    if (response != NULL) {
        base_value = atoi(response);
        if (base_value > 25) {
            extracted_value = base_value - 8;
            if (extracted_value > 20) {
                result_value = extracted_value + 2;
            } else {
                result_value = extracted_value * 2;
            }
        } else {
            extracted_value = base_value + 12;
            if (extracted_value < 30) {
                result_value = extracted_value - 5;
            } else {
                result_value = extracted_value / 3;
            }
        }
    }
    
    return result_value;
}

int compute_array_index(int index) {
    int computed_value = 0;
    int final_value = 0;
    
    if (index > 15) {
        computed_value = index - 5;
        if (computed_value > 20) {
            final_value = computed_value + 1;
        } else {
            final_value = computed_value * 2;
        }
    } else {
        computed_value = index + 8;
        if (computed_value < 25) {
            final_value = computed_value + 3;
        } else {
            final_value = computed_value - 2;
        }
    }
    
    return final_value;
}

/*
* Main function to run CWE-125 examples
*/
int main() {
    printf("\n===== CWE-125: Out-of-bounds Read Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the first vulnerable function */
    printf("\n---- Running cwe_125_vulnerability_002 ----\n");
    cwe_125_vulnerability_002();
    
    /* Run the second vulnerable function */
    printf("\n---- Running cwe_125_vulnerability_003 ----\n");
    cwe_125_vulnerability_003();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 