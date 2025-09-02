/********Software Analysis - FY2023*************/
/*
* File Name: cwe_125_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-125: Out-of-bounds Read
* Defect Sub-type: Array access using untrusted input from network
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

#define PORT 8081
#define BUFFER_SIZE 100
#define ARRAY_SIZE 10

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
* CWE-125: Out-of-bounds Read vulnerability
* Source: tcp_server() function
* Sink: Array access using untrusted input
*/
void cwe_125_vulnerability_001() {
    int data_array[ARRAY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that seems logical */
    int index_value = process_received_data(network_data);
    
    /* Step 3: Pass to another variable */
    int array_index = index_value;
    
    /* Step 4: Pass through another function */
    int final_index = calculate_final_index(array_index);
    
    /* Step 5: Store in another variable */
    int target_index = final_index;
    
    // CWE 125
    int result = data_array[target_index]; /*Tool should detect this line as error*/ /*ERROR:Out-of-bounds Read*/
    
    printf("[TEST] Array value at index %d: %d\n", target_index, result);
    
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
            processed_value = temp_value * 2;
            if (processed_value < 100) {
                final_value = processed_value - 1;
            } else {
                final_value = processed_value / 2;
            }
        } else {
            final_value = abs(temp_value);
        }
    }
    
    return final_value;
}

/*
* Helper function to calculate final index - More complex with multiple steps
*/
int calculate_final_index(int index) {
    int intermediate_value = 0;
    int calculated_value = 0;
    int result_value = 0;
    
    if (index > 10) {
        intermediate_value = index + 5;
        if (intermediate_value > 20) {
            calculated_value = intermediate_value - 10;
        } else {
            calculated_value = intermediate_value + 2;
        }
    } else {
        intermediate_value = index * 3;
        if (intermediate_value < 15) {
            calculated_value = intermediate_value + 5;
        } else {
            calculated_value = intermediate_value - 5;
        }
    }
    
    result_value = calculated_value;
    return result_value;
}

/*
* Main function to run CWE-125 example
*/
int main() {
    printf("\n===== CWE-125: Out-of-bounds Read Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_125_vulnerability_001 ----\n");
    cwe_125_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 