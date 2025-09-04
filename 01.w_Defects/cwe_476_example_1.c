/********Software Analysis - FY2023*************/
/*
* File Name: cwe_476_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-476: NULL Pointer Dereference
* Defect Sub-type: Assigning NULL to pointer and then dereferencing it
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

#define PORT 8095

// Function prototypes
void cwe_476_vulnerability_001();
char* tcp_server();
char* process_network_data(char* data);
char* validate_data_pointer(char* data);
char* limit_pointer_length(char* data);
char* adjust_pointer_length(char* data);
char* process_normal_pointer(char* data);
char* handle_data_pointer(char* data);
char* calculate_data_pointer(char* data);

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
* CWE-476: NULL Pointer Dereference vulnerability
* Source: tcp_server() function
* Sink: Assigning NULL to pointer and then dereferencing it
*/
void cwe_476_vulnerability_001() {
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that has IF and calls another function */
    char* data_ptr = process_network_data(network_data);
    
    /* Step 3: Pass to another variable */
    char* target_ptr = data_ptr;
    
    /* Step 4: Pass through another function */
    char* final_ptr = calculate_data_pointer(target_ptr);
    
    /* Step 5: Store in another variable */
    char* result_ptr = final_ptr;
    
    if (result_ptr != NULL) {
        printf("[TEST] Data: %s\n", result_ptr);
    } else {
        printf("[TEST] Pointer is NULL\n");
    }
    
    free(network_data);
}

/*
* First function in the chain - has IF and calls another function
*/
char* process_network_data(char* data) {
    char* value = NULL;
    
    if (data != NULL) {
        if (strlen(data) > 0) {
            value = validate_data_pointer(data);
        } else {
            value = handle_data_pointer(data);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
char* validate_data_pointer(char* ptr) {
    if (strlen(ptr) > 100) {
        return limit_pointer_length(ptr);
    } else if (strlen(ptr) > 50) {
        return adjust_pointer_length(ptr);
    } else {
        return process_normal_pointer(ptr);
    }
}

/*
* Third function in the chain - called by second function
*/
char* limit_pointer_length(char* ptr) {
    if (strlen(ptr) > 200) {
        ptr[200] = '\0';
    } else {
        ptr = NULL;
        // CWE 476
        printf("Pointer length: %lu\n", strlen(ptr));
    }
    
    return ptr;
}

/*
* Fourth function in the chain - called by second function
*/
char* adjust_pointer_length(char* ptr) {
    if (strlen(ptr) > 75) {
        ptr[75] = '\0';
    } else {
        ptr[strlen(ptr)] = '\0';
    }
    
    return ptr;
}

/*
* Fifth function in the chain - called by second function
*/
char* process_normal_pointer(char* ptr) {
    if (strlen(ptr) > 25) {
        return ptr;
    }
    
    return ptr;
}

/*
* Sixth function in the chain - called by first function
*/
char* handle_data_pointer(char* ptr) {
    if (ptr == NULL) {
        return strdup("default_data");
    } else {
        return ptr;
    }
}

/*
* Helper function to calculate data pointer - called by main vulnerability function
*/
char* calculate_data_pointer(char* ptr) {
    if (strlen(ptr) > 150) {
        ptr[150] = '\0';
    }
    
    return ptr;
}

/*
* Main function to run CWE-476 example
*/
int main() {
    printf("\n===== CWE-476: NULL Pointer Dereference Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_476_vulnerability_001 ----\n");
    cwe_476_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 