/********Software Analysis - FY2023*************/
/*
* File Name: cwe_476_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-476: NULL Pointer Dereference
* Defect Sub-type: Assigning NULL to pointer and then dereferencing it (UDP)
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

#define PORT 8096

// Function prototypes
void cwe_476_vulnerability_002();
char* udp_server();
char* analyze_network_packet(char* data);
char* evaluate_packet_pointer(char* data);
char* restrict_pointer_length(char* data);
char* modify_pointer_length(char* data);
char* enhance_normal_pointer(char* data);
char* process_packet_pointer(char* data);
char* determine_data_pointer(char* data);

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
* CWE-476: NULL Pointer Dereference vulnerability
* Source: udp_server() function
* Sink: Assigning NULL to pointer and then dereferencing it
*/
void cwe_476_vulnerability_002() {
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    char* data_ptr = analyze_network_packet(network_data);
    
    // CWE 476
    printf("Pointer length: %lu\n", strlen(data_ptr));

    
    free(network_data);
}

/*
* First function in the chain - has IF and calls another function
*/
char* analyze_network_packet(char* packet) {
    char* value = NULL;
    
    if (packet != NULL) {
        if (strlen(packet) > 0) {
            value = evaluate_packet_pointer(packet);
        } else {
            value = process_packet_pointer(packet);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
char* evaluate_packet_pointer(char* ptr) {
    if (strlen(ptr) > 150) {
        return restrict_pointer_length(ptr);
    } else if (strlen(ptr) > 75) {
        return modify_pointer_length(ptr);
    } else {
        return enhance_normal_pointer(ptr);
    }
}

/*
* Third function in the chain - called by second function
*/
char* restrict_pointer_length(char* ptr) {
    if (strlen(ptr) > 300) {
        ptr[300] = '\0';
    } else {
        ptr = NULL;
    }
    
    return ptr;
}

/*
* Fourth function in the chain - called by second function
*/
char* modify_pointer_length(char* ptr) {
    if (strlen(ptr) > 100) {
        ptr[100] = '\0';
    } else {
        ptr[strlen(ptr)] = '\0';
    }
    
    return ptr;
}

/*
* Fifth function in the chain - called by second function
*/
char* enhance_normal_pointer(char* ptr) {
    if (strlen(ptr) > 30) {
        return ptr;
    }
    
    return ptr;
}

/*
* Sixth function in the chain - called by first function
*/
char* process_packet_pointer(char* ptr) {
    if (ptr == NULL) {
        return strdup("packet_default_data");
    } else {
        return ptr;
    }
}

/*
* Main function to run CWE-476 example
*/
int main() {
    printf("\n===== CWE-476: NULL Pointer Dereference Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_476_vulnerability_002 ----\n");
    cwe_476_vulnerability_002();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 