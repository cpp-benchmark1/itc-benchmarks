#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#define PORT 8083
#define BUFFER_SIZE 1024

/*
* CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
* This example demonstrates a TOCTOU vulnerability where a file is checked
* and then used after creating a symlink to an external file
*/

/*
* UDP Server function - receives data from client
*/
char* udp_server() {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return NULL;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return NULL;
    }
    
    ssize_t bytes_received = recvfrom(server_fd, buffer, BUFFER_SIZE - 1, 0,
                                     (struct sockaddr*)&client_addr, &client_len);
    if (bytes_received <= 0) {
        close(server_fd);
        return NULL;
    }
    
    buffer[bytes_received] = '\0';
    char* result = (char*)malloc(bytes_received + 1);
    if (!result) {
        close(server_fd);
        return NULL;
    }
    
    strcpy(result, buffer);
    close(server_fd);
    return result;
}

/*
* Main vulnerability function - demonstrates TOCTOU race condition
*/
char* cwe_367_vulnerability_002() {
    char* network_data = udp_server();
    if (!network_data) {
        printf("Failed to receive network data\n");
        return NULL;
    }
    
    char* user_input = process_network_packet(network_data);
    
    static char failResponse[256];
    snprintf(failResponse, sizeof(failResponse), "Failed to get server config");
    
    const char* filename = "/tmp/server_config.yml";
    struct stat st;
    
    // TIME OF CHECK
    if (stat(filename, &st) != 0) {
        perror("File does not exist");
        free(network_data);
        return failResponse;
    }
    
    // File changing after check
    if (remove(filename) != 0) {
        perror("Failed to remove original file");
        free(network_data);
        return failResponse;
    }
    
    if (symlink(user_input, filename) != 0) {
        perror("Failed to create symlink");
        free(network_data);
        return failResponse;
    }
    
    // TIME OF USE
    // SINK CWE 367
    FILE* f = fopen(filename, "r");
    if (!f) {
        perror("Failed to open file for reading");
        free(network_data);
        return failResponse;
    }
    
    char* buffer = malloc(1024);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(f);
        free(network_data);
        return failResponse;
    }
    
    if (fgets(buffer, 1024, f) == NULL) {
        perror("Failed to read file");
        free(buffer);
        fclose(f);
        free(network_data);
        return failResponse;
    }
    
    fclose(f);
    free(network_data);
    return buffer;
}

/*
* First function in the chain - calls another function
*/
char* process_network_packet(char* data) {
    return decode_packet_content(data);
}

/*
* Second function in the chain - called by first function
*/
char* decode_packet_content(char* data) {
    char* decoded_data = NULL;
    decoded_data = extract_packet_payload(data);

    return decoded_data;
}

/*
* Third function in the chain - called by second function
*/
char* extract_packet_payload(char* data) {
    char* payload_data = NULL;
    payload_data = data;
    return payload_data;
}

/*
* Main function to run CWE-367 example
*/
int main() {
    printf("\n===== CWE-367: Time-of-check Time-of-use (TOCTOU) Demo (UDP Config) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_367_vulnerability_002 ----\n");
    char* result = cwe_367_vulnerability_002();
    if (result) {
        printf("Server config: %s\n", result);
        if (result != "Failed to get server config") {
            free(result);
        }
    }
    
    printf("\n===== CWE-367 Demo Complete =====\n");
    return 0;
}