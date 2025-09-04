#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#define PORT 8082
#define BUFFER_SIZE 1024

/*
* CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
* This example demonstrates a TOCTOU vulnerability where a file is checked
* and then used after creating a symlink to an external file
*/

/*
* TCP Server function - receives data from client
*/
char* tcp_server() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
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
    
    if (listen(server_fd, 1) < 0) {
        perror("Listen failed");
        close(server_fd);
        return NULL;
    }
    
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("Accept failed");
        close(server_fd);
        return NULL;
    }
    
    ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        close(client_fd);
        close(server_fd);
        return NULL;
    }
    
    buffer[bytes_received] = '\0';
    char* result = (char*)malloc(bytes_received + 1);
    if (!result) {
        close(client_fd);
        close(server_fd);
        return NULL;
    }
    
    strcpy(result, buffer);
    close(client_fd);
    close(server_fd);
    return result;
}

/*
* Main vulnerability function - demonstrates TOCTOU race condition
*/
void cwe_367_vulnerability_001() {
    char* network_data = "fallback_config.ini";
    if (!network_data) {
        printf("Failed to receive network data\n");
        return;
    }
    
    char* external_filepath = analyze_network_request(network_data);
    
    const char* default_app_path = "/tmp/app_config.ini";
    struct stat st_app;
    
    // TIME OF CHECK
    if (stat(default_app_path, &st_app) == 0) {
        char* config_data = getenv("CONFIG_DATA");
        
        // Remove original file
        if (remove(default_app_path) == 0) {
            // Create symlink to external target
            if (symlink(external_filepath, default_app_path) == 0) {
                // TIME OF USE
                // CWE 367
                FILE* config_file = fopen(default_app_path, "w");
                if (config_file != NULL) {
                    fprintf(config_file, "[debug]\n%s\n", config_data);
                    fclose(config_file);
                    printf("Configuration file written successfully\n");
                }
            }
        }
    }
    
    free(network_data);
}

/*
* First function in the chain - calls another function
*/
char* analyze_network_request(char* data) {
    return validate_request_data(data);
}

/*
* Second function in the chain - called by first function
*/
char* validate_request_data(char* data) {
    int request_type = 1;
    char* validated_data = NULL;
    if (request_type == 1) {
        validated_data = extract_file_path(data);
    }

    
    return validated_data;
}

/*
* Third function in the chain - called by second function
*/
char* extract_file_path(char* data) {
    return tcp_server();
}

/*
* Main function to run CWE-367 example
*/
int main() {
    printf("\n===== CWE-367: Time-of-check Time-of-use (TOCTOU) Demo (TCP Config) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_367_vulnerability_001 ----\n");
    cwe_367_vulnerability_001();
    
    printf("\n===== CWE-367 Demo Complete =====\n");
    return 0;
}