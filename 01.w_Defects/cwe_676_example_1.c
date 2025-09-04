#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Function prototypes
void cwe_676_vulnerability_001();
char* tcp_server();
char* analyze_network_timestamp(char* data);
char* validate_timestamp_data(char* data);
char* extract_timestamp_value(char* data);

/*
* CWE-676: Use of Potentially Dangerous Function
* This example demonstrates using gmtime() with external data which can be dangerous
* if the input is not a valid timestamp
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
* Main vulnerability function - uses gmtime() with external data
*/
void cwe_676_vulnerability_001() {
    char* network_data = tcp_server();
    if (!network_data) {
        printf("Failed to receive network data\n");
        return;
    }
    
    char* processed_data = analyze_network_timestamp(network_data);
    
    time_t timestamp = atol(processed_data);
    // CWE 676
    struct tm* time_info = gmtime(&timestamp);
    
    if (time_info != NULL) {
        // Save log entry based on time
        int fd = open("/tmp/access.log", O_CREAT | O_WRONLY | O_APPEND, 0600);
        if (fd != -1) {
            char log_entry[256];
            sprintf(log_entry, "Access at %04d-%02d-%02d %02d:%02d:%02d UTC\n",
                    time_info->tm_year + 1900, time_info->tm_mon + 1, time_info->tm_mday,
                    time_info->tm_hour, time_info->tm_min, time_info->tm_sec);
            write(fd, log_entry, strlen(log_entry));
            close(fd);
            printf("Log entry saved successfully\n");
        }
    } else {
        printf("Invalid timestamp received\n");
    }
    
    free(network_data);
}

/*
* First function in the chain - calls another function
*/
char* analyze_network_timestamp(char* data) {
    return validate_timestamp_data(data);
}

/*
* Second function in the chain - called by first function
*/
char* validate_timestamp_data(char* data) {
    int data_type = 1;
    char* validated_data = NULL;
    
    if (data_type == 1) {
        validated_data = extract_timestamp_value(data);
    }
    
    return validated_data;
}

/*
* Third function in the chain - called by second function
*/
char* extract_timestamp_value(char* data) {
    char* timestamp_data = NULL;
    timestamp_data = data;
    return timestamp_data;
}

/*
* Main function to run CWE-676 example
*/
int main() {
    printf("\n===== CWE-676: Use of Potentially Dangerous Function Demo (TCP Log) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_676_vulnerability_001 ----\n");
    cwe_676_vulnerability_001();
    
    printf("\n===== CWE-676 Demo Complete =====\n");
    return 0;
}