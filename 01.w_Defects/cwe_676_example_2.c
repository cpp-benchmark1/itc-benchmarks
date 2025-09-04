#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#define PORT 8081
#define BUFFER_SIZE 1024

// Function prototypes
void cwe_676_vulnerability_002();
char* udp_server();
time_t decode_network_packet(char* data);
time_t interpret_packet_data(char* data);
time_t extract_packet_timestamp(char* data);

/*
* CWE-676: Use of Potentially Dangerous Function
* This example demonstrates using gmtime() with external data which can be dangerous
* if the input is not a valid timestamp
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
* Main vulnerability function - uses gmtime() with external data
*/
void cwe_676_vulnerability_002() {
    char* network_data = udp_server();
    if (!network_data) {
        printf("Failed to receive network data\n");
        return;
    }
    
    time_t timestamp = decode_network_packet(network_data);
    
    // CWE 676
    struct tm* time_info = gmtime(&timestamp);
    
    if (time_info != NULL) {
        // Create session file based on time
        char session_file[128];
        sprintf(session_file, "/tmp/session_%04d%02d%02d_%02d%02d%02d.tmp",
                time_info->tm_year + 1900, time_info->tm_mon + 1, time_info->tm_mday,
                time_info->tm_hour, time_info->tm_min, time_info->tm_sec);
        
        int fd = open(session_file, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd != -1) {
            char session_data[256];
            sprintf(session_data, "SESSION_START=%ld\nUSER_ID=anonymous\nLAST_ACCESS=%04d-%02d-%02d %02d:%02d:%02d UTC\n",
                    timestamp, time_info->tm_year + 1900, time_info->tm_mon + 1, time_info->tm_mday,
                    time_info->tm_hour, time_info->tm_min, time_info->tm_sec);
            write(fd, session_data, strlen(session_data));
            close(fd);
            printf("Session file created: %s\n", session_file);
        }
    } else {
        printf("Invalid timestamp format received\n");
    }
    
    free(network_data);
}

/*
* First function in the chain - calls another function
*/
time_t decode_network_packet(char* data) {
    return interpret_packet_data(data);
}

/*
* Second function in the chain - called by first function
*/
time_t interpret_packet_data(char* data) {
    time_t interpreted_timestamp = 0;
    interpreted_timestamp = extract_packet_timestamp(data);
    
    return interpreted_timestamp;
}

/*
* Third function in the chain - called by second function
*/
time_t extract_packet_timestamp(char* data) {
    time_t packet_timestamp = 0;
    packet_timestamp = atol(data);
    return packet_timestamp;
}

/*
* Main function to run CWE-676 example
*/
int main() {
    printf("\n===== CWE-676: Use of Potentially Dangerous Function Demo (UDP Timestamp) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_676_vulnerability_002 ----\n");
    cwe_676_vulnerability_002();
    
    printf("\n===== CWE-676 Demo Complete =====\n");
    return 0;
}