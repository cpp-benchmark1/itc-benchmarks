/********Software Analysis - FY2023*************/
/*
* File Name: cwe_611_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-611: Improper Restriction of XML External Entity Reference
* Defect Sub-type: Using untrusted input as filename for xmlReadFile with DTD loading enabled (UDP)
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
#include <libxml/parser.h>
#include <libxml/tree.h>

#define PORT 8094
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
* CWE-611: Improper Restriction of XML External Entity Reference vulnerability
* Source: udp_server() function
* Sink: Using untrusted input as filename for xmlReadFile with DTD loading enabled
*/
void cwe_611_vulnerability_002() {
    /* Step 1: Get external value from UDP network via server function */
    char* network_data = udp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that has IF and calls another function */
    char* file_path = analyze_network_packet(network_data);
    
    /* Step 3: Pass to another variable */
    char* xml_file_path = file_path;
    
    /* Step 4: Pass through another function */
    char* final_path = determine_file_path(xml_file_path);
    
    /* Step 5: Store in another variable */
    char* target_path = final_path;
    
    /* Step 6: Sink - Using external value as filename for xmlReadFile with DTD loading enabled */
    printf("[TEST] Attempting to parse XML file: %s\n", target_path);
    
    // CWE 611
    xmlDocPtr doc = xmlReadFile(target_path, NULL, XML_PARSE_DTDLOAD | XML_PARSE_NOENT);
    if (doc == NULL) {
        printf("[TEST] Failed to parse XML file\n");
        free(network_data);
        free(file_path);
        return;
    }
    
    printf("[TEST] Successfully parsed XML file\n");
    
    // Process the XML document
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root != NULL) {
        printf("[TEST] Root element: %s\n", root->name);
    }
    
    xmlFreeDoc(doc);
    free(network_data);
    free(file_path);
}

/*
* First function in the chain - has IF and calls another function
*/
char* analyze_network_packet(char* packet) {
    char* value = NULL;
    
    if (packet != NULL) {
        if (strlen(packet) > 0) {
            value = evaluate_packet_path(packet);
        } else {
            value = process_packet_path(packet);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
char* evaluate_packet_path(char* path) {
    if (strlen(path) > 150) {
        return restrict_path_length(path);
    } else if (strlen(path) > 75) {
        return modify_path_length(path);
    } else {
        return path;
    }
}

/*
* Third function in the chain - called by second function
*/
char* restrict_path_length(char* path) {
    if (strlen(path) > 300) {
        path[300] = '\0';
    } else {
        path[strlen(path)] = '\0';
    }
    
    return path;
}

/*
* Fourth function in the chain - called by second function
*/
char* modify_path_length(char* path) {
    if (strlen(path) > 100) {
        path[100] = '\0';
    } else {
        // Assume path already has .xml extension
        return path;
    }
    
    return path;
}

/*
* Sixth function in the chain - called by first function
*/
char* process_packet_path(char* path) {
    if (path == NULL) {
        return strdup("packet_default.xml");
    } else {
        return path;
    }
}

/*
* Helper function to determine file path - called by main vulnerability function
*/
char* determine_file_path(char* path) {
    if (strlen(path) > 200) {
        path[200] = '\0';
    }
    
    return path;
}

/*
* Main function to run CWE-611 example
*/
int main() {
    printf("\n===== CWE-611: XML External Entity Reference Vulnerability Demo (UDP) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_611_vulnerability_002 ----\n");
    cwe_611_vulnerability_002();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 