/********Software Analysis - FY2023*************/
/*
* File Name: cwe_611_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-611: Improper Restriction of XML External Entity Reference
* Defect Sub-type: Using untrusted input as filename for xmlReadFile with DTD loading enabled
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

#define PORT 8093
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
* CWE-611: Improper Restriction of XML External Entity Reference vulnerability
* Source: tcp_server() function
* Sink: Using untrusted input as filename for xmlReadFile with DTD loading enabled
*/
void cwe_611_vulnerability_001() {
    /* Step 1: Get external value from network via server function */
    char* network_data = tcp_server();
    if (network_data == NULL) {
        printf("[TEST] Failed to get data from server\n");
        return;
    }
    
    printf("[TEST] Received data: %s\n", network_data);
    
    /* Step 2: Pass to function that has IF and calls another function */
    char* file_path = process_network_data(network_data);
    
    /* Step 3: Pass to another variable */
    char* xml_file_path = file_path;
    
    /* Step 4: Pass through another function */
    char* final_path = calculate_file_path(xml_file_path);
    
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
char* process_network_data(char* data) {
    char* value = NULL;
    
    if (data != NULL) {
        if (strlen(data) > 0) {
            value = validate_file_path(data);
        } else {
            value = handle_file_path(data);
        }
    }
    
    return value;
}

/*
* Second function in the chain - called by first function
*/
char* validate_file_path(char* path) {
    if (strlen(path) > 100) {
        return limit_path_length(path);
    } else if (strlen(path) > 50) {
        return adjust_path_length(path);
    } else {
        return process_normal_path(path);
    }
}

/*
* Third function in the chain - called by second function
*/
char* limit_path_length(char* path) {
    if (strlen(path) > 200) {
        path[200] = '\0';
    } else {
        path[strlen(path)] = '\0';
    }
    
    return path;
}

/*
* Fourth function in the chain - called by second function
*/
char* adjust_path_length(char* path) {
    if (strlen(path) > 75) {
        path[75] = '\0';
    } else {
        // Assume path already has .xml extension
        return path;
    }
    
    return path;
}

/*
* Fifth function in the chain - called by second function
*/
char* process_normal_path(char* path) {
    return path;
}

/*
* Sixth function in the chain - called by first function
*/
char* handle_file_path(char* path) {
    if (path == NULL) {
        return strdup("default.xml");
    } else {
        return path;   
    }
}

/*
* Helper function to calculate file path - called by main vulnerability function
*/
char* calculate_file_path(char* path) {
    if (strlen(path) > 150) {
        path[150] = '\0';
    }
    
    return path;
}

/*
* Main function to run CWE-611 example
*/
int main() {
    printf("\n===== CWE-611: XML External Entity Reference Vulnerability Demo =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_611_vulnerability_001 ----\n");
    cwe_611_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 