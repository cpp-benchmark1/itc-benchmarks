#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <mongoc/mongoc.h>

#define BUFFER_SIZE 1024
#define PORT 12345

void process_tainted_data(const char* tainted_input) {
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    bson_error_t error;
    bson_t *query;
    bool success;

    printf("Processing received data: %s\n", tainted_input);

    // Initialize MongoDB client
    mongoc_init();
    client = mongoc_client_new("mongodb://localhost:27017");
    if (!client) {
        printf("Failed to create MongoDB client\n");
        return;
    }
    printf("MongoDB client created successfully\n");

    collection = mongoc_client_get_collection(client, "test", "users");
    if (!collection) {
        printf("Failed to get collection\n");
        goto cleanup;
    }
    printf("Got collection successfully\n");

    // VULNERABILITY: Using tainted data directly in MongoDB operations
    // Create query from received data without sanitization
    query = bson_new_from_json((const uint8_t *)tainted_input, -1, &error);
    if (!query) {
        printf("Error creating query: %s\n", error.message);
        goto cleanup;
    }
    printf("Query created successfully\n");

    // VULNERABILITY: Using tainted data in insert_one
    success = mongoc_collection_insert_one(collection, query, NULL, NULL, &error);
    if (!success) {
        printf("Error inserting document: %s\n", error.message);
    } else {
        printf("Document inserted successfully\n");
    }

    // VULNERABILITY: Using tainted data in delete_one
    success = mongoc_collection_delete_one(collection, query, NULL, NULL, &error);
    if (!success) {
        printf("Error deleting document: %s\n", error.message);
    } else {
        printf("Document deleted successfully\n");
    }

    bson_destroy(query);

cleanup:
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
    mongoc_cleanup();
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating socket");
        return 1;
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        return 1;
    }

    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        perror("Error listening");
        return 1;
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept and handle client connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Error accepting connection");
            continue;
        }

        printf("New connection accepted\n");

        // SOURCE: Receive tainted data from client
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Received %zd bytes\n", bytes_received);
            process_tainted_data(buffer);
        } else {
            printf("No data received or error\n");
        }

        close(client_socket);
    }

    close(server_socket);
    return 0;
} 

/*
to compile:
gcc -Wall -I/usr/include/libmongoc-1.0 -I/usr/include/libbson-1.0 -o nosql_injection nosql_injection.c -lmongoc-1.0 -lbson-1.0

to run:
./nosql_injection
*/