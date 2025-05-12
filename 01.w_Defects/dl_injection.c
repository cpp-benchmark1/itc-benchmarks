#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Function pointer type for the dynamically loaded function
typedef int (*DynamicFunction)();

void process_library(const char* library_path) {
    void* handle;
    DynamicFunction func;
    char error[256];

    // VULNERABILITY: Direct use of network input in dlopen without validation
    handle = dlopen(library_path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return;
    }

    // VULNERABILITY: Using the handle from dlopen directly in dlsym
    // This could lead to code injection if the library was malicious
    func = (DynamicFunction)dlsym(handle, "malicious_function");
    if (!func) {
        fprintf(stderr, "dlsym error: %s\n", dlerror());
        dlclose(handle);
        return;
    }

    // Execute the potentially malicious function
    func();

    dlclose(handle);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket to port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept failed");
        exit(EXIT_FAILURE);
    }

    // Read library path from socket
    // VULNERABILITY: Reading untrusted input from network socket
    int valread = read(new_socket, buffer, BUFFER_SIZE);
    if (valread > 0) {
        // Remove newline if present
        buffer[strcspn(buffer, "\n")] = 0;
        
        // VULNERABILITY: Passing network input directly to process_library
        process_library(buffer);
    }

    close(new_socket);
    close(server_fd);
    return 0;
} 