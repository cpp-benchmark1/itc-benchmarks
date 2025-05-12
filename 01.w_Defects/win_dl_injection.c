#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define BUFFER_SIZE 1024

// Define the vflag variable
volatile int vflag;

// Function pointer type for the dynamically loaded function
typedef int (*DynamicFunction)();

// Common function to handle network server setup and input
char* setup_network_server() {
    static char buffer[BUFFER_SIZE] = {0};
    WSADATA wsaData;
    SOCKET server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return NULL;
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("socket failed\n");
        WSACleanup();
        return NULL;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        printf("bind failed\n");
        closesocket(server_fd);
        WSACleanup();
        return NULL;
    }

    // Listen for connections
    if (listen(server_fd, 3) == SOCKET_ERROR) {
        printf("listen failed\n");
        closesocket(server_fd);
        WSACleanup();
        return NULL;
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) == INVALID_SOCKET) {
        printf("accept failed\n");
        closesocket(server_fd);
        WSACleanup();
        return NULL;
    }

    // VULNERABILITY: Reading untrusted input from network socket
    int valread = recv(new_socket, buffer, BUFFER_SIZE, 0);
    if (valread > 0) {
        buffer[valread] = '\0';
    }

    closesocket(new_socket);
    closesocket(server_fd);
    WSACleanup();
    return buffer;
}

/*
 * Types of defects: Code Injection
 * Complexity: Basic network input to LoadLibraryA
 */
void win_dl_injection_001() {
    char* library_path = setup_network_server();
    if (!library_path) return;

    HMODULE handle;
    DynamicFunction func;

    // VULNERABILITY: Direct use of network input in LoadLibraryA without validation
    handle = LoadLibraryA(library_path);
    if (!handle) {
        fprintf(stderr, "LoadLibrary error: %lu\n", GetLastError());
        return;
    }

    // VULNERABILITY: Using the handle from LoadLibraryA directly in GetProcAddress
    func = (DynamicFunction)GetProcAddress(handle, "malicious_function");
    if (!func) {
        fprintf(stderr, "GetProcAddress error: %lu\n", GetLastError());
        FreeLibrary(handle);
        return;
    }

    // Execute the potentially malicious function
    func();
    FreeLibrary(handle);
}

/*
 * Types of defects: Code Injection
 * Complexity: Network input through LoadLibraryW
 */
void win_dl_injection_002() {
    char* library_path = setup_network_server();
    if (!library_path) return;

    // Convert to wide string for LoadLibraryW
    int wlen = MultiByteToWideChar(CP_UTF8, 0, library_path, -1, NULL, 0);
    wchar_t* wlibrary_path = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    if (!wlibrary_path) return;

    MultiByteToWideChar(CP_UTF8, 0, library_path, -1, wlibrary_path, wlen);

    HMODULE handle;
    DynamicFunction func;

    // VULNERABILITY: Direct use of network input in LoadLibraryW without validation
    handle = LoadLibraryW(wlibrary_path);
    if (!handle) {
        fprintf(stderr, "LoadLibrary error: %lu\n", GetLastError());
        free(wlibrary_path);
        return;
    }

    // VULNERABILITY: Using the handle from LoadLibraryW directly in GetProcAddress
    func = (DynamicFunction)GetProcAddress(handle, "malicious_function");
    if (!func) {
        fprintf(stderr, "GetProcAddress error: %lu\n", GetLastError());
        FreeLibrary(handle);
        free(wlibrary_path);
        return;
    }

    // Execute the potentially malicious function
    func();
    FreeLibrary(handle);
    free(wlibrary_path);
}

/*
 * Types of defects: Code Injection
 * Complexity: Network input through LoadLibraryEx
 */
void win_dl_injection_003() {
    char* library_path = setup_network_server();
    if (!library_path) return;

    HMODULE handle;
    DynamicFunction func;

    // VULNERABILITY: Direct use of network input in LoadLibraryEx without validation
    handle = LoadLibraryExA(library_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!handle) {
        fprintf(stderr, "LoadLibrary error: %lu\n", GetLastError());
        return;
    }

    // VULNERABILITY: Using the handle from LoadLibraryEx directly in GetProcAddress
    func = (DynamicFunction)GetProcAddress(handle, "malicious_function");
    if (!func) {
        fprintf(stderr, "GetProcAddress error: %lu\n", GetLastError());
        FreeLibrary(handle);
        return;
    }

    // Execute the potentially malicious function
    func();
    FreeLibrary(handle);
}

extern volatile int vflag;
void win_dl_injection_main() {
    if (vflag == 1 || vflag == 888) {
        win_dl_injection_001();
    }

    if (vflag == 2 || vflag == 888) {
        win_dl_injection_002();
    }

    if (vflag == 3 || vflag == 888) {
        win_dl_injection_003();
    }
}

// Client function to test the vulnerability
void test_client(const char* dll_path) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in serv_addr;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return;
    }

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    // Connect to server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        printf("Connection failed\n");
        closesocket(sock);
        WSACleanup();
        return;
    }

    printf("Connected to server. Sending DLL path: %s\n", dll_path);

    // Send DLL path
    if (send(sock, dll_path, strlen(dll_path), 0) == SOCKET_ERROR) {
        printf("Send failed\n");
    }

    // Cleanup
    closesocket(sock);
    WSACleanup();
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "client") == 0) {
            // Run as client
            const char* dll_path = (argc > 2) ? argv[2] : "C:\\Windows\\System32\\kernel32.dll";
            test_client(dll_path);
        } else {
            // Run as server with test case number
            vflag = atoi(argv[1]);
            win_dl_injection_main();
        }
    } else {
        // Default to running all test cases as server
        vflag = 888;
        win_dl_injection_main();
    }
    return 0;
} 