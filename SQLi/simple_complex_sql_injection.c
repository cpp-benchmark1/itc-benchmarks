#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <mysql/mysql.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 2048
#define MAX_SESSIONS 100
#define SESSION_TIMEOUT 3600

typedef struct {
    char session_id[32];
    char username[50];
    time_t last_activity;
    int is_admin;
} session_t;

// Global variables
session_t sessions[MAX_SESSIONS];
MYSQL *db_conn = NULL;

// Function declarations
void handle_request(int client_socket, const char *action, const char *data);
void process_login(int client_socket, const char *username, const char *password);
void process_search(int client_socket, const char *session_id, const char *search_term);
void process_profile(int client_socket, const char *session_id, const char *user_id);
char* generate_session_id();
int validate_session(const char *session_id);

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    
    // Initialize MySQL connection
    db_conn = mysql_init(NULL);
    if (db_conn == NULL) {
        perror("mysql_init failed");
        exit(EXIT_FAILURE);
    }
    
    if (mysql_real_connect(db_conn, "localhost", "app_user", "App_password123!",
                          "user_management", 0, NULL, 0) == NULL) {
        perror("mysql_real_connect failed");
        mysql_close(db_conn);
        exit(EXIT_FAILURE);
    }
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d...\n", PORT);
    
    while(1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }
        
        int bytes_received = read(new_socket, buffer, BUFFER_SIZE);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            
            // Parse request (format: "action:data")
            char *action = strtok(buffer, ":");
            char *data = strtok(NULL, ":");
            
            if (action && data) {
                handle_request(new_socket, action, data);
            }
        }
        
        close(new_socket);
    }
    
    mysql_close(db_conn);
    return 0;
}

void handle_request(int client_socket, const char *action, const char *data) {
    if (strcmp(action, "login") == 0) {
        char *username = strtok((char*)data, ",");
        char *password = strtok(NULL, ",");
        if (username && password) {
            process_login(client_socket, username, password);
        }
    }
    else if (strcmp(action, "search") == 0) {
        char *session_id = strtok((char*)data, ",");
        char *search_term = strtok(NULL, ",");
        if (session_id && search_term) {
            process_search(client_socket, session_id, search_term);
        }
    }
    else if (strcmp(action, "profile") == 0) {
        char *session_id = strtok((char*)data, ",");
        char *user_id = strtok(NULL, ",");
        if (session_id && user_id) {
            process_profile(client_socket, session_id, user_id);
        }
    }
}

void process_login(int client_socket, const char *username, const char *password) {
    // VULNERABLE: SQL Injection in login query
    char query[BUFFER_SIZE];
    snprintf(query, sizeof(query),
            "SELECT id, username, is_admin FROM users WHERE username = '%s' AND password = '%s'",
            username, password);
    
    printf("Executing login query: %s\n", query);
    
    if (mysql_query(db_conn, query)) {
        printf("Query failed: %s\n", mysql_error(db_conn));
        write(client_socket, "error:Database error", 19);
        return;
    }
    
    MYSQL_RES *result = mysql_store_result(db_conn);
    if (result) {
        MYSQL_ROW row = mysql_fetch_row(result);
        if (row) {
            char *session_id = generate_session_id();
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response), "success:%s", session_id);
            printf("Sending response: %s\n", response);
            ssize_t bytes_sent = write(client_socket, response, strlen(response));
            printf("Bytes sent: %zd\n", bytes_sent);
            printf("Login successful for user: %s\n", row[1]);
        } else {
            const char *error_msg = "error:Invalid credentials";
            printf("Sending response: %s\n", error_msg);
            ssize_t bytes_sent = write(client_socket, error_msg, strlen(error_msg));
            printf("Bytes sent: %zd\n", bytes_sent);
            printf("Login failed: No matching user found\n");
        }
        mysql_free_result(result);
    } else {
        const char *error_msg = "error:Database error";
        printf("Sending response: %s\n", error_msg);
        ssize_t bytes_sent = write(client_socket, error_msg, strlen(error_msg));
        printf("Bytes sent: %zd\n", bytes_sent);
        printf("Login failed: No result set\n");
    }
}

void process_search(int client_socket, const char *session_id, const char *search_term) {
    if (!validate_session(session_id)) {
        write(client_socket, "error:Invalid session", 20);
        return;
    }
    
    // VULNERABLE: SQL Injection in search query
    char query[BUFFER_SIZE];
    snprintf(query, sizeof(query),
            "SELECT u.id, u.username, u.email, p.bio, p.location "
            "FROM users u "
            "LEFT JOIN user_profiles p ON u.id = p.user_id "
            "WHERE u.username LIKE '%%%s%%' OR p.bio LIKE '%%%s%%'",
            search_term, search_term);
    
    printf("Executing search query: %s\n", query);
    
    if (mysql_query(db_conn, query)) {
        printf("Query failed: %s\n", mysql_error(db_conn));
        return;
    }
    
    MYSQL_RES *result = mysql_store_result(db_conn);
    if (result) {
        char response[BUFFER_SIZE] = "success:";
        int offset = strlen(response);
        
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(result))) {
            offset += snprintf(response + offset, BUFFER_SIZE - offset,
                             "%s,%s,%s,%s,%s|",
                             row[0], row[1], row[2], row[3], row[4]);
        }
        
        write(client_socket, response, strlen(response));
        mysql_free_result(result);
    }
}

void process_profile(int client_socket, const char *session_id, const char *user_id) {
    if (!validate_session(session_id)) {
        write(client_socket, "error:Invalid session", 20);
        return;
    }
    
    // VULNERABLE: SQL Injection in profile query
    char query[BUFFER_SIZE];
    snprintf(query, sizeof(query),
            "SELECT u.id, u.username, u.email, p.bio, p.location, p.phone, p.address "
            "FROM users u "
            "LEFT JOIN user_profiles p ON u.id = p.user_id "
            "WHERE u.id = '%s'",
            user_id);
    
    printf("Executing profile query: %s\n", query);
    
    if (mysql_query(db_conn, query)) {
        printf("Query failed: %s\n", mysql_error(db_conn));
        return;
    }
    
    MYSQL_RES *result = mysql_store_result(db_conn);
    if (result) {
        MYSQL_ROW row = mysql_fetch_row(result);
        if (row) {
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response),
                    "success:%s,%s,%s,%s,%s,%s,%s",
                    row[0], row[1], row[2], row[3], row[4], row[5], row[6]);
            write(client_socket, response, strlen(response));
        }
        mysql_free_result(result);
    }
}

char* generate_session_id() {
    static char session_id[32];
    snprintf(session_id, sizeof(session_id), "%ld", time(NULL));
    return session_id;
}

int validate_session(const char *session_id) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (strcmp(sessions[i].session_id, session_id) == 0) {
            if (time(NULL) - sessions[i].last_activity < SESSION_TIMEOUT) {
                sessions[i].last_activity = time(NULL);
                return 1;
            }
        }
    }
    return 0;
} 