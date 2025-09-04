#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Function prototypes
void cwe_732_vulnerability_001();
char* get_config_file_path();
char* validate_config_location();
char* retrieve_config_path();
char* process_config_path(char* path);

/*
* CWE-732: Incorrect Permission Assignment for Critical Resource
* This example demonstrates creating a file with overly permissive permissions (666)
* in a sensitive system directory (/etc/)
*/

/*
* Main vulnerability function - creates file with insecure permissions
*/
void cwe_732_vulnerability_001() {
    char* config_path = get_config_file_path();
    
    char* target_path = process_config_path(config_path);
    
    // CWE 732
    int fd = open(target_path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd == -1) {
        printf("Failed to create config file\n");
        return;
    }
    
    // Write some configuration data
    const char* config_data = "database_host=localhost\ndatabase_port=3306\n";
    if (write(fd, config_data, strlen(config_data)) == -1) {
        printf("Failed to write config data\n");
        close(fd);
        return;
    }
    
    printf("Config file created successfully with permissions 666\n");
    close(fd);
}

/*
* First function in the chain - calls another function
*/
char* get_config_file_path() {
    return validate_config_location();
}

/*
* Second function in the chain - called by first function
*/
char* validate_config_location() {
    int system_type = 1;
    char* validated_path = NULL;
    
    if (system_type == 1) {
        validated_path = retrieve_config_path();
    } 
    
    return validated_path;
}

/*
* Third function in the chain - called by second function
*/
char* retrieve_config_path() {
    int config_type = 1;
    char* config_path = NULL;
    
    if (config_type == 1) {
        config_path = "/etc/config.conf";
    }
    
    return config_path;
}

/*
* Helper function to process config path - called by main vulnerability function
*/
char* process_config_path(char* path) {
    if (strlen(path) > 50) {
        path[50] = '\0';
    }
    
    return path;
}

/*
* Main function to run CWE-732 example
*/
int main() {
    printf("\n===== CWE-732: Incorrect Permission Assignment Demo (Config File) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_732_vulnerability_001 ----\n");
    cwe_732_vulnerability_001();
    
    printf("\n===== CWE-732 Demo Complete =====\n");
    return 0;
}