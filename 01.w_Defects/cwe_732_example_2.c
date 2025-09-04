#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/*
* CWE-732: Incorrect Permission Assignment for Critical Resource
* This example demonstrates creating a file with overly permissive permissions (644)
* in a system binary directory (/usr/local/bin/)
*/

/*
* Main vulnerability function - creates file with insecure permissions
*/
void cwe_732_vulnerability_002() {
    char* binary_path = get_binary_file_path();
    
    char* target_path = process_binary_path(binary_path);
    
    // CWE 732
    int fd = open(target_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        printf("Failed to create binary file\n");
        return;
    }
    
    // Write some binary data
    const char* binary_data = "#!/bin/bash\necho 'Hello World'\n";
    if (write(fd, binary_data, strlen(binary_data)) == -1) {
        printf("Failed to write binary data\n");
        close(fd);
        return;
    }
    
    printf("Binary file created successfully with permissions 644\n");
    close(fd);
}

/*
* First function in the chain - calls another function
*/
char* get_binary_file_path() {
    return validate_binary_location();
}

/*
* Second function in the chain - called by first function
*/
char* validate_binary_location() {
    char* validated_path = NULL;
    validated_path = retrieve_binary_path();

    
    return validated_path;
}

/*
* Third function in the chain - called by second function
*/
char* retrieve_binary_path() {
    char* binary_path = NULL;
    binary_path = "/usr/local/bin/custom_script.sh";

    return binary_path;
}

/*
* Helper function to process binary path - called by main vulnerability function
*/
char* process_binary_path(char* path) {
    if (strlen(path) > 60) {
        path[60] = '\0';
    }
    
    return path;
}

/*
* Main function to run CWE-732 example
*/
int main() {
    printf("\n===== CWE-732: Incorrect Permission Assignment Demo (Binary File) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_732_vulnerability_002 ----\n");
    cwe_732_vulnerability_002();
    
    printf("\n===== CWE-732 Demo Complete =====\n");
    return 0;
}