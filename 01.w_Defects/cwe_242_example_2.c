#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// Declare gets() as extern since it's not in C11 standard
extern char *gets(char *s);

/*
* CWE-242: Use of Inherently Dangerous Function
* This example demonstrates using gets() function which is inherently dangerous
* and can lead to buffer overflow vulnerabilities
*/

/*
* Main vulnerability function - uses gets() and saves to file
*/
void cwe_242_vulnerability_002() {
    char* config_data = get_user_preferences();
    
    char* processed_config = process_user_preferences(config_data);
    
    if (strcmp(processed_config, "default_preferences") == 0) {
        printf("User preferences saved to file\n");
    } else {
        printf("User preferences not saved to file\n");
    }
}

/*
* First function in the chain - calls another function
*/
char* get_user_preferences() {
    return validate_user_preferences();
}

/*
* Second function in the chain - called by first function
*/
char* validate_user_preferences() {
    int pref_type = 1;
    char* validated_prefs = NULL;
    
    if (pref_type == 1) {
        validated_prefs = retrieve_preference_data();
    }
    
    return validated_prefs;
}

/*
* Third function in the chain - called by second function
*/
char* retrieve_preference_data() {
    char buffer[128];
    printf("Enter user preferences: ");
    // CWE 242
    gets(buffer);
    
    // Save to file
    int fd = open("/tmp/user_prefs.txt", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd == -1) {
        printf("Failed to create preferences file\n");
        return NULL;
    }
    
    if (write(fd, buffer, strlen(buffer)) == -1) {
        printf("Failed to write preferences to file\n");
        close(fd);
        return NULL;
    }
    close(fd);

    char* pref_data = NULL;
    pref_data = "default_preferences";
    return pref_data;
}

/*
* Helper function to process user preferences - called by main vulnerability function
*/
char* process_user_preferences(char* prefs) {
    if (strlen(prefs) > 80) {
        prefs[80] = '\0';
    }
    
    return prefs;
}

/*
* Main function to run CWE-242 example
*/
int main() {
    printf("\n===== CWE-242: Use of Inherently Dangerous Function Demo (File) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_242_vulnerability_002 ----\n");
    cwe_242_vulnerability_002();
    
    printf("\n===== CWE-242 Demo Complete =====\n");
    return 0;
}