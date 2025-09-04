#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare gets() as extern since it's not in C11 standard
extern char *gets(char *s);

/*
* CWE-242: Use of Inherently Dangerous Function
* This example demonstrates using gets() function which is inherently dangerous
* and can lead to buffer overflow vulnerabilities
*/

/*
* Main vulnerability function - uses gets() and saves to environment variable
*/
void cwe_242_vulnerability_001() {
    char buffer[256];
    printf("Enter configuration: ");
    // CWE 242
    gets(buffer);
    
    // Save to environment variable
    if (setenv("USER_CONFIG", buffer, 1) != 0) {
        printf("Failed to set environment variable\n");
        return;
    }
    
    printf("Configuration saved to environment variable\n");
}

/*
* Main function to run CWE-242 example
*/
int main() {
    printf("\n===== CWE-242: Use of Inherently Dangerous Function Demo (Environment) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_242_vulnerability_001 ----\n");
    cwe_242_vulnerability_001();
    
    printf("\n===== CWE-242 Demo Complete =====\n");
    return 0;
}