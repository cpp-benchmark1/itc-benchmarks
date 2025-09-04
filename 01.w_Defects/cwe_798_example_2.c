/********Software Analysis - FY2023*************/
/*
* File Name: cwe_798_example_2.c
* Defect Classification
* ---------------------
* Defect Type: CWE-798: Use of Hard-coded Password
* Defect Sub-type: Using hard-coded password for LDAP connection
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>

char* get_ldap_credentials();
char* authenticate_ldap_access();
char* retrieve_ldap_password();
char* process_ldap_password(char* password);


/*
* CWE-798: Use of Hard-coded Password vulnerability
* Source: Hard-coded password in function chain
* Sink: Using hard-coded password for LDAP connection
*/
void cwe_798_vulnerability_002() {
    char* ldap_password = get_ldap_credentials();
    
    char* connection_password = process_ldap_password(ldap_password);
    
    LDAP* ldap = ldap_init("localhost", 389);
    if (ldap == NULL) {
        printf("Failed to initialize LDAP\n");
        return;
    }
    
    // Set LDAP version
    int version = LDAP_VERSION3;
    if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
        printf("Failed to set LDAP version\n");
        ldap_unbind(ldap);
        return;
    }
    
    // CWE 798
    int result = ldap_simple_bind_s(ldap, "cn=admin,dc=conn,dc=com", connection_password);
    if (result != LDAP_SUCCESS) {
        printf("LDAP bind failed: %s\n", ldap_err2string(result));
        ldap_unbind(ldap);
        return;
    }
    
    printf("LDAP connection successful\n");
    
    // Search for users
    char* search_filter = "(objectClass=person)";
    char* search_base = "dc=conn,dc=com";
    
    LDAPMessage* search_result;
    result = ldap_search_ext_s(ldap, search_base, LDAP_SCOPE_SUBTREE, search_filter, NULL, 0, NULL, NULL, NULL, 0, &search_result);
    if (result != LDAP_SUCCESS) {
        printf("LDAP search failed: %s\n", ldap_err2string(result));
    } else {
        printf("LDAP search executed successfully\n");
        ldap_msgfree(search_result);
    }
    
    ldap_unbind(ldap);
}

/*
* First function in the chain - calls another function
*/
char* get_ldap_credentials() {
    return authenticate_ldap_access();
}

/*
* Second function in the chain - called by first function
*/
char* authenticate_ldap_access() {
    return retrieve_ldap_password();
}


/*
* Fourth function in the chain - called by second function
*/
char* retrieve_ldap_password() {
    char* primary_password = NULL;
    primary_password = "Ld9#pA7$mK4@nR2";
    return primary_password;
}

/*
* Helper function to process LDAP password - called by main vulnerability function
*/
char* process_ldap_password(char* password) {
    if (strlen(password) > 25) {
        password[25] = '\0';
    }
    
    return password;
}

/*
* Main function to run CWE-798 example
*/
int main() {
    printf("\n===== CWE-798: Hard-coded Password Vulnerability Demo (LDAP) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_798_vulnerability_002 ----\n");
    cwe_798_vulnerability_002();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 