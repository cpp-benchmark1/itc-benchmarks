/********Software Analysis - FY2023*************/
/*
* File Name: cwe_798_example_1.c
* Defect Classification
* ---------------------
* Defect Type: CWE-798: Use of Hard-coded Password
* Defect Sub-type: Using hard-coded password for MySQL database connection
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql/mysql.h>

/*
* CWE-798: Use of Hard-coded Password vulnerability
* Source: Hard-coded password in function chain
* Sink: Using hard-coded password for MySQL connection
*/
void cwe_798_vulnerability_001() {
    char* db_password = get_database_credentials();
    
    char* mysql_password = db_password;
    
    char* connection_password = process_mysql_password(mysql_password);
    
    MYSQL* mysql = mysql_init(NULL);
    if (mysql == NULL) {
        printf(" Failed to initialize MySQL\n");
        return;
    }
    
    // CWE 798
    if (mysql_real_connect(mysql, "localhost", "admin", connection_password, "main_db", 3306, NULL, 0) == NULL) {
        printf(" MySQL connection failed: %s\n", mysql_error(mysql));
        mysql_close(mysql);
        return;
    }
    
    printf("MySQL connection successful\n");
    
    // Execute a query
    if (mysql_query(mysql, "SELECT * FROM users LIMIT 1") != 0) {
        printf("Query failed: %s\n", mysql_error(mysql));
    } else {
        printf("Query executed successfully\n");
    }
    
    mysql_close(mysql);
}

/*
* First function in the chain - calls another function
*/
char* get_database_credentials() {
    return validate_database_access();
}

/*
* Second function in the chain - called by first function
*/
char* validate_database_access() {
    return retrieve_mysql_password();
}

/*
* Fourth function in the chain - called by second function
*/
char* retrieve_mysql_password() {
    char* final_password = NULL;
    final_password = "Kj8#mN9$pQ2@vX7";
    return final_password;
}

char* process_mysql_password(char* password) {
    if (strlen(password) > 20) {
        password[20] = '\0';
    }
    
    return password;
}

/*
* Main function to run CWE-798 example
*/
int main() {
    printf("\n===== CWE-798: Hard-coded Password Vulnerability Demo (MySQL) =====\n\n");
    
    /* Run the vulnerable function */
    printf("\n---- Running cwe_798_vulnerability_001 ----\n");
    cwe_798_vulnerability_001();
    
    printf("\n===== Demo completed =====\n");
    
    return 0;
} 