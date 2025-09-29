#include <stdio.h>
#include <string.h>

int main() {
    char password[] = "secret123";
    char input[100];

    printf("Enter password: ");
    gets(input);  // Vulnerable function

    if (strcmp(input, password) == 0) {
        printf("Access granted!\n");
    } else {
        printf("Access denied!\n");
    }

    return 0;
}