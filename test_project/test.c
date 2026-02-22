#include <stdio.h>
#include <string.h>

int main() {
    char buffer[50];
    /* Safe comment: gets */
    gets(buffer);
    
    char dest[20];
    strcpy(dest, buffer);
    
    char out[100];
    sprintf(out, "Input: %s", dest);
    
    system("ls -la");
    
    char *password = "secret123";
    
    return 0;
}
