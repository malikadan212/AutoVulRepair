#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    gets(buffer);  // Vulnerable: buffer overflow
    strcpy(buffer, "This is too long for the buffer");  // Another vulnerability
    printf("Buffer: %s\n", buffer);
    return 0;
}
