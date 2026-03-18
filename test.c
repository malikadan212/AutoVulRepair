#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    fgets(buffer, sizeof(buffer), stdin);  // Safe: reads up to buffer size
    strncpy(buffer, "This is a string", sizeof(buffer) - 1);  // Safe: limits copy to buffer size
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
    printf("Buffer: %s\n", buffer);
    return 0;
}
