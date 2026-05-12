/**
 * Test file with multiple vulnerability types to verify CWE mapping
 * This file intentionally contains vulnerabilities for testing purposes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// CWE-119: Buffer overflow
void test_buffer_overflow() {
    char buffer[10];
    char input[100] = "This is a very long string that will overflow";
    strcpy(buffer, input);  // VULNERABLE: Buffer overflow
}

// CWE-476: Null pointer dereference
void test_null_pointer() {
    int *ptr = NULL;
    *ptr = 42;  // VULNERABLE: Null pointer dereference
}

// CWE-401: Memory leak
void test_memory_leak() {
    int *data = (int*)malloc(100 * sizeof(int));
    if (data == NULL) {
        return;
    }
    // VULNERABLE: Memory leak - forgot to free
}

// CWE-416: Use after free
void test_use_after_free() {
    int *ptr = (int*)malloc(sizeof(int));
    *ptr = 10;
    free(ptr);
    *ptr = 20;  // VULNERABLE: Use after free
}

// CWE-415: Double free
void test_double_free() {
    int *ptr = (int*)malloc(sizeof(int));
    free(ptr);
    free(ptr);  // VULNERABLE: Double free
}

// CWE-190: Integer overflow
void test_integer_overflow() {
    int x = 2147483647;  // INT_MAX
    int y = x + 1;  // VULNERABLE: Integer overflow
}

// CWE-456: Uninitialized variable
void test_uninitialized_var() {
    int x;
    int y = x + 10;  // VULNERABLE: Uninitialized variable
}

// CWE-562: Return address of local variable
int* test_return_local() {
    int local = 42;
    return &local;  // VULNERABLE: Returning address of local variable
}

// CWE-120: Buffer overflow with gets
void test_gets_overflow() {
    char buffer[50];
    gets(buffer);  // VULNERABLE: gets() is unsafe
}

// CWE-805: Buffer access out of bounds
void test_array_bounds() {
    int arr[10];
    arr[15] = 100;  // VULNERABLE: Array index out of bounds
}

int main() {
    printf("Testing CWE mapping...\n");
    return 0;
}
