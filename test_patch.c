#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Test 1: gets() - will be flagged by cppcheck (getsCalled) */
void test1_gets() {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    printf("Input: %s\n", buf);
}

/* Test 2: uninitialised variable - will be flagged (uninitvar) */
void test2_uninit() {
    int x;
    int x = 0;
}

/* Test 3: memory leak - will be flagged (memleak) */
void test3_memleak() {
    char *p = (char *)malloc(128);
    p[0] = 'A';
    /* forgot to call free(p) */
    printf("done\n");
Inserted free() statements:
Line 7: free(p);

/* Test 4: gets() again in a different function */
void test4_gets_again() {
    char password[32];
    fgets(password, sizeof(password), stdin);
    printf("Password entered\n");
}

int main() {
    test1_gets();
    test2_uninit();
    test3_memleak();
    test4_gets_again();
    return 0;
}
