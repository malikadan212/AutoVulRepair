#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* ====================================================================
 *  test_smart_fix.c — Comprehensive buggy C file for testing Smart Fix
 *  
 *  Contains a MIX of:
 *    🔧 Rule-based fixable errors  (buffer overflow, gets, memleak, etc.)
 *    🤖 AI-required errors         (race condition, logic bugs, etc.)
 * ==================================================================== */


/* ──────────────────────────────────────────────────────────────────────
 *  🔧 RULE-BASED FIXABLE BUGS
 * ────────────────────────────────────────────────────────────────────── */

/* Bug 1: gets() usage — dangerous, should use fgets() */
void bug1_gets_usage() {
    char username[32];
    printf("Enter username: ");
    gets(username);  /* VULNERABLE: no bounds checking */
    printf("Hello, %s\n", username);
}

/* Bug 2: strcpy buffer overflow — dest too small */
void bug2_strcpy_overflow() {
    char small_buf[8];
    char *user_input = "This is a very long string that will overflow the buffer easily";
    strcpy(small_buf, user_input);  /* VULNERABLE: buffer overflow */
    printf("Copied: %s\n", small_buf);
}

/* Bug 3: sprintf overflow — no size limit */
void bug3_sprintf_overflow(const char *name, int age) {
    char output[16];
    sprintf(output, "Name: %s, Age: %d", name, age);  /* VULNERABLE: overflow */
    printf("%s\n", output);
}

/* Bug 4: Uninitialized variable */
int bug4_uninitialized_var(int flag) {
    int result;
    if (flag > 0) {
        result = 42;
    }
    /* result is uninitialized when flag <= 0 */
    return result;  /* VULNERABLE: uninitialized read */
}

/* Bug 5: Memory leak — allocated but never freed */
void bug5_memory_leak() {
    char *buffer = (char *)malloc(256);
    if (buffer == NULL) return;
    strcpy(buffer, "sensitive data");
    printf("Data: %s\n", buffer);
    /* VULNERABLE: forgot free(buffer) */
}

/* Bug 6: Null pointer dereference */
void bug6_null_deref(int *data, int size) {
    /* Missing NULL check on data */
    for (int i = 0; i < size; i++) {
        data[i] = data[i] * 2;  /* VULNERABLE: data could be NULL */
    }
}

/* Bug 7: Double free */
void bug7_double_free() {
    char *ptr = (char *)malloc(64);
    if (!ptr) return;
    strcpy(ptr, "hello");
    free(ptr);
    /* ... some code ... */
    free(ptr);  /* VULNERABLE: double free */
}

/* Bug 8: Use after free */
void bug8_use_after_free() {
    int *arr = (int *)malloc(10 * sizeof(int));
    if (!arr) return;
    arr[0] = 100;
    free(arr);
    printf("Value: %d\n", arr[0]);  /* VULNERABLE: use after free */
}

/* Bug 9: Integer overflow */
int bug9_integer_overflow(int a, int b) {
    return a * b;  /* VULNERABLE: no overflow check, could wrap */
}

/* Bug 10: Format string vulnerability */
void bug10_format_string(char *user_input) {
    printf(user_input);  /* VULNERABLE: format string attack */
}

/* Bug 11: Array out of bounds */
void bug11_array_oob() {
    int arr[10];
    for (int i = 0; i <= 10; i++) {  /* VULNERABLE: off-by-one, i <= 10 */
        arr[i] = i * 2;
    }
}

/* Bug 12: Division by zero — unchecked */
int bug12_division_by_zero(int numerator, int denominator) {
    return numerator / denominator;  /* VULNERABLE: no zero check */
}

/* Bug 13: Missing return value check */
void bug13_unchecked_return() {
    FILE *f = fopen("/etc/passwd", "r");
    /* VULNERABLE: not checking if fopen returned NULL */
    char line[256];
    fgets(line, sizeof(line), f);
    printf("First line: %s\n", line);
    fclose(f);
}


/* ──────────────────────────────────────────────────────────────────────
 *  🤖 AI-REQUIRED BUGS (complex, need contextual understanding)
 * ────────────────────────────────────────────────────────────────────── */

/* Bug 14: TOCTOU race condition */
void bug14_toctou_race(const char *filename) {
    /* Check if file exists, then open it — classic race condition */
    if (access(filename, F_OK) == 0) {
        /* An attacker could swap the file between access() and fopen() */
        FILE *f = fopen(filename, "r");
        if (f) {
            char buf[1024];
            fgets(buf, sizeof(buf), f);
            fclose(f);
        }
    }
}

/* Bug 15: Insecure temporary file creation */
void bug15_insecure_tmpfile() {
    char tmpname[64];
    sprintf(tmpname, "/tmp/myapp_%d.tmp", getpid());  /* VULNERABLE: predictable name */
    FILE *f = fopen(tmpname, "w");
    if (f) {
        fprintf(f, "secret data\n");
        fclose(f);
    }
}

/* Bug 16: Command injection */
void bug16_command_injection(const char *user_filename) {
    char cmd[256];
    sprintf(cmd, "cat %s", user_filename);  /* VULNERABLE: unsanitized input */
    system(cmd);  /* VULNERABLE: command injection */
}

/* Bug 17: Crypto weakness — using rand() for security */
void bug17_weak_random() {
    srand(42);  /* VULNERABLE: predictable seed */
    int token = rand();  /* VULNERABLE: not cryptographically secure */
    printf("Auth token: %d\n", token);
}

/* Bug 18: Information leak through error message */
void bug18_info_leak(const char *username) {
    FILE *f = fopen("/etc/shadow", "r");
    if (!f) {
        /* VULNERABLE: leaks system path and errno info */
        perror("Failed to open /etc/shadow");
        printf("Attempted access by user: %s from config at /opt/myapp/config.yml\n", username);
    }
}


/* ──────────────────────────────────────────────────────────────────────
 *  Main — calls all buggy functions
 * ────────────────────────────────────────────────────────────────────── */

int main() {
    printf("=== AutoVulRepair Smart Fix Test ===\n\n");

    /* Rule-based fixable */
    bug1_gets_usage();
    bug2_strcpy_overflow();
    bug3_sprintf_overflow("Alice", 30);
    int val = bug4_uninitialized_var(0);
    bug5_memory_leak();
    bug6_null_deref(NULL, 5);
    bug7_double_free();
    bug8_use_after_free();
    int overflow = bug9_integer_overflow(2147483647, 2);
    bug10_format_string("%s%s%s%s%s");
    bug11_array_oob();
    int result = bug12_division_by_zero(100, 0);
    bug13_unchecked_return();

    /* AI-required */
    bug14_toctou_race("/tmp/important.conf");
    bug15_insecure_tmpfile();
    bug16_command_injection("file.txt; rm -rf /");
    bug17_weak_random();
    bug18_info_leak("admin");

    printf("\n=== Done ===\n");
    return 0;
}