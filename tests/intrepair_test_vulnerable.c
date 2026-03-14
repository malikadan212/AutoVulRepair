/**
 * INTREPAIR Test File
 * Contains integer overflow vulnerabilities from the paper (§6 examples).
 *
 * Paper examples:
 *   - Line 544: int result = data * data;  (P1: squaring)
 *   - P2:       char a = y * 3;            (multiply by constant)
 *   - P3:       char a = y + z;            (add two variables)
 *   - P4:       char a = y + 4;            (add variable + constant)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-190: Integer Overflow — Pattern 1: Squaring */
int test_square(int data) {
    int result = data * data;   /* VULNERABLE: overflow if data > sqrt(INT_MAX) */
    return result;
}

/* CWE-190: Integer Overflow — Pattern 2: Multiply by constant */
char test_mult_const(char y) {
    char a = y * 3;            /* VULNERABLE: overflow if y > INT_MAX/3 */
    return a;
}

/* CWE-190: Integer Overflow — Pattern 3: Add two variables */
char test_add_vars(char y, char z) {
    char a = y + z;            /* VULNERABLE: overflow if y > INT_MAX - z */
    return a;
}

/* CWE-190: Integer Overflow — Pattern 4: Add constant */
char test_add_const(char y) {
    char a = y + 4;            /* VULNERABLE: overflow if y > INT_MAX - 4 */
    return a;
}

/* CWE-191: Integer Underflow — multiply by negative constant */
int test_mult_neg(int y) {
    int result = y * -3;       /* VULNERABLE: underflow if y > 0 && y > INT_MIN/-3 */
    return result;
}

int main() {
    printf("Testing INTREPAIR patterns...\n");
    printf("P1 (square): %d\n", test_square(2147483647));
    printf("P2 (mult c): %d\n", test_mult_const(127));
    printf("P3 (add v):  %d\n", test_add_vars(126, 2));
    printf("P4 (add c):  %d\n", test_add_const(126));
    printf("P5 (neg m):  %d\n", test_mult_neg(1000000));
    return 0;
}
