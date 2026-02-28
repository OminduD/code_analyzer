#include <stdio.h>

void safe_recursion(int a) {
    if (a > 10) return;
    safe_recursion(a + 1);
}

void uncontrolled_recursion(int b) {
    uncontrolled_recursion(b + 1); // Stack overflow
}

void check_loops() {
    int max = 100;
    
    // Mismatched
    for (int i = 0; max < 100; i++) {
        printf("loop");
    }
    
    // Wrong direction
    for (int i = 0; i < max; i--) {
        printf("loop2");
    }
}
