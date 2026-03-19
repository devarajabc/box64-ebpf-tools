/*
 * Custom x86_64 stress test to exercise Box64's DynaRec JIT compiler.
 *
 * When Box64 emulates this on ARM64, the hot loops force DynaRec to
 * JIT-compile multiple code blocks, triggering AllocDynarecMap calls.
 *
 * Cross-compile for ARM64 CI:
 *   x86_64-linux-gnu-gcc -O1 -o dynarec_stress dynarec_stress.c
 */
#include <stdio.h>

volatile int sink;

/* Multiple small functions to create distinct DynaRec blocks */
int sum_squares(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++)
        s += i * i;
    return s;
}

int fibonacci(int n) {
    int a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        int t = a + b;
        a = b;
        b = t;
    }
    return a;
}

double taylor_sin(double x) {
    double term = x, sum = x;
    for (int i = 1; i <= 20; i++) {
        term *= -x * x / ((2 * i) * (2 * i + 1));
        sum += term;
    }
    return sum;
}

int collatz_steps(int n) {
    int steps = 0;
    while (n != 1) {
        n = (n % 2 == 0) ? n / 2 : 3 * n + 1;
        steps++;
    }
    return steps;
}

int main(void) {
    /* Repeated calls force DynaRec to allocate JIT blocks */
    for (int round = 0; round < 200; round++) {
        sink = sum_squares(500);
        sink += fibonacci(40);
        sink += (int)(taylor_sin(1.0) * 1000);
        sink += collatz_steps(27);
    }
    printf("dynarec_stress: result=%d sin(1)=%.6f\n",
           sink, taylor_sin(1.0));
    return 0;
}
