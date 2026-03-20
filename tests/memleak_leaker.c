/*
 * x86_64 test binary that guarantees outstanding Box64 internal allocations.
 *
 * Guest malloc()/free() don't go through Box64's customMalloc — but Box64
 * internally calls customMalloc extensively during emulation (DynaRec blocks,
 * ELF metadata, wrapper tables, symbol resolution). By calling _exit(0) we
 * skip Box64's atexit cleanup, guaranteeing outstanding customMalloc entries
 * that box64_memleak.py can detect.
 *
 * Additionally, dlopen() on standard libs forces Box64 to create symbol table
 * and wrapper allocations that won't be freed on _exit().
 *
 * Cross-compile for ARM64 CI:
 *   x86_64-linux-gnu-gcc -O1 -ldl -o memleak_leaker tests/memleak_leaker.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>

volatile int sink;

/* Hot loop functions — same as dynarec_stress.c to force DynaRec allocations */
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
    printf("memleak_leaker: starting (pid=%d)\n", getpid());

    /* Hot loops to force DynaRec JIT block allocations via customMalloc */
    for (int round = 0; round < 200; round++) {
        sink = sum_squares(500);
        sink += fibonacci(40);
        sink += (int)(taylor_sin(1.0) * 1000);
        sink += collatz_steps(27);
    }

    /* dlopen standard libs to create Box64 symbol table allocations */
    void *h1 = dlopen("libz.so.1", RTLD_LAZY);
    void *h2 = dlopen("libpthread.so.0", RTLD_LAZY);
    void *h3 = dlopen("librt.so.1", RTLD_LAZY);

    /* Don't dlclose — these stay open */
    (void)h1;
    (void)h2;
    (void)h3;

    printf("memleak_leaker: done (pid=%d)\n", getpid());

    /* _exit() skips atexit handlers, preventing Box64's cleanup.
     * This guarantees outstanding customMalloc entries remain. */
    _exit(0);
}
