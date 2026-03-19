/*
 * Multi-process x86_64 test binary to exercise Box64's fork/vfork/exec
 * lifecycle tracking in box64_steam.py.
 *
 * When Box64 emulates this on ARM64, fork/vfork/execve go through Box64's
 * wrapped libc (my_fork, my_vfork, my_execve), triggering the corresponding
 * eBPF uprobes.
 *
 * Modes (selected by argv[1]):
 *   (none)      Parent: fork -> child execs --child; vfork -> child execs
 *               --vchild; then runs hot loops for DynaRec activity.
 *   --child     Fork child: runs hot loops, then execve(argv[0], "--worker").
 *   --vchild    Vfork child: immediately execve(argv[0], "--worker").
 *   --worker N  Worker: runs hot loops for N seconds (default 1).
 *
 * Process tree created:
 *   box64 steam_lifecycle          (parent)
 *   +-- box64 steam_lifecycle --child
 *   |   +-- box64 steam_lifecycle --worker 1
 *   +-- box64 steam_lifecycle --vchild
 *       +-- box64 steam_lifecycle --worker 1
 *
 * Cross-compile for ARM64 CI:
 *   x86_64-linux-gnu-gcc -O1 -o /tmp/steam_lifecycle tests/steam_lifecycle.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

volatile int sink;

/* Hot loop functions — same as dynarec_stress.c to create DynaRec blocks */
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

/* Run hot loops for the given number of seconds */
void run_hot_loops(int seconds) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (1) {
        for (int i = 0; i < 100; i++) {
            sink = sum_squares(500);
            sink += fibonacci(40);
            sink += (int)(taylor_sin(1.0) * 1000);
            sink += collatz_steps(27);
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= seconds)
            break;
    }
}

/* --worker N: run hot loops for N seconds */
int do_worker(int argc, char *argv[]) {
    int duration = 1;
    if (argc >= 3)
        duration = atoi(argv[2]);
    if (duration < 1)
        duration = 1;
    printf("steam_lifecycle worker (pid=%d): running for %ds\n",
           getpid(), duration);
    run_hot_loops(duration);
    printf("steam_lifecycle worker (pid=%d): done\n", getpid());
    return 0;
}

/* --child: run hot loops, then exec into --worker */
int do_child(char *self) {
    printf("steam_lifecycle child (pid=%d): hot loops then exec\n", getpid());
    run_hot_loops(1);
    char *new_argv[] = {self, "--worker", "1", NULL};
    execve(self, new_argv, NULL);
    /* If execve fails, try execvp as fallback */
    perror("execve failed");
    return 1;
}

/* --vchild: immediately exec into --worker (no hot loops — vfork restriction) */
int do_vchild(char *self) {
    /* After vfork, we must not modify parent state — go straight to exec */
    char *new_argv[] = {self, "--worker", "1", NULL};
    execve(self, new_argv, NULL);
    perror("execve failed in vchild");
    _exit(1);
    return 1;  /* unreachable */
}

/* Parent mode: fork, vfork, then hot loops */
int do_parent(char *self, int loop_seconds) {
    pid_t pid;

    printf("steam_lifecycle parent (pid=%d): starting\n", getpid());

    /* Fork -> child runs --child mode */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        return do_child(self);
    }
    printf("steam_lifecycle parent: forked child pid=%d\n", pid);

    /* Brief pause to let fork child start before vfork */
    usleep(100000);  /* 100ms */

    /* Vfork -> child runs --vchild mode */
    pid = vfork();
    if (pid < 0) {
        perror("vfork");
        return 1;
    }
    if (pid == 0) {
        do_vchild(self);
        _exit(1);  /* unreachable if exec succeeds */
    }
    printf("steam_lifecycle parent: vforked child pid=%d\n", pid);

    /* Parent hot loops to generate DynaRec activity */
    printf("steam_lifecycle parent: running hot loops for %ds\n", loop_seconds);
    run_hot_loops(loop_seconds);

    /* Wait for all children */
    int status;
    while (wait(&status) > 0)
        ;

    printf("steam_lifecycle parent: done\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc >= 2 && strcmp(argv[1], "--worker") == 0) {
        return do_worker(argc, argv);
    }
    if (argc >= 2 && strcmp(argv[1], "--child") == 0) {
        return do_child(argv[0]);
    }
    if (argc >= 2 && strcmp(argv[1], "--vchild") == 0) {
        return do_vchild(argv[0]);
    }

    /* Parent mode — optional duration argument */
    int loop_seconds = 2;
    if (argc >= 2)
        loop_seconds = atoi(argv[1]);
    if (loop_seconds < 1)
        loop_seconds = 2;

    return do_parent(argv[0], loop_seconds);
}
