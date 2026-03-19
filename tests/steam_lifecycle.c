/*
 * Multi-process x86_64 test binary to exercise Box64's fork/vfork/exec/thread
 * lifecycle tracking in box64_steam.py.
 *
 * When Box64 emulates this on ARM64, fork/vfork/execve/execvp/execv go through
 * Box64's wrapped libc (my_fork, my_vfork, my_execve, my_execvp, my_execv),
 * and pthread_create goes through my_pthread_create — triggering the
 * corresponding eBPF uprobes.
 *
 * Modes (selected by argv[1]):
 *   (none)      Parent: 10 forks (rotating exec variants), 10 vforks,
 *               4 pthreads, then hot loops.
 *   --worker    Worker: brief hot loops (~100ms), then exit.
 *
 * Process tree created:
 *   box64 steam_lifecycle                      (parent)
 *   +-- 10 fork children -> exec -> worker     (rotating execve/execvp/execv)
 *   +-- 10 vfork children -> execve -> worker
 *   +-- 4 pthreads (brief hot loops)
 *
 * Cross-compile for ARM64 CI:
 *   x86_64-linux-gnu-gcc -O1 -lpthread -o /tmp/steam_lifecycle tests/steam_lifecycle.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <pthread.h>

#define NUM_FORKS   10
#define NUM_VFORKS  10
#define NUM_THREADS  4

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

/* Run brief hot loops (~100ms) for workers and threads */
void run_hot_loops_brief(void) {
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
        long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 +
                          (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed_ms >= 100)
            break;
    }
}

/* --worker: brief hot loops then exit */
int do_worker(void) {
    printf("steam_lifecycle worker (pid=%d): running\n", getpid());
    run_hot_loops_brief();
    printf("steam_lifecycle worker (pid=%d): done\n", getpid());
    return 0;
}

/* Thread function: brief hot loops */
void *thread_fn(void *arg) {
    int id = *(int *)arg;
    printf("steam_lifecycle thread %d (pid=%d): running\n", id, getpid());
    run_hot_loops_brief();
    printf("steam_lifecycle thread %d: done\n", id);
    return NULL;
}

/* Parent mode: multiple forks, vforks, pthreads, then hot loops */
int do_parent(char *self, int loop_seconds) {
    pid_t pid;

    printf("steam_lifecycle parent (pid=%d): starting\n", getpid());

    /* --- Forks (rotating exec variants) --- */
    for (int i = 0; i < NUM_FORKS; i++) {
        pid = fork();
        if (pid < 0) {
            perror("fork");
            continue;
        }
        if (pid == 0) {
            char *argv[] = {self, "--worker", NULL};
            char *envp[] = {NULL};
            switch (i % 3) {
                case 0: execve(self, argv, envp); break;
                case 1: execvp(self, argv); break;
                case 2: execv(self, argv); break;
            }
            perror("exec failed in fork child");
            _exit(1);
        }
        printf("steam_lifecycle parent: forked child %d pid=%d (exec variant %d)\n",
               i, pid, i % 3);
        usleep(10000);  /* 10ms stagger */
    }

    /* --- Vforks --- */
    for (int i = 0; i < NUM_VFORKS; i++) {
        pid = vfork();
        if (pid < 0) {
            perror("vfork");
            continue;
        }
        if (pid == 0) {
            char *argv[] = {self, "--worker", NULL};
            char *envp[] = {NULL};
            execve(self, argv, envp);
            _exit(1);
        }
        printf("steam_lifecycle parent: vforked child %d pid=%d\n", i, pid);
        usleep(10000);  /* 10ms stagger */
    }

    /* --- Threads --- */
    pthread_t tids[NUM_THREADS];
    int targs[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        targs[i] = i;
        if (pthread_create(&tids[i], NULL, thread_fn, &targs[i]) != 0) {
            perror("pthread_create");
        }
    }

    /* Parent hot loops to generate DynaRec activity */
    printf("steam_lifecycle parent: running hot loops for %ds\n", loop_seconds);
    run_hot_loops(loop_seconds);

    /* Join threads */
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(tids[i], NULL);

    /* Wait for all child processes */
    while (wait(NULL) > 0)
        ;

    printf("steam_lifecycle parent: done\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc >= 2 && strcmp(argv[1], "--worker") == 0) {
        return do_worker();
    }

    /* Parent mode — optional duration argument */
    int loop_seconds = 2;
    if (argc >= 2)
        loop_seconds = atoi(argv[1]);
    if (loop_seconds < 1)
        loop_seconds = 2;

    return do_parent(argv[0], loop_seconds);
}
