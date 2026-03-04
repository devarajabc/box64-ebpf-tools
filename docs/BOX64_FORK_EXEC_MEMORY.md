# How Fork, Exec, and Memory Work in Box64

This document provides a detailed technical reference for box64's process lifecycle
(fork, exec, clone) and memory management systems. All source references include
file paths and line numbers.

---

## Table of Contents

1. [Overview: Multi-Process Model](#1-overview-multi-process-model)
2. [How Fork Works](#2-how-fork-works)
3. [How vfork Works](#3-how-vfork-works)
4. [How forkpty Works](#4-how-forkpty-works)
5. [How execve Works](#5-how-execve-works)
6. [How clone / pthread_create Works](#6-how-clone--pthread_create-works)
7. [Memory: Custom Allocator](#7-memory-custom-allocator)
8. [Memory: DynaRec JIT](#8-memory-dynarec-jit)
9. [Memory: Guest mmap](#9-memory-guest-mmap)
10. [Memory: Context and Stack](#10-memory-context-and-stack)
11. [Memory: Protection System](#11-memory-protection-system)
12. [Pressure-Vessel Steam Container](#12-pressure-vessel-steam-container)
13. [Tracing with box64_steam.py](#13-tracing-with-box64_steampy)

---

## 1. Overview: Multi-Process Model

Box64 is a Linux x86_64 emulator. When an emulated program calls `execve()` on
another x86_64 binary, box64's wrapped `execve` prepends `box64` to the argv
and calls the real `execve`. This replaces the current process with a **fresh
box64 instance** — not a fork, but a complete process image replacement.

When running Steam, this creates 5-10+ concurrent box64 processes:

```
[Terminal] $ box64 steam
    │
    ├─ box64 #1: Steam Client (core.c:945 sets box64_steam=1)
    │   ├─ fork+exec → box64 #2: steamwebhelper (Chromium UI)
    │   │   ├─ fork+exec → box64 #3: steamwebhelper (renderer)
    │   │   ├─ fork+exec → box64 #4: steamwebhelper (renderer)
    │   │   └─ fork+exec → box64 #5: steamwebhelper (gpu)
    │   │
    │   ├─ fork+exec → box64 #6: steam-runtime-launcher-service
    │   │
    │   └─ fork+exec → box64 #7: pressure-vessel-wrap (TRANSIENT)
    │       └─ vfork+exec → box64 #8: game binary (full emulation)
    │           ├─ fork+exec → box64 #9: (game child)
    │           └─ ...
```

Each instance is independent: own `box64context_t`, own custom allocator state,
own DynaRec JIT cache. They share nothing except the kernel's CoW page mappings
inherited from `fork()`.

---

## 2. How Fork Works

Guest code calling `fork()` goes through a **deferred fork** mechanism. The fork
does not happen immediately — it is deferred until the emulator reaches a safe
state boundary.

### Call Chain

```
Guest x86 code calls fork()
    │
    ▼
libc wrapper resolves to my_fork()
(src/wrapped/wrappedlibc.c:657)
    │
    │  Sets emu->quit = 1
    │  Sets emu->fork = 1
    │  Returns 0 (but this is NOT the real fork return value)
    │
    ▼
Interpreter/DynaRec main loop detects emu->quit
    │
    │  Exits current run loop
    │
    ▼
Exit trampoline checks emu->fork != 0
    │
    ▼
Calls x64emu_fork(emu, forktype=1)
(src/emu/x64int3.c:40)
    │
    ├─ 1. Run pthread_atfork() PREPARE handlers (reverse order)
    │
    ├─ 2. Call real fork() system call
    │     │
    │     ├─ Parent process (fork returns child_pid):
    │     │   ├─ Run atfork PARENT handlers
    │     │   └─ Set R_EAX = child_pid
    │     │
    │     └─ Child process (fork returns 0):
    │         ├─ Run atfork CHILD handlers
    │         └─ Set R_EAX = 0
    │
    └─ Both: continue emulation from where emu->quit was set
```

### Why Deferred?

The fork is deferred to ensure the emulator state is consistent. If `fork()` were
called mid-instruction-decode or mid-wrapper, the child process would inherit a
partially modified emulator state, leading to corruption. By deferring to the
main loop boundary, both parent and child have a clean, consistent state.

### Source References

- `my_fork()`: `src/wrapped/wrappedlibc.c:657`
- `my___fork()` (alias): `src/wrapped/wrappedlibc.c:691`
- `x64emu_fork()`: `src/emu/x64int3.c:40`
- `__register_atfork()`: `src/wrapped/wrappedlibc.c:2920`
- Fork type constants: `1`=fork, `2`=forkpty, `3`=vfork

---

## 3. How vfork Works

```c
// src/wrapped/wrappedlibc.c:692
pid_t EXPORT my_vfork(x64emu_t* emu) {
    emu->quit = 1;
    emu->fork = 3;  // vfork type
    return 0;
}
```

Same deferred mechanism as `fork`, but `forktype == 3` triggers different
behavior in `x64emu_fork`:

```
x64emu_fork(emu, forktype=3):
    1. Run atfork prepare handlers
    2. Call real fork()
    3. Parent:
       ├─ Run atfork parent handlers
       └─ Call waitpid(child_pid, &status, 0)  ← BLOCKS here
          (simulates vfork: parent waits until child exits or execs)
    4. Child:
       ├─ Run atfork child handlers
       └─ Set R_EAX = 0, continue execution
```

This simulates vfork semantics where the parent blocks until the child calls
`exec` or `_exit`. In box64's implementation, a real `fork()` is used (not
`vfork()`), but the parent immediately `waitpid()`s for the child, achieving the
same blocking behavior.

---

## 4. How forkpty Works

```c
// src/wrapped/wrappedutil.c:23
pid_t EXPORT my_forkpty(x64emu_t* emu, void* amaster, void* name,
                         void* termp, void* winp) {
    emu->fork = 2;
    emu->forkpty_info = {amaster, name, termp, winp};
    emu->quit = 1;
    return 0;
}
```

When `forktype == 2`, `x64emu_fork` calls native `forkpty()` instead of `fork()`,
passing the saved terminal parameters. This creates a pseudo-terminal pair and
forks, used by programs that need a PTY (like terminal emulators).

---

## 5. How execve Works

When emulated code calls `execve()`, box64 intercepts it to prepend the
appropriate emulator:

```
Guest calls execve(path, argv, envp)
    │
    ▼
my_execve(emu, path, argv, envp)
(src/wrapped/wrappedlibc.c:2548)
    │
    ├─ FileIsX64ELF(path)?
    │   YES → execve(box64_path, ["box64", path, args...], envp)
    │
    ├─ FileIsX86ELF(path)?
    │   YES → execve(box86_path, ["box86", path, args...], envp)
    │
    ├─ FileIsShell(path)?
    │   YES → execve(bash_path, ["bash", path, args...], envp)
    │
    ├─ FileIsPython(path)?
    │   YES → execve(python_path, ["python3", path, args...], envp)
    │
    └─ None of the above?
        → execve(path, argv, envp)  // native passthrough
```

### Special Cases

| Case | Behavior |
|------|----------|
| `wine64-preloader` | Detected and handled specially |
| `/proc/self/exe` | Redirected to the actual x86 binary, not box64 |
| `uname` | Faked to report x86_64 architecture |
| `cat /proc/cpuinfo` | Faked to show x86 CPU info |
| `grep /proc/cpuinfo` | Faked similarly |

### Process Replacement

After `execve` succeeds, the **kernel completely replaces** the current process
image. The new box64 instance:

1. Starts from `main()` in `src/core.c`
2. Creates a **new** `box64context_t` via `NewBox64Context()`
3. Allocates a **new** stack via `CalcStackSize()`
4. Initializes a **new** custom allocator via `init_custommem_helper()`
5. Creates a **new** DynaRec JIT cache
6. Loads the target ELF and begins emulation

Nothing is shared with the previous process image — it is a complete restart.

### All exec Variants

| Function | File | Line | Notes |
|----------|------|------|-------|
| `my_execv` | `wrappedlibc.c` | 2502 | No envp |
| `my_execve` | `wrappedlibc.c` | 2548 | Full version |
| `my_execvp` | `wrappedlibc.c` | 2663 | PATH-searching |
| `my_execvpe` | `wrappedlibc.c` | 2722 | PATH-searching + envp |
| `my_execl` | `wrappedlibc.c` | 2776 | Variadic, delegates to `my_execv` |
| `my_execle` | `wrappedlibc.c` | 2789 | Variadic + envp |
| `my_execlp` | `wrappedlibc.c` | 2804 | Variadic + PATH |
| `my_posix_spawn` | `wrappedlibc.c` | 2817 | Spawn without replacing current process |
| `my_posix_spawnp` | `wrappedlibc.c` | 2856 | PATH-searching spawn |

---

## 6. How clone / pthread_create Works

### Syscall-Level Clone

The `sys_clone` syscall (case 56 in `src/emu/x64syscall.c`) creates a new thread
or process:

```
x64Syscall_linux case 56 (sys_clone):
    │
    ├─ Allocate new x64emu_t via NewX64Emu()
    │
    ├─ Create clone_t struct:
    │   { .emu = new_emu,
    │     .stack_to_free = child_stack_ptr,
    │     .tls = tls_addr }
    │
    ├─ Call native clone(clone_fn_syscall, child_stack, flags, &clone_args)
    │
    └─ clone_fn_syscall runs in NEW thread:
        (src/emu/x64syscall.c:445, STATIC function)
        │
        ├─ thread_set_emu(new_emu)
        ├─ DynaRun(new_emu)        ← emulation starts
        ├─ Free emu on exit
        └─ _exit(return_value)
```

### Wrapper-Level pthread_create

When emulated code calls `pthread_create()`:

```
my_pthread_create(emu, thread_ptr, attr, start_routine, arg)
    │
    ├─ Create emuthread_t struct:
    │   { .fnc = start_routine,     ← x86_64 function pointer
    │     .arg = arg }
    │
    ├─ Call native pthread_create(thread_ptr, attr, pthread_routine, emuthread)
    │
    └─ pthread_routine runs in NEW thread:
        (src/wrapped/wrappedlibc.c)
        │
        ├─ Read x86 start routine from emuthread->fnc
        ├─ Create new x64emu_t
        ├─ Set up emulated registers (RDI=arg, RIP=start_routine)
        ├─ DynaRun(emu)             ← emulation starts
        └─ Return value from emulated function

    Thread cleanup via TLS destructor:
        emuthread_destroy()          ← fires when thread exits
```

### Key Difference from Fork

- **Fork**: Creates a complete copy of the process (CoW pages). Child inherits
  ALL emulator state. Box64's deferred fork ensures clean state at fork point.
- **Clone/pthread_create**: Creates a new thread sharing the same address space.
  A **new** `x64emu_t` is allocated for the thread, but memory (custom allocator
  pool, DynaRec cache) is shared with the parent thread.

---

## 7. Memory: Custom Allocator

Box64 uses its own heap allocator instead of libc `malloc`. Located in
`src/custommem.c`.

### Public API

| Function | File:Line | Signature |
|----------|-----------|-----------|
| `customMalloc` | `custommem.c:988` | `void* customMalloc(size_t size)` |
| `customFree` | `custommem.c:1127` | `void customFree(void* p)` |
| `customCalloc` | `custommem.c:997` | `void* customCalloc(size_t n, size_t size)` |
| `customRealloc` | `custommem.c:1062` | `void* customRealloc(void* p, size_t size)` |
| `customMalloc32` | `custommem.c:992` | 32-bit variant (sub-4GB addresses) |
| `customFree32` | `custommem.c:1131` | 32-bit variant |

### Three-Tier Allocation Strategy

All allocations go through `internal_customMalloc(size, is32bits)` at line 848:

```
                    ┌──────────────────────────────────┐
                    │       customMalloc(size)          │
                    │       customCalloc(n, size)       │
                    │       customRealloc(ptr, size)    │
                    └───────────────┬──────────────────┘
                                    │
                        internal_customMalloc(size, 0)
                                    │
                    ┌───────────────┼──────────────────┐
                    │               │                  │
            size <= 64 B     size <= 128 B        size > 128 B
                    │               │                  │
                    ▼               ▼                  ▼
          ┌─────────────┐  ┌──────────────┐  ┌────────────────┐
          │  Tier 1:    │  │  Tier 2:     │  │  Tier 3:       │
          │  64-byte    │  │  128-byte    │  │  Linked-list   │
          │  slab       │  │  slab        │  │  allocator     │
          │             │  │              │  │                │
          │  Bitmap     │  │  Bitmap      │  │  Free-list in  │
          │  allocator  │  │  allocator   │  │  each backing  │
          │  64B slots  │  │  128B slots  │  │  block         │
          │             │  │              │  │                │
          │  Backing:   │  │  Backing:    │  │  Backing:      │
          │  64KB pages │  │  128KB pages │  │  1-4MB blocks  │
          │  (InternalM │  │  (InternalM  │  │  (InternalMmap)│
          │   map)      │  │   map)       │  │                │
          └─────────────┘  └──────────────┘  └────────────────┘
```

**Tier 1 — 64-byte slab** (`map64_customMalloc`, line 720):
- Fixed 64-byte slots with bitmap tracking
- Each slab is 64KB allocated via `InternalMmap`
- Bitmap at the end of the slab tracks free/used slots
- Scanned linearly from `lowest` hint for fast allocation

**Tier 2 — 128-byte slab** (`map128_customMalloc`, line 588):
- Same bitmap approach, 128-byte slots
- Each slab is 128KB

**Tier 3 — Linked-list** (BTYPE_LIST):
- For allocations > 128 bytes
- Free blocks maintained as doubly-linked list within each backing block
- New backing blocks: 1MB (`ALLOCSIZE`) or 4MB, allocated via `InternalMmap`

### Block Lookup on Free

When `customFree(ptr)` is called, box64 needs to find which backing block owns
the pointer. This is done via `blockstree`, a **red-black tree** that maps
address ranges to block indices. Lookup is O(log n).

```c
// src/custommem.c — simplified
void customFree(void* p) {
    internal_customFree(p, 0);
}

static void internal_customFree(void* p, int is32bits) {
    mutex_lock(&mutex_blocks);
    int idx = findBlock(p);  // ← rbtree lookup in blockstree
    if (idx >= 0) {
        // Found: free from the appropriate tier
        p_blocks[idx].type == BTYPE_MAP64 ? clear_bitmap_bit(...)
        p_blocks[idx].type == BTYPE_MAP   ? clear_bitmap_bit(...)
        p_blocks[idx].type == BTYPE_LIST  ? unlink_from_freelist(...)
    }
    mutex_unlock(&mutex_blocks);
}
```

### Thread Safety

All custom allocator operations are protected by `mutex_blocks`. This means
threads within the same box64 process serialize on allocation/free. Different
box64 processes have independent allocator states.

---

## 8. Memory: DynaRec JIT

The DynaRec (Dynamic Recompiler) translates x86_64 instructions into native ARM64
(or RISC-V/LoongArch) code at runtime. The translated code needs executable memory.

### JIT Block Allocation

```c
// src/custommem.c:1663
uintptr_t AllocDynarecMap(uintptr_t x64_addr, size_t size, int is_new)
```

```
AllocDynarecMap(x64_addr, size, is_new)
    │
    ├─ Look up mmaplist_t for x64_addr's region
    │   (locality-aware: JIT blocks near same x64 code share chunks)
    │
    ├─ Scan existing chunks in mmaplist for free space
    │   │
    │   ├─ Found free block → return it
    │   │
    │   └─ No free space:
    │       ├─ If BOX64_DYNAREC_PURGE set: try PurgeDynarecMap()
    │       │   (evict cold blocks to reclaim space)
    │       │
    │       └─ Allocate new chunk via InternalMmap():
    │           Size: DYNMMAPSZ = 2MB (default)
    │           Flags: MAP_PRIVATE | MAP_ANONYMOUS
    │           Prot: PROT_READ | PROT_WRITE | PROT_EXEC
    │           + madvise(MADV_HUGEPAGE) for TLB efficiency
    │
    └─ Return native address for JIT code
```

### JIT Block Free

```c
// src/custommem.c:1771
void FreeDynarecMap(uintptr_t addr)
```

Returns the block to the chunk's free list. Lookup via `rbt_dynmem` red-black
tree (maps native address ranges to `blocklist_t*`).

### Code Protection (Self-Modifying Code Detection)

```
Guest writes to address that has JIT translations
    │
    ▼
protectDB(addr, size)               ← called when JIT block is created
(src/custommem.c:2267)
    │
    ├─ mprotect(addr, size, PROT_READ)  ← remove PROT_WRITE
    │
    └─ Now any write to this page triggers SIGSEGV
        │
        ▼
    SIGSEGV handler detects write to protected page
        │
        ▼
    unprotectDB(addr, size, mark=1)
    (src/custommem.c:2318)
        │
        ├─ mprotect(addr, size, PROT_READ | PROT_WRITE)
        ├─ cleanDBFromAddressRange(addr, size, destroy=1)
        │   └─ Mark/destroy overlapping JIT blocks as invalid
        └─ Next execution of that x86 code will retranslate
```

On systems with large pages (e.g., 16KB ARM64 pages on Asahi Linux), a single
host page may contain both code and data. `protectDB` handles this by checking
for mixed code/data pages and using `PROT_NEVERCLEAN` (always-test mode) instead
of mprotecting, to avoid breaking kernel `read()` calls on the page.

### Purge (Memory Pressure)

```c
// src/custommem.c:1622
int PurgeDynarecMap(mmaplist_t* list, size_t size)
```

When JIT memory is exhausted, `PurgeDynarecMap` evicts "cold" blocks — blocks
that haven't been executed recently, determined by tick/speed counters.

---

## 9. Memory: Guest mmap

When x86 guest code calls `mmap()`, it goes through a multi-layer wrapper chain:

```
Guest x86 code calls mmap(addr, length, prot, flags, fd, offset)
    │
    ▼
Intercepted mmap symbol in box64
(src/custommmap.c:36)
    │
    ▼
box_mmap(addr, length, prot, flags, fd, offset)
(src/custommem.c:3287)
    │
    ├─ MAP_32BIT flag set?
    │   YES → find31bitBlockNearHint(length)
    │         (find suitable address in low 2GB/4GB range)
    │
    ├─ Regular mapping?
    │   → Restrict to 47-bit address space (wine compatibility)
    │   → find47bitBlock(length) or find47bitBlockElf(length)
    │
    ▼
InternalMmap(addr, length, prot, flags, fd, offset)
(src/os/os_linux.c:163)
    │
    │  syscall(__NR_mmap, addr, length, prot, flags, fd, offset)
    │  (direct kernel syscall, bypasses libc)
    │
    ▼
After successful mapping:
    setProtection*(addr, length, prot)
    (records the mapping in mapallmem + memprot rbtrees)
```

### InternalMmap vs box_mmap

| Function | Purpose | Caller |
|----------|---------|--------|
| `InternalMmap` | Direct kernel mmap. Used for ALL box64 internal allocations. | Custom allocator, DynaRec, stack, etc. |
| `box_mmap` | Guest-facing mmap wrapper. Translates x86 mmap flags. | Emulated `mmap()` calls |
| `InternalMunmap` | Direct kernel munmap. | Corresponding unmaps |
| `box_munmap` | Guest-facing munmap wrapper. | Emulated `munmap()` calls |

### Address Space Restrictions

Box64 carefully manages the address space to maintain x86 compatibility:

- **31-bit range** (< 2GB): For `MAP_32BIT` flag (used by some x86 programs)
- **47-bit range** (< 128TB): For wine compatibility (x86_64 has 48-bit virtual addresses, but the top bit is sign-extended, so usable range is 47 bits)
- **High memory reservation**: `reserveHighMem()` maps `MAP_NORESERVE` regions above 47 bits to prevent the kernel from handing out addresses that confuse x86 programs

---

## 10. Memory: Context and Stack

### Context Creation

```c
// src/box64context.c:163
box64context_t *NewBox64Context(int argc)
```

Called once per box64 process. Creates and initializes:

```
NewBox64Context(argc):
    │
    ├─ init_custommem_helper(ctx)    ← initialize custom allocator
    │   ├─ Initialize blockstree, memprot, mapallmem rbtrees
    │   ├─ Initialize mutex_blocks
    │   ├─ Set up jump tables (for DynaRec)
    │   ├─ Register atfork_child_custommem handler
    │   ├─ loadProtectionFromMap()   ← read /proc/self/maps
    │   └─ reserveHighMem()          ← reserve high address space
    │
    ├─ Create librarian (symbol resolution)
    ├─ Create bridge (native ↔ emulated function call bridge)
    ├─ Create vsyscall stubs
    ├─ Create dlprivate (dlopen/dlsym state)
    ├─ Allocate argv array
    └─ Register atfork_child_box64context handler
```

### Stack Allocation

```c
// src/tools/box64stack.c:18
int CalcStackSize(box64context_t *context)
```

```
CalcStackSize(context):
    │
    ├─ Read stack size from ELF PT_GNU_STACK header
    │   (default: 8 MB if no PT_GNU_STACK)
    │
    ├─ mmap(NULL, stacksz,
    │       PROT_READ | PROT_WRITE,
    │       MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, ...)
    │
    ├─ setProtection_stack(addr, stacksz, prot)
    │   (record in mapallmem as MEM_STACK)
    │
    └─ Store pointer in context->stack
```

### Initial Stack Layout

`SetupInitialStack()` (`src/tools/box64stack.c:53`) pushes the complete initial
stack frame that an x86_64 binary expects:

```
High address (stack top)
    ┌──────────────────────────┐
    │  Strings area            │  argv[0], argv[1], ..., envp[0], ...
    ├──────────────────────────┤
    │  Random bytes (16 bytes) │  AT_RANDOM points here
    ├──────────────────────────┤
    │  Padding / alignment     │
    ├──────────────────────────┤
    │  Auxiliary vector        │  AT_PHDR, AT_ENTRY, AT_HWCAP, etc.
    │  (null-terminated)       │  AT_RANDOM, AT_PAGESZ, AT_NULL
    ├──────────────────────────┤
    │  envp[n] = NULL          │
    │  envp[n-1]               │  Pointers to env strings above
    │  ...                     │
    │  envp[0]                 │
    ├──────────────────────────┤
    │  argv[argc] = NULL       │
    │  argv[argc-1]            │  Pointers to arg strings above
    │  ...                     │
    │  argv[0]                 │
    ├──────────────────────────┤
    │  argc                    │
    └──────────────────────────┘
Low address (RSP points here at program entry)
```

### Context Destruction

```c
// src/box64context.c:285
void FreeBox64Context(box64context_t** context)
```

Guards against premature free via a `forked` counter (after fork, both parent
and child have references to the same context; the counter tracks this). Frees:

1. Video memory
2. All ELF headers (triggering their destructors)
3. All loaded libraries
4. Bridge
5. Librarians
6. TLS data
7. Atfork callback list
8. Rolling logs
9. Calls `fini_custommem_helper()` — frees all custom memory blocks, destroys rbtrees

---

## 11. Memory: Protection System

Box64 tracks every memory mapping in two red-black trees:

### mapallmem — Region Type Tracking

Tracks all mapped regions with their type:

| Type | Meaning | Set by |
|------|---------|--------|
| `MEM_ALLOCATED` | Custom allocator backing block | `setProtection()` |
| `MEM_MMAP` | Guest mmap | `setProtection_mmap()` |
| `MEM_BOX` | Internal box64 allocation | `setProtection_box()` |
| `MEM_STACK` | Emulated stack | `setProtection_stack()` |
| `MEM_ELF` | ELF segment mapping | `setProtection_elf()` |
| `MEM_EXTERNAL` | Existing kernel mapping | `allocProtection()` |

### memprot — Per-Page Protection Bits

Tracks protection bits for every mapped page. Used by the DynaRec system to:

1. Know which pages are write-protected (have JIT translations)
2. Detect when a page's protection changes via `mprotect`
3. Apply `PROT_DYNAREC` flag to prevent write access to JIT-translated code

### Initialization

```c
// src/custommem.c:2746
void loadProtectionFromMap()
```

Called at startup by `init_custommem_helper()`. Reads `/proc/self/maps` line by
line and populates both `mapallmem` and `memprot` with the initial process
memory layout. Also detects whether 48-bit addresses are available (`have48bits`).

### Protection Flow

```
setProtection(addr, size, prot)     ← called after every mmap/mprotect
    │
    ├─ rb_set(mapallmem, addr, size, MEM_ALLOCATED)
    └─ rb_set(memprot, addr, size, prot)

updateProtection(addr, size, prot)  ← called when guest does mprotect()
    │
    ├─ If PROT_DYNAREC is set on the page:
    │   └─ Strip PROT_WRITE (prevent guest from writing to JIT code)
    └─ rb_set(memprot, addr, size, new_prot)

freeProtection(addr, size)          ← called on munmap
    │
    ├─ rb_unset(mapallmem, addr, size)
    └─ rb_unset(memprot, addr, size)
```

---

## 12. Pressure-Vessel Steam Container

When Steam launches a game, it invokes `pressure-vessel-wrap` — a container
setup tool. Box64 intercepts this entirely.

### Detection

```c
// src/core.c:974-981
if (!strcmp(prog_, "pressure-vessel-wrap")) {
    printf_log(LOG_INFO, "pressure-vessel-wrap detected\n");
    pressure_vessel(argc, argv, nextarg+1, prog);
    // pressure_vessel() never returns — it calls exit(0)
}
```

This check happens **after** `NewBox64Context()` but **before** any ELF loading.
The `pressure_vessel()` function runs pure native C code — it never emulates
any x86 instructions.

### What pressure_vessel() Does

```c
// src/steam.c:65
void pressure_vessel(int argc, const char** argv, int nextarg, const char* prog)
```

```
pressure_vessel(argc, argv, nextarg, prog):
    │
    ├─ Parse 4 of ~40 arguments:
    │   ├─ --env-if-host=PRESSURE_VESSEL_APP_LD_LIBRARY_PATH=X
    │   ├─ --env-if-host=STEAM_RUNTIME_LIBRARY_PATH=X
    │   ├─ --ld-preloads=X
    │   └─ -- (end of options, rest is the game command)
    │
    ├─ Set up environment:
    │   ├─ BOX64_LD_LIBRARY_PATH = /lib/x86_64-linux-gnu:...:X
    │   ├─ BOX86_LD_LIBRARY_PATH = /lib/box86:...:X
    │   ├─ BOX64_LD_PRELOAD = preload_libs
    │   ├─ BOX86_LD_PRELOAD = preload_libs
    │   ├─ LD_LIBRARY_PATH = sniper_runtime_dirs
    │   ├─ XDG_DATA_DIRS = sniper_dirs
    │   └─ BOX64_PRESSURE_VESSEL_FILES = sniper_root
    │
    ├─ Create versioned library symlinks (fake ldconfig):
    │   libfoo.so.1 → libfoo.so.1.2 → libfoo.so.1.2.3
    │   in sniper runtime directories
    │
    ├─ Build new argv: ["box64", game_binary, game_args...]
    │
    ├─ vfork()
    │   ├─ Parent: FreeBox64Context() → wait() → exit(0)
    │   └─ Child: execvp("box64", new_argv)
    │
    └─ (never returns)
```

### Environment Variable Translation

| pressure-vessel-wrap argument | Box64 translation |
|------|----------|
| `--env-if-host=PRESSURE_VESSEL_APP_LD_LIBRARY_PATH=X` | `LD_LIBRARY_PATH=X` |
| `--env-if-host=STEAM_RUNTIME_LIBRARY_PATH=X` | `BOX64_LD_LIBRARY_PATH=...X` and `BOX86_LD_LIBRARY_PATH=...X` |
| `--ld-preloads=X` | `BOX64_LD_PRELOAD=X` and `BOX86_LD_PRELOAD=X` |

### What Box64 Skips

The real pressure-vessel provides extensive container isolation that box64
completely bypasses:

- Linux namespaces (mount, pid, user) — **No**
- Filesystem isolation — **No** (direct host filesystem access)
- Home directory isolation — **No** (shared home)
- Process management (subreaper) — **No**
- Graphics driver injection — **No**
- Vulkan layer management — **No**
- ld.so.cache regeneration — **No** (symlink creation instead)

This is acceptable because on ARM64, the emulation layer is the primary concern,
and container isolation is less critical.

---

## 13. Tracing with box64_steam.py

The `tools/ebpf/box64_steam.py` eBPF tool traces all of the functions described
in this document across multiple concurrent box64 processes.

### Quick Start

```bash
# Trace all box64 processes during a Steam session
sudo python3 tools/ebpf/box64_steam.py

# Custom binary path, 5-second interval
sudo python3 tools/ebpf/box64_steam.py -b ~/box64/build/box64 -i 5

# Focus on fork/exec lifecycle only (minimal overhead)
sudo python3 tools/ebpf/box64_steam.py --no-mem --no-dynarec --no-mmap
```

### What It Traces

| Category | Functions Traced | Controlled by |
|----------|-----------------|---------------|
| Fork | `my_fork`, `my_vfork`, `x64emu_fork`, `sched:sched_process_fork` | Always on |
| Exec | `my_execve`, `my_execv`, `my_execvp`, `my_execvpe`, `my_posix_spawn` | Always on |
| Context | `NewBox64Context`, `FreeBox64Context`, `CalcStackSize` | Always on |
| Steam | `pressure_vessel` | Always on |
| Memory | `customMalloc`, `customFree`, `customCalloc`, `customRealloc` | `--no-mem` |
| DynaRec | `AllocDynarecMap`, `FreeDynarecMap` | `--no-dynarec` |
| Mmap | `InternalMmap`, `InternalMunmap`, `box_mmap`, `box_munmap` | `--no-mmap` |
| Threads | `my_pthread_create`, `pthread_routine`, `emuthread_destroy`, `my_clone` | `--no-threads` |
| CoW | `wp_page_copy` kprobe + `/proc` sampling | `--no-cow` |

### Output Sections

The final report (on Ctrl+C) provides:

1. **Lifecycle totals** — fork, vfork, exec, posix_spawn, context counts
2. **Process tree** — Parent-child box64 process hierarchy with labels
3. **Fork/exec timeline** — Chronological event log with timestamps
4. **Per-PID memory breakdown** — Custom alloc, JIT, mmap stats per process
5. **Memory growth timeline** — RSS snapshots over time per PID
6. **Thread tree** — Hierarchical thread view with per-thread alloc stats
7. **CoW analysis** — Private_Dirty and page fault tracking
