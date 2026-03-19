# How Box64 Supports Steam v1

## Overview

Steam on non-x86 platforms (ARM64, RISC-V, LoongArch) requires special handling because Steam's runtime infrastructure assumes an x86_64 host. Box64 provides a **shim** that intercepts Steam's container setup tool (`pressure-vessel-wrap`), extracts the essential environment configuration, and directly launches games under emulation — completely bypassing the container machinery.

This document cross-references box64's implementation (`src/steam.c`) with the real pressure-vessel source code (`steam-runtime-tools/pressure-vessel/`).

---

## Part 1: Architecture Overview

### 1. What is pressure-vessel?

Pressure-vessel is Steam's container runtime. When Steam launches a game, it doesn't run the game binary directly — it invokes `pressure-vessel-wrap`, which sets up an isolated container using a Flatpak-derived approach.

**The real pressure-vessel is a 3-stage pipeline:**

```
Stage 1: pressure-vessel-wrap
    Parses ~40 command-line options (--env-if-host, --runtime, --ld-preloads, etc.)
    Discovers the "sniper" runtime (Steam Runtime 3, based on Debian 11)
    Configures bwrap (bubblewrap) container settings
    Builds final argv combining: bwrap + pv-adverb + game command
    Replaces itself via execve(bwrap, ...)
        │
        ▼
Stage 2: bwrap (bubblewrap)
    Creates Linux namespaces (mount, pid, user, ipc)
    Bind-mounts /usr from the sniper runtime into the container
    Isolates the home directory (~/.var/app/com.steampowered.AppNNN/)
    Execs pv-adverb inside the container
        │
        ▼
Stage 3: pv-adverb
    Acts as process manager (subreaper, signal forwarding)
    Regenerates ld.so.cache for the container
    Sets up LD_LIBRARY_PATH within the container
    Manages LD_PRELOAD modules
    Execs the actual game binary as a child process
        │
        ▼
Game binary runs inside the container
```

**Source references (steam-runtime-tools):**
- `pressure-vessel/wrap.c:1334` — `pv_bwrap_execve(final_argv, ...)` replaces the process with bwrap
- `pressure-vessel/bwrap.c:122` — `execve(bwrap->argv->pdata[0], ...)` is the actual execve call
- `pressure-vessel/adverb.c:809` — `process_manager_options.subreaper = ...` enables subreaper mode

### 2. What Box64 Does Instead

Box64 completely bypasses the container. When it detects that the program being run is named `pressure-vessel-wrap`, it never loads it as an ELF binary. Instead, it calls a native C function (`pressure_vessel()`) that:

1. Parses only the arguments it cares about (4 out of ~40)
2. Translates Steam's environment variables into box64-compatible equivalents
3. Sets up library paths pointing to the sniper runtime's files
4. Creates versioned library symlinks (acting as a fake `ldconfig`)
5. Directly `vfork()` + `execvp()` the game binary with `box64` prepended

```
box64 pressure-vessel-wrap [40+ options] -- game_binary
    │
    ▼
core.c detects "pressure-vessel-wrap" by name (line 975)
    │
    ▼
Calls pressure_vessel() in steam.c — NO ELF loading
    │
    ├─ Parses: --env-if-host=PRESSURE_VESSEL_APP_LD_LIBRARY_PATH=...
    ├─ Parses: --env-if-host=STEAM_RUNTIME_LIBRARY_PATH=...
    ├─ Parses: --ld-preloads=...
    ├─ Parses: -- (end of options)
    ├─ Ignores: all other 36+ options
    │
    ├─ Sets BOX64_LD_LIBRARY_PATH, BOX86_LD_LIBRARY_PATH
    ├─ Sets BOX64_LD_PRELOAD, BOX86_LD_PRELOAD
    ├─ Creates lib symlinks in sniper runtime directories
    ├─ Sets LD_LIBRARY_PATH with sniper + box64 native paths
    ├─ Sets BOX64_PRESSURE_VESSEL_FILES to sniper root
    │
    └─ vfork() + execvp("box64", ["box64", game_binary, args...])
```

**This is a deliberate trade-off**: box64 sacrifices all container isolation in exchange for simplicity. On ARM64, the emulation layer is the primary concern, and the container isolation that pressure-vessel provides is less critical when the entire userspace is already being translated.

### 3. The Multi-Process Re-invocation Model

A key difference from normal executable emulation: **Steam causes box64 to re-invoke itself multiple times as separate processes**.

#### How it works

When an emulated x86_64 program calls `execve()` on another x86_64 binary, box64's wrapped `execve()` intercepts the call:

```c
// Simplified from wrappedlibc.c my_execve()
int x64 = FileIsX64ELF(path);
int x86 = FileIsX86ELF(path);

if (x64 || x86) {
    newargv[0] = x86 ? box86path : box64path;  // prepend emulator
    newargv[1] = path;                           // original binary
    execve(newargv[0], newargv, envp);           // NEW box64 process
}
```

Each `execve()` of an x86_64 ELF **replaces the current process** with a fresh `box64` instance. This is not a fork — it's a complete process replacement. The new box64 instance starts from `main()`, loads the target ELF, and begins emulation from scratch.

#### How fork() works inside emulation

The emulated `fork()` is **deferred**, not executed immediately:

```
Emulated code calls fork()
    → my_fork() sets emu->fork = 1, emu->quit = 1
    → Interpreter/dynarec loop detects emu->fork flag
    → Calls x64emu_fork() at a safe emulator state boundary
    → x64emu_fork() executes:
        1. Runs pthread_atfork prepare handlers
        2. Calls real fork() system call
        3. Parent: runs atfork parent handlers
        4. Child: runs atfork child handlers
        5. Both: continue emulation with return value in EAX
```

This deferred approach ensures the emulator state is consistent at the fork point.

### 4. Process Tree for a Steam Gaming Session

```
[Terminal] $ steam
    │
    ▼
┌──────────────────────────────────────────────────────┐
│  box64 instance #1 — Steam Client                    │
│  (core.c:945 sets box64_steam=1)                     │
│                                                      │
│  Steam binary runs under emulation.                  │
│  It internally calls fork()+exec() for each          │
│  subprocess. Each exec goes through my_execve()      │
│  which prepends "box64" to x86_64 targets.           │
│                                                      │
│  Subprocess launches:                                │
│   ├─ fork+exec("steamwebhelper") ────────────────────┼──► box64 #2 (Steam UI / Chromium)
│   │                                                  │      ├─ fork+exec(renderer) ──► box64 #3
│   │                                                  │      ├─ fork+exec(renderer) ──► box64 #4
│   │                                                  │      └─ fork+exec(gpu)      ──► box64 #5
│   │                                                  │
│   ├─ fork+exec("steam-runtime-launcher-service") ────┼──► box64 #6
│   │                                                  │
│   └─ fork+exec("pressure-vessel-wrap"                │
│        --env-if-host=STEAM_RUNTIME_LIBRARY_PATH=...  │
│        --env-if-host=PRESSURE_VESSEL_APP_LD_...      │
│        --ld-preloads=...                             │
│        -- /path/to/game_binary)                      │
│                                                      │
└──────────────────────┬───────────────────────────────┘
                       │
                       │ my_execve() detects x86_64 ELF
                       │ prepends "box64"
                       ▼
┌──────────────────────────────────────────────────────┐
│  box64 instance #7 — pressure-vessel-wrap shim       │
│  (core.c:975 detects name, calls pressure_vessel())  │
│                                                      │
│  This instance NEVER emulates x86 code.              │
│  It runs pure native C code in steam.c:              │
│   1. Parse args, extract env vars                    │
│   2. Set up library paths from sniper runtime        │
│   3. Create symlinks for versioned .so files         │
│   4. vfork()                                         │
│      ├─ Parent: wait() → exit(0)                     │
│      └─ Child: execvp("box64", game_binary)          │
│                                                      │
└──────────────────────┬───────────────────────────────┘
                       │
                       │ execvp starts fresh box64
                       ▼
┌──────────────────────────────────────────────────────┐
│  box64 instance #8 — Game Binary                     │
│  Inherits all env vars set by the shim:              │
│   - BOX64_LD_LIBRARY_PATH (sniper + box64 native)    │
│   - LD_LIBRARY_PATH (sniper runtime dirs)            │
│   - BOX64_PRESSURE_VESSEL_FILES (sniper root)        │
│                                                      │
│  Game runs under full emulation (dynarec + interp).  │
│  May spawn its own child processes:                  │
│   ├─ fork+exec(audio_server) ──► box64 #9            │
│   ├─ fork+exec(renderer)     ──► box64 #10           │
│   └─ ...                                             │
└──────────────────────────────────────────────────────┘
```

**Typical count: 5-10+ concurrent box64 instances** during a Steam gaming session.

Note that instance #7 (the pressure-vessel-wrap shim) is **transient** — it exits immediately after its child starts. So at steady state, it's not running.

### 5. What Box64 Skips

The real pressure-vessel provides extensive container isolation that box64 completely bypasses:

| Feature | Real pressure-vessel | Box64 shim |
|---|---|---|
| Linux namespaces (mount, pid, user) | Yes, via bwrap | No |
| Filesystem isolation | Bind-mounts /usr from runtime | Direct access to host filesystem |
| Home directory isolation | `~/.var/app/com.steampowered.AppN/` | Shared home directory |
| Process management (subreaper) | pv-adverb | None |
| Signal forwarding | pv-adverb forwards signals | None |
| Graphics driver injection | graphics-provider.c | None |
| Vulkan layer management | Yes | None |
| ld.so.cache regeneration | Yes (inside container) | Symlink creation instead |
| LD_AUDIT support | Yes | None |
| Flatpak sub-sandbox support | Yes | None |
| Systemd scope creation | Yes | None |
| FEX-Emu rootfs bypass | Yes (wrap.c:136-141) | Not needed |

**Why this is acceptable**: On ARM64, the primary challenge is making x86_64 code run at all. Container isolation is a secondary concern. Box64 focuses on getting the library paths right and launching the binary under emulation.

---

## Part 2: Deep Technical Reference

### 6. Steam Detection Code Paths

#### Program Name Detection

**`src/core.c:945-950`** — Checks the basename of the program:
```c
} else if(!strcmp(prog_, "steam") ) {
    printf_log(LOG_INFO, "steam detected\n");
    box64_steam = 1;
} else if(!strcmp(prog_, "steamcmd")) {
    printf_log(LOG_INFO, "steamcmd detected\n");
    box64_steamcmd = 1;
```

These global flags (`box64_steam`, `box64_steamcmd`) are declared in `src/include/debug.h:28-29` and used throughout the codebase for Steam-specific behavior.

#### Pressure-Vessel-Wrap Interception

**`src/core.c:974-981`** — Early exit before any ELF loading:
```c
#ifndef STATICBUILD
if(!strcmp(prog_, "pressure-vessel-wrap")) {
    printf_log(LOG_INFO, "pressure-vessel-wrap detected, bashpath=%s\n", ...);
    unsetenv("BOX64_ARG0");
    if(!my_context->bashpath)
        my_context->bashpath = ResolveFile("box64-bash", &my_context->box64_path);
    pressure_vessel(argc, argv, nextarg+1, prog);
}
#endif
```

This check happens **after** `NewBox64Context()` is created (line 956) but **before** any ELF loading or emulation setup. The `pressure_vessel()` function never returns — it calls `exit(0)` in both parent and child paths.

#### The pressure_vessel() Function

**`src/steam.c:65-308`** — Complete breakdown:

| Lines | Purpose |
|---|---|
| 68 | Read `PRESSURE_VESSEL_RUNTIME` env var |
| 70-72 | Find the actual command (skip `--` prefixed args) |
| 73 | Check if command starts with `/usr/` (runtime-based) |
| 74-121 | Parse pressure-vessel-wrap arguments |
| 76-86 | Handle `--env-if-host=PRESSURE_VESSEL_APP_LD_LIBRARY_PATH=` |
| 87-103 | Handle `--env-if-host=STEAM_RUNTIME_LIBRARY_PATH=` |
| 104-115 | Handle `--ld-preloads=` |
| 116-117 | Handle `--` (end of options) |
| 123-126 | Special case: steamwebhelper skips runtime |
| 127-250 | Set up sniper runtime (paths, symlinks, env vars) |
| 136-153 | ARM64: find x86_64 python3 in runtime |
| 186-196 | Create library symlinks (fake ldconfig) |
| 197-222 | Build LD_LIBRARY_PATH |
| 224-229 | Set XDG_DATA_DIRS |
| 249 | Set BOX64_PRESSURE_VESSEL_FILES |
| 251-274 | Build new argv array (prepend box64/box86/bash) |
| 289-307 | vfork() + execvp() |

#### Fork/Exec Wrappers

**`src/wrapped/wrappedlibc.c:657-690`** — Wrapped fork:
```c
pid_t EXPORT my_fork(x64emu_t* emu) {
    emu->quit = 1;
    emu->fork = 1;  // deferred fork
    return 0;
}
```

**`src/wrapped/wrappedlibc.c:692-701`** — Wrapped vfork:
```c
pid_t EXPORT my_vfork(x64emu_t* emu) {
    emu->quit = 1;
    emu->fork = 3;  // deferred vfork (waits for child)
    return 0;
}
```

**`src/emu/x64int3.c:40-77`** — Real fork execution:
```c
x64emu_t* x64emu_fork(x64emu_t* emu, int forktype) {
    // 1. Run pthread_atfork() prepare handlers (reverse order)
    // 2. Call real fork()
    // 3. Parent: run atfork parent handlers
    //    If forktype==3 (vfork): waitpid(child)
    // 4. Child: run atfork child handlers
    // 5. Set R_EAX = fork return value
}
```

**`src/wrapped/wrappedlibc.c:2548-2659`** — Wrapped execve (re-invocation logic):
```c
int32_t my_execve(x64emu_t* emu, const char* path, ...) {
    int x64 = FileIsX64ELF(path);
    int x86 = FileIsX86ELF(path);
    int script = FileIsShell(path);
    int python = FileIsPython(path);
    if (x64 || x86 || script || python) {
        newargv[0] = x86 ? box86path : box64path;
        // ... copy args ...
        execve(newargv[0], newargv, envp);
    }
    return execve(path, argv, envp);
}
```

#### Default Configuration

**`src/tools/env.c:78-91`** — Built-in `.box64rc` defaults:
```ini
[pressure-vessel-wrap]
BOX64_NOGTK=1

[steam-runtime-launcher-service]
BOX64_NOGTK=1
```

GTK is disabled for these processes to avoid conflicts with Steam's own GTK libraries.

### 7. Environment Variable Translation

When box64 intercepts `pressure-vessel-wrap`, it translates Steam's container environment variables into box64-specific equivalents:

| pressure-vessel-wrap argument | Box64 translation |
|---|---|
| `--env-if-host=PRESSURE_VESSEL_APP_LD_LIBRARY_PATH=X` | `LD_LIBRARY_PATH=X` (strips the prefix, sets directly) |
| `--env-if-host=STEAM_RUNTIME_LIBRARY_PATH=X` | `BOX86_LD_LIBRARY_PATH=/lib/box86:/usr/lib/box86:/lib/i386-linux-gnu:...:<X>` |
| (same) | `BOX64_LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:...:<X>` |
| `--ld-preloads=X` | `BOX64_LD_PRELOAD=X` AND `BOX86_LD_PRELOAD=X` |

Additionally, the sniper runtime setup adds to `LD_LIBRARY_PATH`:
```
/usr/lib/box64-x86_64-linux-gnu
/usr/lib/box64-i386-linux-gnu
{sniper}/lib/x86_64-linux-gnu
{sniper}/lib/i386-linux-gnu
{sniper}/lib/x86_64-linux-gnu/openblas
{sniper}/lib/i386-linux-gnu/openblas
{sniper}/lib/x86_64-linux-gnu/openblas-pthread
{sniper}/lib/i386-linux-gnu/openblas-pthread
{sniper}/lib
{sniper}/lib64
{sniper}/lib32
```

### 8. Special Cases

#### steamwebhelper Bypass

**`src/steam.c:123-126`**:
```c
if(argv[nextarg] && !strcmp(argv[nextarg], "steamwebhelper")) {
    runtime = NULL;  // skip runtime setup
}
```

steamwebhelper is Steam's Chromium-based UI. When launched through pressure-vessel-wrap, box64 skips the sniper runtime setup because steamwebhelper doesn't need the full game runtime environment.

#### /etc/os-release Redirection

**`src/wrapped/wrappedlibc.c:2165-2174`**:

When `BOX64_PRESSURE_VESSEL_FILES` is set (i.e., running inside Steam's runtime), opening `/etc/os-release` is redirected to `{sniper}/lib/os-release`. This lets Steam's runtime report its own OS identity (Debian 11 "sniper") instead of the host's (e.g., Armbian).

#### Forced Emulated gnutls

**`src/core.c:427-428`**:
```c
if(getenv("BOX64_PRESSURE_VESSEL_FILES"))
    GO("libgnutls.so.30");  // force emulated version
```

When running under pressure-vessel, box64 forces the use of the emulated (x86_64) gnutls library instead of trying to use a native one, because the sniper runtime's gnutls may have different ABI expectations.

#### BOX64_STEAM_VULKAN (ARM64/LoongArch)

**`src/wrapped32/wrappedlibc.c:1958-1992`**:

When `BOX64_STEAM_VULKAN=1`, box64 detects `steamwebhelper.sh` execution and injects `--enable-features=Vulkan` into the command line. This forces Vulkan hardware acceleration for Steam's UI on platforms where it's not automatically detected.

#### steamcmd robust_list Syscall

**`src/emu/x86syscall_32.c:721-733`**:

The `get_robust_list` syscall returns a fake robust list head structure. This is needed for Steam's legacy 32-bit utilities that use robust futexes for thread-safe list management.

### 9. Cross-Reference: Real pressure-vessel vs Box64 Shim

| Aspect | Real pressure-vessel | Box64 shim |
|---|---|---|
| **Source** | `wrap.c` (1350 lines) + `runtime.c` (354KB) + 15+ support files | `steam.c` (308 lines) |
| **Arguments parsed** | ~40 options (`--runtime`, `--home`, `--filesystem`, `--graphics-provider`, etc.) | 4 patterns (`--env-if-host=` x2, `--ld-preloads=`, `--`) |
| **Container technology** | bwrap (bubblewrap) — Linux namespaces | None |
| **Process management** | pv-adverb (subreaper, signal forwarding, terminate timeout) | None |
| **Runtime setup** | Bind-mount entire `/usr` from sniper | Set `LD_LIBRARY_PATH` to sniper dirs + create symlinks |
| **Library cache** | Regenerates `ld.so.cache` inside container | Creates versioned `.so` symlinks |
| **Final execution** | `execve(bwrap_executable, final_argv, envp)` | `execvp(box64, [box64, game_binary, args...])` |
| **Execution stages** | 3 (wrap → bwrap → adverb → game) | 1 (shim → game) |
| **Home isolation** | `~/.var/app/com.steampowered.AppN/` | None (shared home) |
| **Graphics** | Injects host GPU drivers into container | None |
| **FEX-Emu awareness** | Yes (`wrap.c:136-141` bypasses FEX rootfs for bwrap paths) | Not applicable |

### 10. Library Symlink Creation (Fake ldconfig)

The real pressure-vessel regenerates `ld.so.cache` inside the container so the dynamic linker can find libraries. Box64 can't do this (no container, no access to ldconfig for the target arch), so instead it creates versioned symlinks:

**`src/steam.c:18-62`**:

For a library like `libfoo.so.1.2.3`:
1. Finds files matching `lib*.so.*.*.*` and `lib*.so.*.*`
2. Checks each is an x86/x64 ELF (not a native ARM64 lib)
3. Creates symlink: `libfoo.so.1.2` → `libfoo.so.1.2.3`
4. Then: `libfoo.so.1` → `libfoo.so.1.2`

Directories processed:
- `{sniper}/lib/x86_64-linux-gnu`
- `{sniper}/lib/i386-linux-gnu`
- `{sniper}/lib`
- `{sniper}/lib64`
- `{sniper}/lib32`

---

## Part 3: D-Bus and Its Role

### 14. What is D-Bus?

D-Bus (Desktop Bus) is a Linux inter-process communication (IPC) system. It provides a message bus where programs can:

- **Register named services** (e.g., `com.steampowered.PressureVessel.Launcher1`)
- **Call methods** on other programs (like RPC across processes)
- **Emit and listen for signals** (async notifications)

It runs as a daemon listening on a Unix socket (typically `/run/user/<uid>/bus` for the session bus). Most Linux desktop applications use D-Bus for service discovery, notifications, media controls, accessibility, and more.

### 15. D-Bus in the Real Pressure-Vessel

The real pressure-vessel uses D-Bus **centrally** for process management across the container boundary.

#### steam-runtime-launcher-service (D-Bus Daemon)

**Source**: `steam-runtime-tools/bin/launcher-service.c`

This is a D-Bus service that runs **inside** the pressure-vessel container:

```
D-Bus Interface: com.steampowered.PressureVessel.Launcher1
D-Bus Path:      /com/steampowered/PressureVessel/Launcher1

Methods:
  Launch(env, cwd, argv, fds) → pid    Fork/exec a child process
  SendSignal(pid, signal)               Send a signal to a child

Signals:
  ProcessExited(pid, wait_status)       Notifies when a child dies
```

**Why a D-Bus service?** Steam runs **outside** the container. The game runs **inside** the container. D-Bus bridges this namespace boundary — Steam can ask the launcher service to spawn and manage processes inside the container without needing direct access to the container's namespace.

#### steam-runtime-launch-client (D-Bus Client)

**Source**: `steam-runtime-tools/bin/launch-client.c`

A command-line tool that communicates with the launcher service. It can use three different D-Bus APIs depending on context:

| API | D-Bus Name | Use Case |
|---|---|---|
| Launcher | `com.steampowered.PressureVessel.Launcher1` | Standard pressure-vessel |
| Host | `org.freedesktop.Flatpak.SessionHelper` | Access host from inside Flatpak |
| Subsandbox | `org.freedesktop.portal.Flatpak` | Nested Flatpak sandbox |

#### Three D-Bus Buses Inside the Container

**Source**: `steam-runtime-tools/pressure-vessel/flatpak-run-dbus.c`

Pressure-vessel configures three D-Bus buses inside the container:

| Bus | Socket Path (inside container) | Purpose |
|---|---|---|
| Session | `/run/pressure-vessel/bus` | Application messaging, service discovery |
| System | `/run/dbus/system_bus_socket` | System services (systemd, hardware) |
| Accessibility (AT-SPI) | `/run/pressure-vessel/at-spi-bus` | Screen readers, accessibility tools |

Each is set up by bind-mounting the host's D-Bus socket into the container filesystem.

#### The Complete Real Flow

```
Steam Client (outside container)
    │
    │ D-Bus method call: Launch(game_binary, args, env)
    ▼
steam-runtime-launcher-service (inside container)
    │
    │ fork() + exec(game_binary)
    ▼
Game process (inside container)
    │
    │ (game exits)
    ▼
steam-runtime-launcher-service
    │
    │ D-Bus signal: ProcessExited(pid, status)
    ▼
Steam Client receives exit notification
```

### 16. D-Bus in Box64

Box64's involvement with D-Bus is **purely mechanical** — it wraps the library so x86_64 D-Bus calls work on ARM64.

#### Library Wrapping

**`src/wrapped/wrappeddbus_private.h`** — 235 D-Bus functions wrapped (e.g., `dbus_bus_get`, `dbus_connection_send`, `dbus_message_new_method_call`, etc.)

**`src/wrapped/wrappeddbus.c`** — The complex part: **callback bridging**. D-Bus uses 12+ callback types where the library calls back into user code asynchronously:

| Callback Type | Purpose |
|---|---|
| `DBusHandleMessageFunction` | Message filtering |
| `DBusPendingCallNotifyFunction` | Async call completion |
| `DBusAddWatchFunction` / `DBusRemoveWatchFunction` | I/O event monitoring |
| `DBusAddTimeoutFunction` / `DBusRemoveTimeoutFunction` | Timer management |
| `DBusWakeupMainFunction` | Event loop integration |
| `DBusDispatchStatusFunction` | Dispatch state changes |
| `DBusObjectPathMessageFunction` | Object path handlers |
| `DBusNewConnectionFunction` | New connection handling |
| `DBusFreeFunction` | Memory cleanup |

Each callback is an x86_64 function pointer that must be bridged to a native ARM64 trampoline. Box64 uses a slot-based lookup system (up to 8 slots per callback type) to maintain these mappings.

Box64 also wraps `dbus-glib-1` (~95 functions) for GLib D-Bus integration.

#### What Box64 Does NOT Do

Box64 does **not** intercept or modify D-Bus messages. The actual socket communication (connecting to `/run/user/<uid>/bus`, sending method calls, receiving signals) happens through the native `libdbus-1` on the host. Box64 only translates the API calls and callbacks between x86_64 and native code.

### 17. How Box64 Simplifies D-Bus Away

Since box64 bypasses the entire container, it also bypasses all D-Bus-based process management:

```
Real pressure-vessel:
  Steam ──D-Bus──► launcher-service ──fork/exec──► game (inside container)
                   ◄──D-Bus signal── ProcessExited

Box64 shim:
  Steam ──fork+exec──► pressure-vessel shim ──vfork+exec──► game (no container)
                        (steam.c, no D-Bus)     wait()
```

| D-Bus Component | Real pressure-vessel | Box64 |
|---|---|---|
| launcher-service | D-Bus daemon managing child processes | Not used — replaced by `vfork()` + `wait()` |
| launch-client | D-Bus client calling Launch() method | Not used — direct `execvp()` |
| Session bus binding | Bind-mounted into container | No container to bind into |
| System bus binding | Bind-mounted into container | No container to bind into |
| AT-SPI bus binding | Bind-mounted for accessibility | No container to bind into |
| ProcessExited signals | D-Bus async notification | Parent calls `wait()` synchronously |

#### DBUS_FATAL_WARNINGS=0

**`install_steam.sh`** sets `export DBUS_FATAL_WARNINGS=0`.

Since box64 skips the container setup that would normally configure D-Bus buses properly (bind-mounting sockets, setting bus addresses), some D-Bus operations inside Steam may emit protocol warnings. This flag prevents those warnings from becoming fatal crashes.

#### D-Bus Still Works for Steam Itself

Even though box64 bypasses D-Bus for **process management**, Steam's own internal D-Bus usage still works through the wrapped library:
- Desktop notifications
- Media key handling
- System tray integration
- Steam Input controller support

These go through box64's wrapped `libdbus-1.so.3` → native libdbus → host session bus, and work transparently.

---
