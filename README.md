# goauld

Android / arm64 dynamic instrumentation toolkit (Rust core). Named after the Goa'uld —
parasitic symbionts that take over a host.

**Version:** workspace `0.1.6` — agent/injector/host log `goauld_proto::version_info()`
(`0.1.6 (git:… built:…)`) at startup and on agent `Hello`, so logcat / attach output
shows which binary is running. The agent also logs **`sdk_int` / Android release** and
adapts String mirror decoding for API &lt; 26 vs 26+.

**Scope:** Android + AArch64 only. No x86, no ARM32, no iOS/desktop.

## Architecture

```
┌──────────────┐   adb push/shell    ┌─────────────────────────┐
│  goauld-host │ ─────────────────►  │ goauld-injector (arm64) │  ← runs ON the phone
│  (desktop)   │                     │  ptrace + remote dlopen │
└──────┬───────┘                     └───────────┬─────────────┘
       │ adb forward                             │ injects
       ▼                                         ▼
  TCP ↔ abstract socket              ┌─────────────────────────┐
                                     │ libgoauld_agent.so      │
                                     │  hooks + QuickJS + ART  │
                                     └─────────────────────────┘
```

Ptrace **must** run on-device. The desktop CLI never attaches to app processes itself;
it deploys `goauld-injector` + the agent `.so` and executes the injector as root.

## Frida, the reference

[Frida](https://frida.re/) is the instrumentation toolkit this project is measured against.
It is the mature, cross-platform reference: Stalker, Gum, a complete JS runtime, `frida-server` /
`frida-gadget`, and the ecosystem of tools and scripts people already use. goauld is a smaller
**Android / arm64 alternative** that borrows a Frida-shaped JS surface (`send`, `Interceptor`,
`Java`, `Process`, `Module`, `Memory`, `Arm64Writer`) so scripts can look familiar. It is not a
Frida replacement. If you need Frida’s coverage, platforms, or tooling, use Frida.

API gaps versus that surface are tracked in [`docs/JS_API_PARITY.md`](docs/JS_API_PARITY.md).

A single emulator snapshot (API 34, `arm64-v8a`, same script, `Date.now` median of 3) is below
so the difference is concrete. Numbers move with the build and the device; re-run
`scripts/bench-js-engines.py` rather than treating this table as a ranking. Frida 17.18.0 is
the baseline. Lower is better.

| | goauld / QuickJS | Frida 17.18.0 |
|---|---:|---:|
| Script load (session already up) | 2.6 ms | **2.0 ms** |
| Inject (adb push of injector + agent, then ptrace, every time) | 370 ms | — |
| Attach (`frida-server` already running; the 56 MB push is not included) | — | **53 ms** |
| Integer add | **48 ns/op** | 74 ns/op |
| Property get | **109 ns/op** | 147 ns/op |
| Call | **112 ns/op** | 145 ns/op |
| `readU32` | **230 ns/op** | 2.2 µs/op |
| String append | 2.7 µs/op | **1.7 µs/op** |
| Object alloc | 1.0 µs/op | **0.9 µs/op** |
| `send` | **2 µs/msg** | 14 µs/msg |
| Agent PSS at idle | **~1.6 MB** | ~6 MB |

Those two startup rows are not the same operation. goauld's 370 ms repeats the push; Frida's 53 ms is only `attach` after `frida-server` is already up. Frida stays ahead on strings and allocation, and on everything this table does not measure (other ABIs, Stalker, the CLI, existing scripts). QuickJS here is a narrower agent that, on this one device, was quicker on tight loops, memory reads, and `send`. The Symbiote engine is a second, pure-Rust backend of the same API and is still well behind both Frida and QuickJS on those loops.

## Workspace

| Crate | Role |
|---|---|
| `goauld-proto` | Wire protocol |
| `goauld-inject` | Ptrace / remote-call library (compiled into the on-device injector) |
| `goauld-injector` | **On-device** arm64 binary — inject into any process/package |
| `goauld-native-hook` | Agent: arm64 inline + GOT/PLT hooks |
| `goauld-art-bridge` | Agent: ArtMethod / JNI hooks |
| `goauld-script` | Agent: Frida-shaped JS API (QuickJS **or** Symbiote) |
| `goauld-agent` | Agent cdylib (`libgoauld_agent.so`) |
| `goauld-host` | Desktop CLI (adb orchestrator + script attach) |

Disassembler: path dependency on sibling [`arm_disassembler`](../arm_disassembler).

## Build

```bash
# Desktop host
cargo build -p goauld-host --release

# On-device arm64 artifacts (NDK — pin in ndk.txt)
./scripts/build-android.sh              # QuickJS (default)
./scripts/build-android.sh symbiote     # Symbiote (path dep: ../../symbiote)
# → dist/android-arm64/goauld-injector
# → dist/android-arm64/libgoauld_agent.so
# or:
# cargo build -p goauld-agent --no-default-features --features symbiote \
#   --release --target aarch64-linux-android
```

JS engines are **compile-time** mutually exclusive features on `goauld-script` / `goauld-agent`:

| Feature | Crate | Notes |
| --- | --- | --- |
| `quickjs` (default) | `rquickjs` | Full Frida-shaped surface + e2e fixtures |
| `symbiote` | `symbiote-core` + `symbiote-jit` | Pure-Rust engine; Process/Memory/Module/send/timers subset first |

Host smoke for both engines:

```bash
./scripts/test-js-engines.sh both    # js_engine_send_hi + js_engine_core_smoke
./scripts/test-js-engines.sh quickjs
./scripts/test-js-engines.sh symbiote
```

Emulator: rooted AVD (e.g. `Goauld_API34`, `google_apis` arm64) with `adb root` + `setenforce 0`.

```bash
./scripts/emulator.sh start          # headless
./scripts/emulator.sh start --gui
./scripts/emulator.sh stop
./scripts/emulator.sh status
```

Demo APK (used in the recipes below):

```bash
./scripts/build-java-target.sh
adb install -r testapps/java-target/build/java-target.apk
adb shell am start -n com.example.javatarget/.Target
```

## Recipes

Common pattern for script recipes: **inject** the agent, then **attach** and load a JS fixture.
Re-inject usually needs a fresh process (`am force-stop` + start again).

```bash
PKG=com.example.javatarget
INJ=dist/android-arm64/goauld-injector
SO=dist/android-arm64/libgoauld_agent.so

# 1) inject (once per process lifetime)
cargo run -p goauld-host --release -- inject \
  --package "$PKG" --injector "$INJ" --agent "$SO" --stage-into-app

PID=$(adb shell pidof -s "$PKG" | tr -d '\r')

# 2) attach + run a script (host exits when --expect-send matches; that is normal)
cargo run -p goauld-host --release -- attach \
  --pid "$PID" --port 27046 \
  --script scripts/fixtures/SOME.js \
  --expect-send SOME-OK --max-wait-secs 30
```

After `--expect-send`, the host closes the socket; logcat may show
`goauld session ended: failed to fill whole buffer` — that is expected.

### Display a toast

Framework `android.widget.Toast` (not an APK API):

```bash
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/java_toast.js \
  --expect-send toast-shown --max-wait-secs 10
```

### Trace syscalls

On-device `PTRACE_SYSCALL` (**no agent `.so`** — uses `goauld-injector` only). Prints decoded
parameters (paths for `openat`/`execve`, sockaddr for `connect`/`bind`, buffer previews for
`read`/`write`/`writev`/`sendto`/… — up to 128 bytes, text or `\xNN` escapes).

The tracer does **not** use `PTRACE_O_EXITKILL`, so ending the trace (timeout / max-events /
Ctrl-C after detach) should leave the app running. Prefer tracing a process that is **not**
already agent-injected if you only care about syscalls — combining both is supported but
heavier.

```bash
# Against a running PID (preferred “attach” form):
cargo run -p goauld-host --release -- attach syscall \
  --pid 16785 \
  --max-events 400 \
  --max-wait-secs 60

# Same via `trace` (alias: --duration-secs):
cargo run -p goauld-host --release -- trace syscalls \
  --package com.example.javatarget \
  --injector dist/android-arm64/goauld-injector \
  --duration-secs 10 \
  --filter openat,connect,write,read
```

On-device equivalent:

```bash
adb shell /data/local/tmp/goauld/goauld-injector trace-syscalls \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --duration-secs 10
```

### Trace Android / Java APIs

Hooks ART invoke stubs and emits `android-api` events for declaring-class prefixes
(default: `android.`, `androidx.`, `java.`, `javax.`, `com.android.`, `dalvik.`).
Each event includes `method`, `shorty`, and decoded `args`:

- primitives (`boolean` / `int` / `long` / `float` / `double`) as typed values
- `java.lang.String` object args as `{"t":"string","v":"…"}` (via ART `ToModifiedUtf8`)
- primitive arrays (esp. `byte[]`) as `{"t":"bytes","length":N,"v":[…],"hex":"…"}` (IPv4/IPv6 get an `ip` field)
- other object refs as compressed-ref hex: `{"t":"ref","v":"0x…"}`
- shorty comes from `ArtMethod::GetShorty` when available (more accurate than the stub register)

Covers platform / Jetpack surfaces from the
[Android API reference](https://developer.android.com/reference).
Direct AOT-to-AOT calls that never enter those stubs are not visible.

**Fresh process** (restart + inject + trace):

```bash
cargo run -p goauld-host --release -- trace java \
  --package com.example.javatarget \
  --injector dist/android-arm64/goauld-injector \
  --agent dist/android-arm64/libgoauld_agent.so \
  --stage-into-app \
  --filter 'android.,androidx.,java.,javax.,com.android.' \
  --max-events 200 \
  --max-wait-secs 20
```

**Already injected** (attach only — no inject/restart):

```bash
# after: inject --package …  (agent listening)
cargo run -p goauld-host --release -- attach java \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --max-events 200 \
  --max-wait-secs 30

# same idea via trace:
cargo run -p goauld-host --release -- trace java \
  --pid 14393 --no-inject --no-restart \
  --max-events 200 --max-wait-secs 30
```

Optional `--java-hooks` installs Technique-A `Java.use` hooks on top; each hit
`send`s `{type:"java-api", class, method, args:[…]}` with **all** JS `arguments`
(not only the first int). Example:

```bash
cargo run -p goauld-host --release -- attach java \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --java-hooks 'com.example.javatarget.Target.hookMe:(I)I' \
  --max-events 50 --max-wait-secs 20
```

Fixture: `scripts/fixtures/trace_java_api.js`.

### Inspect a running package

Dump classes / methods / fields / static values, SharedPreferences, and dataDir listing:

```bash
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/inspect_package.js \
  --expect-send inspect-ok --max-wait-secs 30
```

Optional globals before load: `__INSPECT_PREFIX`, `__INSPECT_MAX`, `__INSPECT_STATICS`, `__INSPECT_ALL`.

### Hook a Java method

```bash
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/java_hook.js \
  --expect-send java-hook-installed --max-wait-secs 10
```

Broader `Java.*` smoke: `scripts/fixtures/java_api.js` (`--expect-send java-api-ok`).

### Native Interceptor

```bash
# attach onEnter (classic)
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/interceptor_strlen.js \
  --expect-send interceptor-installed --max-wait-secs 10

# onEnter + onLeave
--script scripts/fixtures/interceptor_attach.js --expect-send interceptor-attach-ok

# replace + flush + detachAll
--script scripts/fixtures/interceptor_replace.js --expect-send interceptor-replace-ok

# combined API smoke
--script scripts/fixtures/interceptor_api.js --expect-send interceptor-api-ok
```

### Java.perform / performNow

```bash
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/java_perform.js \
  --expect-send java-perform-ok --max-wait-secs 15
```

### Arm64Writer / Arm64Relocator

Runnable recipes in `scripts/fixtures/arm64_writer_examples.js` (callable stub,
`Memory.patchCode` + writer, labels/CBZ, trampoline relocator, call-with-args):

```bash
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/arm64_writer_examples.js \
  --expect-send arm64-examples-ok --max-wait-secs 20
```

API smoke: `scripts/fixtures/arm64_writer.js` (`arm64-writer-ok`).

Minimal patterns:

```javascript
// Emit + call a stub
var code = Memory.alloc(Process.pageSize);
Memory.protect(code, Process.pageSize, 'rwx');
var w = new Arm64Writer(code);
w.putLdrRegU64(Register.x0, 99);
w.putRet();
w.flush();
// __goauld.call0(code.address) → 99

// Classic Frida patchCode + writer
Memory.patchCode(target, 16, function (code) {
  var w = new Arm64Writer(code);
  w.putInstruction((0xD2800000 | (7 << 5)) >>> 0); // MOVZ X0, #7
  w.putRet();
  w.flush();
  w.dispose();
});

// Relocate displaced instructions into a trampoline
var dstW = new Arm64Writer(trampoline);
var reloc = new Arm64Relocator(hookSite, dstW);
reloc.readOne(); reloc.writeOne();
reloc.readOne(); reloc.writeOne();
dstW.flush();
```

### Hello / Process·Module·Memory smoke

```bash
# Minimal send()
--script scripts/fixtures/hi.js --expect-send hi

# Process / Module / Memory API
--script scripts/fixtures/process_module_memory.js --expect-send ptmm-ok
```

### Host ↔ agent communication stress

```bash
./scripts/stress_comm.sh                      # flood: unidirectional send() + apk-tick
./scripts/stress_comm.sh --mode frida         # send/recv ping-pong + binary + rpc.exports
# or: cargo run -p goauld-host --release -- stress --mode frida --stage-into-app --count 500
```

## Fixture index

| Script | What it does | `--expect-send` |
|---|---|---|
| `hi.js` | `send("hi")` round-trip | `hi` |
| `java_toast.js` | Framework toast on main thread | `toast-shown` |
| `java_hook.js` | Hook `Target.hookMe` | `java-hook-installed` |
| `java_api.js` | Frida `Java.*` surface smoke | `java-api-ok` |
| `java_perform.js` | `Java.perform` / `performNow` | `java-perform-ok` |
| `thread_api.js` | observers / `runOnThread` / exception handler | `thread-api-ok` |
| `thread_backtrace.js` | `Thread.backtrace` / `Backtracer` | `backtrace-ok` |
| `memory_scan.js` | `Memory.scan` / `scanSync` | `memory-scan-ok` |
| `memory_patch.js` | `Memory.patchCode` | `memory-patch-ok` |
| `arm64_writer.js` | `Arm64Writer` / `Arm64Relocator` / AArch64 enums | `arm64-writer-ok` |
| `arm64_writer_examples.js` | Callable stub, `patchCode`+writer, labels, relocator, call-with-args | `arm64-examples-ok` |
| `memory_access.js` | `MemoryAccessMonitor` | `memory-access-ok` |
| `module_enumerate.js` | Module exports/imports/symbols/sections/deps | `module-enum-ok` |
| `misc_apis.js` | console / hexdump / timers / gc / Cloak / Profiler | `misc-apis-ok` |
| `inspect_package.js` | Classes / fields / prefs / storage | `inspect-ok` |
| `trace_java_api.js` | Android API invoke tracing | (via `trace java`) |
| `interceptor_strlen.js` | Native `Interceptor.attach` (enter) | `interceptor-installed` |
| `interceptor_attach.js` | `attach` + `onLeave` | `interceptor-attach-ok` |
| `interceptor_replace.js` | `replace` + `flush` + `detachAll` | `interceptor-replace-ok` |
| `interceptor_api.js` | attach/leave/replace/flush/detach | `interceptor-api-ok` |
| `process_module_memory.js` | Process / Module / Memory | `ptmm-ok` |
| `stress_send.js` / `stress_frida_comm.js` | Comm stress | (via `stress`) |

JS API parity vs Frida: [`docs/JS_API_PARITY.md`](docs/JS_API_PARITY.md).  
Deeper design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Milestones

Integration harness: `./scripts/run_milestone.sh <unit|1|2|3|4|5|6|apk|e2e|device-smoke|symbiote|all>`

| # | Goal | Status |
|---|---|---|
| 1 | Injection round-trip | **OK** on emulator (`maps` + ctor + abstract socket) |
| 2 | Native hook plumbing | Host unit OK; live via Interceptor in 4 |
| 3 | `send("hi")` script round-trip | **OK** host + device e2e |
| 4 | `Interceptor.attach` from JS | **OK** install path on device |
| 5 | Java method hook (ArtMethod Technique A) | **OK** live on `java-target` — JS worker owns QJS; `this.hookMe` → `ArtMethod::Invoke` on backup |
| 6 | **APK e2e** on emulator (`java-target`) | syscalls, inject, fixtures, `attach java` / `trace java` |
| 7 | Non-rooted hardening | pending |
| 8 | Stretch: Binder tracing | pending |

```bash
./scripts/build-android.sh
cargo build -p goauld-host --release
./scripts/run_milestone.sh all
# Symbiote agent on the emulator (separate dist, does not replace QuickJS):
./scripts/test-symbiote-emulator.sh
# or APK suite only:
./scripts/run_e2e_apk.sh
./scripts/run_e2e_apk.sh syscalls android-api toast
```

### APK e2e suite (`scripts/run_e2e_apk.sh`)

Runs against the real `com.example.javatarget` APK on a rooted emulator
(`adb root` + `setenforce 0`). Builds/installs the APK if missing.

| Case | What it checks |
|---|---|
| `syscalls` | `attach syscall` + `trace syscalls` (decoded events, no agent) |
| `inject` | `inject --stage-into-app` → maps + abstract socket |
| `hi` / `ptmm` | script attach + `--expect-send` |
| `toast` / `java-api` / `inspect` | Java fixtures on the APK |
| `android-api` | `attach java` emits `android-api` events |
| `android-api-hooks` | `attach java --java-hooks …hookMe` |
| `java-hook` | Technique-A `hookMe` + callOriginal |
| `interceptor` | native `Interceptor.attach` (runs late; force-stops after) |
| `trace-java` | `trace java` restart + inject + events |
