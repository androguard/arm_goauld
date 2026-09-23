<p align="center">
  <img src=".github/logo.jpg" alt="ARM GOAULD — Android / arm64 Dynamic Instrumentation Toolkit" width="520"/>
</p>

<p align="center">
  <strong>goauld</strong> — Android / arm64 dynamic instrumentation<br/>
  <em>Named after the Goa'uld: a symbiont that takes over a host.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#vs-frida">vs Frida</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#recipes">Recipes</a> ·
  <a href="docs/JS_API_PARITY.md">JS API parity</a> ·
  <a href="docs/ARCHITECTURE.md">Design</a>
</p>

---

**goauld** is a Rust toolkit for instrumenting **Android on AArch64**. You inject an agent into a process, then load Frida-shaped JavaScript (`Interceptor`, `Java`, `Process`, `Module`, `Memory`, `Arm64Writer`, `send`).

| | |
|---|---|
| **Platform** | Android + arm64 only — no x86, ARM32, iOS, or desktop targets |
| **Version** | workspace `0.1.6` — agent / injector / host print `goauld_proto::version_info()` (`0.1.6 (git:… built:…)`) |
| **Engines** | QuickJS (default) or Symbiote — compile-time exclusive |
| **Reference** | [Frida](https://frida.re/) — goauld is a smaller alternative, not a replacement |

---

## What you get

- **On-device inject** — `goauld-injector` ptraces the target and `dlopen`s `libgoauld_agent.so`
- **Frida-shaped JS** — familiar globals; see [`docs/JS_API_PARITY.md`](docs/JS_API_PARITY.md) for gaps
- **Native hooks** — `Interceptor.attach` / `replace`, GOT/PLT, inline arm64 patches
- **Java / ART** — `Java.use`, Technique-A method hooks, `attach java` / `trace java` API streams
- **Syscall trace** — `PTRACE_SYSCALL` without loading the agent (injector alone)
- **Arm64Writer / Relocator** — emit and relocate AArch64 code from JS
- **Two JS backends** — QuickJS for the full surface; Symbiote as a pure-Rust experiment

---

## Quick start

```bash
# 1. Host CLI
cargo build -p goauld-host --release

# 2. On-device arm64 artifacts (NDK version pinned in ndk.txt)
./scripts/build-android.sh              # QuickJS → dist/android-arm64/
./scripts/build-android.sh symbiote     # optional second engine

# 3. Rooted emulator (example AVD: Goauld_API34)
./scripts/emulator.sh start
adb root && adb shell setenforce 0

# 4. Demo APK
./scripts/build-java-target.sh
adb install -r testapps/java-target/build/java-target.apk
adb shell am start -n com.example.javatarget/.Target
```

```bash
PKG=com.example.javatarget
INJ=dist/android-arm64/goauld-injector
SO=dist/android-arm64/libgoauld_agent.so

# Inject once per process
cargo run -p goauld-host --release -- inject \
  --package "$PKG" --injector "$INJ" --agent "$SO" --stage-into-app

PID=$(adb shell pidof -s "$PKG" | tr -d '\r')

# Attach a script (host exits when --expect-send matches — that is normal)
cargo run -p goauld-host --release -- attach \
  --pid "$PID" --port 27046 \
  --script scripts/fixtures/java_toast.js \
  --expect-send toast-shown --max-wait-secs 10
```

Re-inject usually needs a fresh process (`am force-stop` + start again). After `--expect-send`, logcat may show `goauld session ended: failed to fill whole buffer` — expected when the host closes the socket.

---

## vs Frida

[Frida](https://frida.re/) is the mature, cross-platform **reference**: Stalker, Gum, `frida-server` / `frida-gadget`, and the ecosystem of tools and scripts people already use. **If you need that coverage, use Frida.**

goauld is a narrower **Android / arm64 alternative**. It reuses a Frida-shaped JS surface so scripts feel familiar. It is not feature-complete Frida.

Snapshot below: API 34 emulator (`arm64-v8a`), same JS workload, `Date.now` median of 3, Frida **17.18.0**. Lower is better. Re-run with `scripts/bench-js-engines.py` — numbers move with build and device.

| | goauld / QuickJS | Frida 17.18.0 |
|---|---:|---:|
| Script load (session already up) | 2.6 ms | **2.0 ms** |
| Inject (adb push of injector + agent, then ptrace, **every time**) | 370 ms | — |
| Attach (`frida-server` already running; **56 MB server push not included**) | — | **53 ms** |
| Integer add | **48 ns/op** | 74 ns/op |
| Property get | **109 ns/op** | 147 ns/op |
| Call | **112 ns/op** | 145 ns/op |
| `readU32` | **230 ns/op** | 2.2 µs/op |
| String append | 2.7 µs/op | **1.7 µs/op** |
| Object alloc | 1.0 µs/op | **0.9 µs/op** |
| `send` | **2 µs/msg** | 14 µs/msg |
| Agent PSS at idle | **~1.6 MB** | ~6 MB |

Those two startup rows are **not the same operation**. goauld’s 370 ms repeats the push; Frida’s 53 ms is only `attach` after `frida-server` is already up.

Frida stays ahead on attach, strings, allocation, and everything this table does not measure (other ABIs, Stalker, CLI, existing scripts). On this device QuickJS was quicker on tight loops, memory reads, and `send`. **Symbiote** is a second pure-Rust backend of the same API and is still well behind both.

---

## Architecture

```
┌──────────────┐   adb push / shell   ┌─────────────────────────┐
│  goauld-host │ ──────────────────►  │ goauld-injector (arm64) │  ← runs ON the phone
│  (desktop)   │                      │  ptrace + remote dlopen │
└──────┬───────┘                      └───────────┬─────────────┘
       │ adb forward                               │ injects
       ▼                                           ▼
  TCP ↔ abstract socket                 ┌─────────────────────────┐
                                        │ libgoauld_agent.so      │
                                        │  hooks + JS + ART       │
                                        └─────────────────────────┘
```

Ptrace **must** run on-device. The desktop CLI never attaches to app processes itself; it deploys the injector and agent, then runs the injector as root (or via `adb root`).

| Crate | Role |
|---|---|
| `goauld-proto` | Wire protocol |
| `goauld-inject` | Ptrace / remote-call library (into the on-device injector) |
| `goauld-injector` | **On-device** arm64 binary — inject / syscall trace |
| `goauld-native-hook` | Agent: arm64 inline + GOT/PLT hooks |
| `goauld-art-bridge` | Agent: ArtMethod / JNI hooks |
| `goauld-script` | Agent: Frida-shaped JS (QuickJS **or** Symbiote) |
| `goauld-agent` | Agent cdylib (`libgoauld_agent.so`) |
| `goauld-host` | Desktop CLI (adb orchestrator + script attach) |

Disassembler: sibling [`arm_disassembler`](../arm_disassembler). Deeper notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### JS engines

Compile-time **mutually exclusive** features on `goauld-script` / `goauld-agent`:

| Feature | Backend | Notes |
|---|---|---|
| `quickjs` **(default)** | `rquickjs` | Full Frida-shaped surface + e2e fixtures |
| `symbiote` | `symbiote-core` + `symbiote-jit` | Pure-Rust; path dep `../../symbiote` |

```bash
./scripts/test-js-engines.sh both
./scripts/test-symbiote-emulator.sh   # Symbiote agent → dist/android-arm64-symbiote/
```

---

## Recipes

Pattern: **inject** once, then **attach** scripts. Replace `SOME.js` / `SOME-OK` as needed.

### Toast

```bash
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/java_toast.js \
  --expect-send toast-shown --max-wait-secs 10
```

### Syscall trace

On-device `PTRACE_SYSCALL` — **no agent `.so`**, injector only. Decoded paths, sockaddrs, buffer previews. Does not use `PTRACE_O_EXITKILL` (app should survive detach).

```bash
cargo run -p goauld-host --release -- attach syscall \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --max-events 400 --max-wait-secs 60

cargo run -p goauld-host --release -- trace syscalls \
  --package com.example.javatarget \
  --injector dist/android-arm64/goauld-injector \
  --duration-secs 10 \
  --filter openat,connect,write,read
```

### Android / Java API stream

Hooks ART invoke stubs; emits `android-api` events (`method`, `shorty`, decoded args). Direct AOT-to-AOT calls that never hit those stubs are invisible.

```bash
# Fresh process: restart + inject + trace
cargo run -p goauld-host --release -- trace java \
  --package com.example.javatarget \
  --injector dist/android-arm64/goauld-injector \
  --agent dist/android-arm64/libgoauld_agent.so \
  --stage-into-app \
  --filter 'android.,androidx.,java.,javax.,com.android.' \
  --max-events 200 --max-wait-secs 20

# Already injected
cargo run -p goauld-host --release -- attach java \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --java-hooks 'com.example.javatarget.Target.hookMe:(I)I' \
  --max-events 50 --max-wait-secs 20
```

### Inspect / Java hook / Interceptor / Arm64Writer

```bash
# Package inspector
--script scripts/fixtures/inspect_package.js --expect-send inspect-ok

# Technique-A Java hook
--script scripts/fixtures/java_hook.js --expect-send java-hook-installed

# Native Interceptor
--script scripts/fixtures/interceptor_attach.js --expect-send interceptor-attach-ok
--script scripts/fixtures/interceptor_replace.js --expect-send interceptor-replace-ok

# Arm64Writer recipes
--script scripts/fixtures/arm64_writer_examples.js --expect-send arm64-examples-ok

# Smoke
--script scripts/fixtures/hi.js --expect-send hi
--script scripts/fixtures/process_module_memory.js --expect-send ptmm-ok
```

Minimal writer / relocator sketch:

```javascript
var code = Memory.alloc(Process.pageSize);
Memory.protect(code, Process.pageSize, 'rwx');
var w = new Arm64Writer(code);
w.putLdrRegU64(Register.x0, 99);
w.putRet();
w.flush();

Memory.patchCode(target, 16, function (code) {
  var w = new Arm64Writer(code);
  w.putInstruction((0xD2800000 | (7 << 5)) >>> 0); // MOVZ X0, #7
  w.putRet();
  w.flush();
  w.dispose();
});
```

### Comm stress

```bash
./scripts/stress_comm.sh
./scripts/stress_comm.sh --mode frida
```

### Process memory dump (goauld freedump)

Tiny cousin of [androguard/freedump](https://github.com/androguard/freedump): enumerate
ranges in the target, stream chunks over the goauld session, write
`%x-%x.dump` + `info.freedump` (same layout freedump uses locally).

```bash
# Agent already injected
python3 scripts/freedump.py --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  -o /tmp/goauld-dumps

# Inject then dump (QuickJS dist)
python3 scripts/freedump.py --package com.example.javatarget --inject \
  --dist dist/android-arm64 -o /tmp/goauld-dumps

# rw- only, 64 KiB chunks, stop at 32 MiB
python3 scripts/freedump.py --pid 1234 -o /tmp/goauld-dumps \
  --prot 'rw-' --chunk 65536 --max 33554432
```

Agent fixture: `scripts/fixtures/freedump.js`.

---

## Fixture index

| Script | Purpose | `--expect-send` |
|---|---|---|
| `hi.js` | `send("hi")` | `hi` |
| `java_toast.js` | Framework toast | `toast-shown` |
| `java_hook.js` | Hook `Target.hookMe` | `java-hook-installed` |
| `java_api.js` | `Java.*` smoke | `java-api-ok` |
| `java_perform.js` | `Java.perform` / `performNow` | `java-perform-ok` |
| `inspect_package.js` | Classes / prefs / storage | `inspect-ok` |
| `interceptor_*.js` | Native Interceptor | `interceptor-*-ok` |
| `arm64_writer*.js` | Writer / relocator | `arm64-*-ok` |
| `process_module_memory.js` | Process / Module / Memory | `ptmm-ok` |
| `memory_scan.js` / `memory_patch.js` | Scan / patchCode | `memory-*-ok` |
| `thread_api.js` / `thread_backtrace.js` | Threads / backtrace | `thread-api-ok` / `backtrace-ok` |
| `misc_apis.js` | console / hexdump / timers / gc | `misc-apis-ok` |
| `trace_java_api.js` | Android API tracing | via `trace java` |
| `stress_*.js` | Comm stress | via `stress` |
| `freedump.js` | Process memory dump | via `scripts/freedump.py` |

---

## Status

```bash
./scripts/run_milestone.sh all
./scripts/run_e2e_apk.sh
./scripts/test-symbiote-emulator.sh
```

| # | Goal | Status |
|---|---|---|
| 1 | Injection round-trip | **OK** on emulator |
| 2 | Native hook plumbing | Host unit OK; live via Interceptor |
| 3 | `send("hi")` round-trip | **OK** |
| 4 | `Interceptor.attach` from JS | **OK** |
| 5 | Java method hook (Technique A) | **OK** on `java-target` |
| 6 | APK e2e (`java-target`) | syscalls, inject, fixtures, `attach` / `trace java` |
| 7 | Non-rooted hardening | pending |
| 8 | Binder tracing | pending |

APK e2e (`scripts/run_e2e_apk.sh`) covers `syscalls`, `inject`, `hi` / `ptmm`, toast / java-api / inspect, `android-api`, Technique-A hooks, Interceptor, and `trace java` on a rooted emulator.

---

## Docs

| Doc | Contents |
|---|---|
| [`docs/JS_API_PARITY.md`](docs/JS_API_PARITY.md) | Frida surface coverage |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Design notes |
| [`docs/INTERNALS.html`](docs/INTERNALS.html) | Internals (HTML) |

```bash
./scripts/emulator.sh start | start --gui | stop | status
```
