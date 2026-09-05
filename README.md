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

## Workspace

| Crate | Role |
|---|---|
| `goauld-proto` | Wire protocol |
| `goauld-inject` | Ptrace / remote-call library (compiled into the on-device injector) |
| `goauld-injector` | **On-device** arm64 binary — inject into any process/package |
| `goauld-native-hook` | Agent: arm64 inline + GOT/PLT hooks |
| `goauld-art-bridge` | Agent: ArtMethod / JNI hooks |
| `goauld-script` | Agent: QuickJS + Frida-shaped JS API |
| `goauld-agent` | Agent cdylib (`libgoauld_agent.so`) |
| `goauld-host` | Desktop CLI (adb orchestrator + script attach) |

Disassembler: path dependency on sibling [`arm_disassembler`](../arm_disassembler).

## Build

```bash
# Desktop host
cargo build -p goauld-host --release

# On-device arm64 artifacts (NDK — pin in ndk.txt)
./scripts/build-android.sh
# → dist/android-arm64/goauld-injector
# → dist/android-arm64/libgoauld_agent.so
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

### Native Interceptor (e.g. `strlen`)

```bash
cargo run -p goauld-host --release -- attach \
  --pid "$(adb shell pidof -s com.example.javatarget | tr -d '\r')" \
  --port 27046 \
  --script scripts/fixtures/interceptor_strlen.js \
  --expect-send interceptor-installed --max-wait-secs 10
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
| `inspect_package.js` | Classes / fields / prefs / storage | `inspect-ok` |
| `trace_java_api.js` | Android API invoke tracing | (via `trace java`) |
| `interceptor_strlen.js` | Native `Interceptor.attach` | `interceptor-installed` |
| `process_module_memory.js` | Process / Module / Memory | `ptmm-ok` |
| `stress_send.js` / `stress_frida_comm.js` | Comm stress | (via `stress`) |

JS API parity vs Frida: [`docs/JS_API_PARITY.md`](docs/JS_API_PARITY.md).  
Deeper design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Milestones

Integration harness: `./scripts/run_milestone.sh <unit|1|2|3|4|5|6|apk|e2e|device-smoke|all>`

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
