# Frida JavaScript API parity plan

Target reference: [Frida JavaScript API](https://frida.re/docs/javascript-api/).

This document tracks goauld’s Frida-shaped JS surface (QuickJS on Android/arm64) versus
that reference. Scope is **Android + AArch64 only** — iOS/ObjC, Windows, and other arches
are out of project scope unless noted.

## Legend

| Status | Meaning |
|--------|---------|
| **done** | Usable for milestones / fixtures |
| **partial** | Stub or subset of Frida semantics |
| **planned** | Needed for parity; not started |
| **n/a** | Out of goauld scope (platform / stretch) |

## Communication (host ↔ injected process)

Reference: [Communication between host and injected process](https://frida.re/docs/javascript-api/#communication-between-host-and-injected-process).

| API | Status | Notes |
|-----|--------|-------|
| `send(message[, data])` | **done** | JSON + optional byte array; stress: `stress` + `stress --mode frida` |
| `recv([type,] callback)` | **done** | One-shot waiter; `wait()` is stub (no blocking pump yet) |
| host `script.post` | **done** | Wire `Message::Post` → JS `recv` |
| `rpc.exports` | **partial** | Sync returns only (no Promise); host `RpcCall`/`RpcReply` wired |
| `script.message` / session events | **planned** | Host CLI prints sends; no Node/Python bindings yet |
| batching / high-frequency guidance | **done** | Documented; flood stress measures throughput |

**Stress coverage**

- `goauld stress` / `./scripts/stress_comm.sh` — unidirectional `send` flood + `apk-tick` impact
- `goauld stress --mode frida` — ping/pong (`send`↔`post`/`recv`) + binary data + `rpc.exports` RTT

## Runtime information

| API | Status |
|-----|--------|
| `Frida.version` / `Frida.heapSize` | **planned** |
| `Script.runtime` | **partial** — always QJS in practice |
| `Script.evaluate` / `load` / source maps | **planned** |
| `Script.nextTick` / pin / unpin / bindWeak | **planned** |

## Process / Thread / Module / Memory

| API | Status | Notes |
|-----|--------|-------|
| `Process` (id, arch, platform, pageSize, pointerSize, codeSigningPolicy) | **done** | Android/arm64; platform reports `linux`/`darwin` |
| `Process.getCurrentDir/Home/Tmp`, `isDebuggerAttached`, `getCurrentThreadId` | **done** | |
| `Process.enumerateModules` / find/get by name/address / `mainModule` | **done** | via `/proc/self/maps` (empty on macOS host) |
| `Process.enumerateRanges` / find/getRangeByAddress | **done** | Frida-style `rw-` “at least” matching + coalesce |
| `Process.enumerateThreads` | **partial** | id/name/state; no register context |
| Thread observers / `runOnThread` / exception handler | **planned** | |
| `Thread.sleep` | **done** | |
| `Thread.backtrace` / `Backtracer` | **partial** | FP walk + fuzzy stack scan on current JS worker; no Interceptor context yet |
| HW breakpoints | **planned** | |
| `Module.findExportByName` / `findBaseAddress` / global export | **done** | |
| Module object (`name`/`base`/`size`/`path`, get/findExport, enumerateRanges) | **done** | |
| `Module.enumerateExports` | **partial** | ELF64 dynsym (incl. IFUNC); on-disk parse |
| `Module.enumerateImports` | **partial** | AArch64 RELA/JMPREL → name + GOT slot |
| `Module.enumerateSymbols`, sections/deps | **planned** | symbols ≈ exports for now |
| `Module.load` | **done** | `dlopen` + maps refresh |
| `ModuleMap` | **done** | JS snapshot over `enumerateModules` |
| `Memory.read*` / `write*` / `writeByteArray` | **done** | u8/u16/u32/u64/pointer/utf8 |
| `Memory.alloc` / `allocUtf8String` / `copy` / `dup` / `protect` / `queryProtection` | **done** | alloc is process-lifetime (no JS GC free yet) |
| `Memory.scan` / `scanSync` | **partial** | byte/`??`/nibble wildcards; no r2 mask suffix |
| `Memory.patchCode` | **partial** | in-place mprotect + apply; default restore `rw-` if query fails |
| `MemoryAccessMonitor` | **planned** | |
| `CModule` / `RustModule` | **planned** / stretch |
| `ApiResolver` / `DebugSymbol` / `Kernel` | **planned** / **n/a** (Kernel) |

**Fixture:** `scripts/fixtures/process_module_memory.js` (`--expect-send ptmm-ok`).

## Data types / NativeFunction

| API | Status |
|-----|--------|
| `NativePointer` / `ptr` | **partial** |
| `Int64` / `UInt64` / `ArrayBuffer` | **planned** |
| `NativeFunction` / `NativeCallback` | **planned** |
| `SystemFunction` | **planned** |

## Network / File / DB

| API | Status |
|-----|--------|
| `Socket*` / streams / `File` / Sqlite | **planned** (low priority vs hooks) |

## Instrumentation

| API | Status | Notes |
|-----|--------|-------|
| `Interceptor.attach` | **partial** — enter only; leave/replace incomplete |
| `Interceptor.replace` / `flush` | **planned** |
| `Stalker` | **planned** (stretch) |
| `Java.available` / `androidVersion` / `ACC_*` | **done** | |
| `Java.perform` / `performNow` | **partial** — runs immediately on JS worker (VM attach on demand) |
| `Java.scheduleOnMainThread` | **done** | `goauld.MainBridge` → JS worker callback |
| `Java.isMainThread` | **done** | |
| `Java.use` + `implementation` / `overload` | **partial** — reflection overloads; `$new` limited; Technique A hooks |
| `Java.enumerateLoadedClasses` / `Sync` | **done** | DexFile.entries via class loaders |
| `Java.enumerateClassLoaders` / `Sync` | **partial** — identity strings, not full wrappers |
| `Java.enumerateMethods` | **partial** — glob `class!method` + `/i` `/s` `/u` |
| `Java.enumerateFieldsSync` / `readStaticField` / `dumpAppStorageSync` | **done** | package inspect helpers |
| `Java.choose` | **planned** | heap scan stub |
| `Java.cast` / `retain` / `array` | **partial** | thin wrappers |
| `Java.backtrace` | **partial** | maps to native `Thread.backtrace` |
| `Java.openClassFile` / `registerClass` | **planned** | stubs |
| `Java.deoptimize*` | **planned** | no-ops |
| `Java.vm` / `classFactory` / `ClassFactory` | **partial** | structure present; loader switching limited |
| `ObjC` | **n/a** |

**Fixture:** `scripts/fixtures/java_api.js` (`--expect-send java-api-ok`).
**Inspect:** `scripts/fixtures/inspect_package.js` (`--expect-send inspect-ok`) — classes/methods/fields/statics + SharedPreferences/dataDir.

## CPU writers / relocators

| API | Status |
|-----|--------|
| Arm64Writer / Relocator | **partial** — internal in `goauld-native-hook`, not JS-exposed |
| Other arches | **n/a** |

## Other

| API | Status |
|-----|--------|
| `console.log` | **partial** — via `send` |
| `hexdump` | **planned** |
| Timers (`setTimeout` / …) | **planned** |
| `gc` / `Worker` / Cloak / Profiler / Samplers | **planned** / stretch |

## Suggested milestone order (parity)

1. **Comm complete** — `recv.wait` pump, Promise `rpc.exports`, binary `send` e2e tests
2. **Memory/Module/Process** — **substantially done** (loop stopped). Remaining stretch: module/thread observers, `MemoryAccessMonitor`
3. **Interceptor leave/replace** + broader `NativeFunction`
4. **Java** — **in progress** — enumerate/use/schedule/main done; choose/registerClass/`$new` next
5. **Timers + Script helpers**
6. **Stretch** — Stalker, CModule, Worker

## Non-goals (explicit)

- iOS / ObjC / non-arm64
- Full V8 runtime (QJS is the goauld runtime)
- Drop-in replacement for every Frida host binding (Node/Python) — wire protocol first; bindings later
