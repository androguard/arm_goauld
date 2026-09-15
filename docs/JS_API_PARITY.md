# Frida JavaScript API parity plan

Target reference: [Frida JavaScript API](https://frida.re/docs/javascript-api/).

This document tracks goauld’s Frida-shaped JS surface (Android/arm64) versus
that reference. The agent selects a JS engine at **compile time**:

- **`quickjs`** (default) — full surface tracked below
- **`symbiote`** — path dependency on [`../../symbiote`](../../../symbiote); same shared `frida_prelude` + `host_ops` surface as QuickJS (`Script.runtime === 'SYMBIOTE'`). Java Technique-A invoke remains QuickJS-preferred.

Host smoke for both: `./scripts/test-js-engines.sh both` (`js_engine_send_hi`, `js_engine_core_smoke`, `js_engine_modules_exposed`, `js_engine_arm64_writer_smoke`).

Scope is **Android + AArch64 only** — iOS/ObjC, Windows, and other arches
are out of project scope unless noted.

## Legend


| Status      | Meaning                                  |
| ----------- | ---------------------------------------- |
| **done**    | Usable for milestones / fixtures         |
| **partial** | Stub or subset of Frida semantics        |
| **planned** | Needed for parity; not started           |
| **n/a**     | Out of goauld scope (platform / stretch) |


## Communication (host ↔ injected process)

Reference: [Communication between host and injected process](https://frida.re/docs/javascript-api/#communication-between-host-and-injected-process).


| API                                | Status      | Notes                                                                |
| ---------------------------------- | ----------- | -------------------------------------------------------------------- |
| `send(message[, data])`            | **done**    | JSON + optional byte array; stress: `stress` + `stress --mode frida` |
| `recv([type,] callback)`           | **done**    | One-shot waiter; `wait()` is stub (no blocking pump yet)             |
| host `script.post`                 | **done**    | Wire `Message::Post` → JS `recv`                                     |
| `rpc.exports`                      | **partial** | Sync returns only (no Promise); host `RpcCall`/`RpcReply` wired      |
| `script.message` / session events  | **planned** | Host CLI prints sends; no Node/Python bindings yet                   |
| batching / high-frequency guidance | **done**    | Documented; flood stress measures throughput                         |


**Stress coverage**

- `goauld stress` / `./scripts/stress_comm.sh` — unidirectional `send` flood + `apk-tick` impact
- `goauld stress --mode frida` — ping/pong (`send`↔`post`/`recv`) + binary data + `rpc.exports` RTT



## Runtime information


| API                                        | Status                               |
| ------------------------------------------ | ------------------------------------ |
| `Frida.version` / `Frida.heapSize`         | **planned**                          |
| `Script.runtime`                           | **partial** — `QJS` or `SYMBIOTE` from compile-time feature |
| `Script.evaluate` / `load` / source maps   | **planned**                          |
| `Script.nextTick` / pin / unpin / bindWeak | **planned**                          |




## Process / Thread / Module / Memory


| API                                                                                 | Status                         | Notes                                                                       |
| ----------------------------------------------------------------------------------- | ------------------------------ | --------------------------------------------------------------------------- |
| `Process` (id, arch, platform, pageSize, pointerSize, codeSigningPolicy)            | **done**                       | Android/arm64; platform reports `linux`/`darwin`                            |
| `Process.getCurrentDir/Home/Tmp`, `isDebuggerAttached`, `getCurrentThreadId`        | **done**                       |                                                                             |
| `Process.enumerateModules` / find/get by name/address / `mainModule`                | **done**                       | via `/proc/self/maps` (empty on macOS host)                                 |
| `Process.enumerateRanges` / find/getRangeByAddress                                  | **done**                       | Frida-style `rw-` “at least” matching + coalesce                            |
| `Process.enumerateThreads`                                                          | **done**                       | id/name/state                                                               |
| Thread observers / `runOnThread` / exception handler                                | **partial**                    | `Process.setThreadObserver` (poll); `Thread.runOnThread`; probe exception handler |
| `Thread.sleep`                                                                      | **done**                       |                                                                             |
| `Thread.backtrace` / `Backtracer`                                                   | **done**                       | FP walk + fuzzy fill; ACCURATE/FUZZY                                        |
| HW breakpoints                                                                      | **planned**                    |                                                                             |
| `Module.findExportByName` / `findBaseAddress` / global export                       | **done**                       |                                                                             |
| Module object (`name`/`base`/`size`/`path`, get/findExport, enumerateRanges)        | **done**                       |                                                                             |
| `Module.enumerateExports`                                                           | **done**                       | ELF64 dynsym (incl. IFUNC); on-disk parse                                   |
| `Module.enumerateImports`                                                           | **done**                       | AArch64 RELA/JMPREL → name + GOT slot                                       |
| `Module.enumerateSymbols` / `enumerateSections` / `enumerateDependencies`           | **done**                       | `.symtab`/`.dynsym`; section headers; `DT_NEEDED`                           |
| `Module.load`                                                                       | **done**                       | `dlopen` + maps refresh                                                     |
| `ModuleMap`                                                                         | **done**                       | JS snapshot over `enumerateModules`                                         |
| `Memory.read*` / `write*` / `writeByteArray`                                        | **done**                       | u8/u16/u32/u64/pointer/utf8                                                 |
| `Memory.alloc` / `allocUtf8String` / `copy` / `dup` / `protect` / `queryProtection` | **done**                       | alloc is process-lifetime (no JS GC free yet)                               |
| `Memory.scan` / `scanSync`                                                          | **done**                       | byte/`??`/nibble wildcards; packed hex; onMatch stop                        |
| `Memory.patchCode`                                                                  | **done**                       | mprotect + apply + icache; restore prior prot                               |
| `MemoryAccessMonitor`                                                               | **done**                       | page traps via PROT_NONE; one notify/page; async onAccess                   |
| `CModule` / `RustModule`                                                            | **planned** / stretch          |                                                                             |
| `ApiResolver` / `DebugSymbol` / `Kernel`                                            | **planned** / **n/a** (Kernel) |                                                                             |


**Fixture:** `scripts/fixtures/process_module_memory.js` (`--expect-send ptmm-ok`).
**Module enum:** `module_enumerate.js` (`module-enum-ok`) — exports/imports/symbols/sections/deps.
**Thread:** `thread_api.js` (`thread-api-ok`), `thread_backtrace.js` (`backtrace-ok`).
**Memory:** `memory_scan.js` (`memory-scan-ok`), `memory_patch.js` (`memory-patch-ok`), `memory_access.js` (`memory-access-ok`).

## Data types / NativeFunction


| API                                 | Status      |
| ----------------------------------- | ----------- |
| `NativePointer` / `ptr`             | **partial** |
| `Int64` / `UInt64` / `ArrayBuffer`  | **planned** |
| `NativeFunction` / `NativeCallback` | **planned** |
| `SystemFunction`                    | **planned** |




## Network / File / DB


| API                                   | Status                              |
| ------------------------------------- | ----------------------------------- |
| `Socket*` / streams / `File` / Sqlite | **planned** (low priority vs hooks) |




## Instrumentation


| API                                                                   | Status                                                                | Notes                                                         |
| --------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------- |
| `Interceptor.attach`                                                  | **done**                                                              | `onEnter` + `onLeave` (retval.replace); listener.detach       |
| `Interceptor.replace` / `flush` / `detachAll`                         | **done**                                                              | JS fn (skip original) or NativePointer; `flush` = icache sync |
| `Interceptor.revert`                                                  | **partial**                                                           | currently `detachAll`                                         |
| `Stalker`                                                             | **planned** (stretch)                                                 |                                                               |
| `Java.available` / `androidVersion` / `ACC_*`                         | **done**                                                              |                                                               |
| `Java.perform` / `performNow`                                         | **done**                                                              | ensure JNI/VM touch then run on JS worker                     |
| `Java.scheduleOnMainThread`                                           | **done**                                                              | `goauld.MainBridge` → JS worker callback                      |
| `Java.isMainThread`                                                   | **done**                                                              |                                                               |
| `Java.use` + `implementation` / `overload`                            | **partial** — reflection overloads; `$new` limited; Technique A hooks |                                                               |
| `Java.enumerateLoadedClasses` / `Sync`                                | **done**                                                              | DexFile.entries via class loaders                             |
| `Java.enumerateClassLoaders` / `Sync`                                 | **partial** — identity strings, not full wrappers                     |                                                               |
| `Java.enumerateMethods`                                               | **partial** — glob `class!method` + `/i` `/s` `/u`                    |                                                               |
| `Java.enumerateFieldsSync` / `readStaticField` / `dumpAppStorageSync` | **done**                                                              | package inspect helpers                                       |
| `Java.choose`                                                         | **planned**                                                           | heap scan stub                                                |
| `Java.cast` / `retain` / `array`                                      | **partial**                                                           | thin wrappers                                                 |
| `Java.backtrace`                                                      | **partial**                                                           | maps to native `Thread.backtrace`                             |
| `Java.openClassFile` / `registerClass`                                | **planned**                                                           | stubs                                                         |
| `Java.deoptimize*`                                                    | **planned**                                                           | no-ops                                                        |
| `Java.vm` / `classFactory` / `ClassFactory`                           | **partial**                                                           | structure present; loader switching limited                   |
| `ObjC`                                                                | **n/a**                                                               |                                                               |


**Fixture:** `scripts/fixtures/java_api.js` (`--expect-send java-api-ok`).
**Inspect:** `scripts/fixtures/inspect_package.js` (`--expect-send inspect-ok`) — classes/methods/fields/statics + SharedPreferences/dataDir.
**Interceptor:** `interceptor_attach.js`, `interceptor_replace.js`, `interceptor_api.js`, `interceptor_strlen.js`.
**Java.perform:** `java_perform.js` (`--expect-send java-perform-ok`).

## CPU writers / relocators


| API                     | Status                                                                 |
| ----------------------- | ---------------------------------------------------------------------- |
| Arm64Writer             | **done** — Frida-shaped API (emit / labels / flush / calls / push-all) |
| Arm64Relocator          | **done** — streaming readOne/writeOne/writeAll/skipOne               |
| AArch64 enums           | **done** — `Register` (incl. Q) / `ConditionCode` / `IndexMode`      |
| Other arches            | **n/a**                                                                |

**Fixtures:**
- `scripts/fixtures/arm64_writer.js` (`--expect-send arm64-writer-ok`) — API smoke
- `scripts/fixtures/arm64_writer_examples.js` (`--expect-send arm64-examples-ok`) — callable stub, `patchCode`+writer, labels, trampoline relocator, call-with-args


## Other


| API                                           | Status                   |
| --------------------------------------------- | ------------------------ |
| `console.log` / `warn` / `error`                                                    | **done**                       | Host `Message::Log` + `send({type:'log'})`; ArrayBuffer → hexdump           |
| `hexdump`                                                                           | **done**                       | NativePointer / ArrayBuffer; offset/length/header/address                   |
| Timers (`setTimeout` / `setInterval` / `setImmediate` + clear*)                     | **done**                       | Side-thread schedule → JS worker `EvalAsync`                                |
| `gc`                                                                                | **done**                       | QuickJS `run_gc`                                                            |
| `Worker`                                                                            | **partial**                    | Constructor throws (single QJS heap)                                        |
| `Cloak`                                                                             | **done**                       | Threads / ranges / fds; filters `enumerateThreads` / `enumerateRanges`      |
| `Profiler` / Samplers                                                               | **partial**                    | Wall/Cycle/Busy/UserTime; Profiler via Interceptor; malloc/call-count stub  |


**Fixture:** `scripts/fixtures/misc_apis.js` (`--expect-send misc-apis-ok`).


## Suggested milestone order (parity)

1. **Comm complete** — `recv.wait` pump, Promise `rpc.exports`, binary `send` e2e tests
2. **Memory/Module/Process** — **substantially done**. Remaining stretch: module observers, HW breakpoints
3. **Interceptor leave/replace** — **done** (`onLeave`, `replace`, `flush`, `detach`)
4. **Java** — **in progress** — perform/use/schedule/enumerate done; choose/registerClass/`$new` next
5. **Timers + Script helpers** — **done** (`console` / `hexdump` / timers / `gc` / `Cloak`; Worker stub; Profiler/Samplers partial)
6. **Stretch** — Stalker, CModule, Worker (real), full CallCount/Malloc samplers



## Non-goals (explicit)

- iOS / ObjC / non-arm64
- Full V8 runtime (QJS is the goauld runtime)
- Drop-in replacement for every Frida host binding (Node/Python) — wire protocol first; bindings later

