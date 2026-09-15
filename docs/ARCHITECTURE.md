# goauld — Technical Architecture

This document explains how goauld actually works internally: the process split between
desktop and device, the ptrace-based injection sequence, the AArch64 inline-hooking
engine, the ART/Java hooking technique, the QuickJS scripting layer, and the wire
protocol that ties them together. It assumes familiarity with Rust, ELF, AArch64
assembly, and roughly how Frida behaves from the outside.

For usage (CLI flags, build commands) see [`README.md`](../README.md). For a running
log of device-specific quirks and their workarounds, see
[`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) — several of the design decisions below exist
*because of* an issue documented there, and are cross-referenced.

## 1. Why the process is split three ways

Everything that touches `ptrace()` must run **on the Android device**, as the same
uid/domain as (or with capabilities over) the target process. A desktop process talking
to the phone over `adb` cannot `ptrace_attach` an app process — there is no such
syscall over USB. So the system is split into three binaries with three different
privilege domains:

```
┌──────────────┐   adb push/shell    ┌─────────────────────────┐
│  goauld-host │ ─────────────────►  │ goauld-injector (arm64) │  ← runs ON the phone,
│  (desktop)   │                     │  ptrace + remote dlopen │     as root
└──────┬───────┘                     └───────────┬─────────────┘
       │ adb forward                             │ injects
       ▼                                         ▼
  TCP ↔ abstract socket              ┌─────────────────────────┐
                                     │ libgoauld_agent.so      │  ← runs INSIDE the
                                     │  hooks + QuickJS + ART  │     target process
                                     └─────────────────────────┘
```

- **`goauld-host`** (`crates/goauld-host`) is a plain desktop binary. It never links
  `ptrace` logic. All it knows how to do is shell out to `adb` (push files, run the
  injector, forward ports) and speak the wire protocol over a TCP socket.
- **`goauld-injector`** (`crates/goauld-injector`) is an AArch64 Android ELF binary,
  pushed to `/data/local/tmp/goauld/` and executed via `adb shell` (optionally through
  `su -c`). It links `goauld-inject`, which contains all the `ptrace` code, and is the
  *only* component that ever calls `ptrace()`.
- **`libgoauld_agent.so`** (`crates/goauld-agent`) is the cdylib that gets `dlopen`'d
  *inside* the target app's process by the injector. It links the hooking engine
  (`goauld-native-hook`), the ART bridge (`goauld-art-bridge`), and the scripting layer
  (`goauld-script`), and exposes them to the host over a Unix domain socket.

`goauld-inject` is written so the same crate builds on the desktop host (where it's a
no-op returning `TraceeError::Unsupported`) and on-device (where `#[cfg(...)]` compiles
in the real `ptrace` implementation). This lets `goauld-injector`'s business logic
(argument parsing, process discovery, error reporting) be unit-testable from a normal
`cargo test` on the desktop, while the actual syscalls only exist in the arm64/Android
build.

## 2. Wire protocol (`goauld-proto`)

Host ↔ agent framing is deliberately simple and symmetric in both directions
(`crates/goauld-proto/src/lib.rs`):

```
[u32 LE total_len] [u8 msg_type] [payload: total_len - 1 bytes]
```

`msg_type` is one of `Hello | ScriptLoad | ScriptUnload | RpcCall | RpcReply | Send | Log`.
Every payload except `Send` is a JSON blob (`serde_json`). `Send` mirrors Frida's
`send(payload, data)` — a JSON string plus an optional raw byte channel — and gets its
own sub-framing:

```
[u32 LE json_len] [json bytes] [u32 LE data_len] [data_len bytes, optional]
```

`Message::decode` / `Message::encode` are pure functions with a full round-trip test
suite, so the protocol itself has zero device dependency — it's tested directly on the
desktop. `Message::frame_len` lets a stream reader figure out how many bytes it needs to
buffer before attempting a decode, which `goauld-agent`'s `read_msg` and `goauld-host`'s
reader loop both rely on for TCP/socket framing.

## 3. Getting code into the process: injection

### 3.1 Discovery (`goauld-inject::discover`)

`enumerate_processes()` walks `/proc/<pid>/cmdline` (Android app processes report their
package name as argv[0], so this doubles as package→pid resolution) and
`resolve_abi()` sniffs `/proc/<pid>/maps` for `lib64/` vs `lib/` to filter out non-arm64
targets. `goauld-injector ps` and `goauld-host ps` both surface this.

### 3.2 Seizing the process (`goauld-inject::remote::Tracee`)

`Tracee::seize(pid)` lists every thread under `/proc/<pid>/task` and, per thread, tries
`PTRACE_SEIZE` + `PTRACE_INTERRUPT` first (Android's default), falling back to the
classic `PTRACE_ATTACH` on older/odd kernels. `PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL`
are set so a crashed target doesn't leave a hung tracer. Once every thread is stopped,
the main thread's register file is saved with `PTRACE_GETREGSET` (`NT_PRSTATUS`) so it
can be restored verbatim on detach — the target must resume exactly where it was, with
no observable trace of the injection.

### 3.3 Getting scratch memory without symbol dependencies

Rather than resolving `mmap`/`mprotect` addresses via a symbol table (which would race
with the exact ELF-parsing problem below), the injector finds an existing `svc #0`
instruction inside libc's already-executable, already-mapped `.text` and reuses it as a
syscall gadget:

1. `find_svc_gadget` scans `r-xp` mappings whose path contains `libc.so` / `libdl.so` /
   `/linker` for the four bytes `01 00 00 D4` (`svc #0`).
2. `remote_mmap_svc` sets `x8=222` (aarch64 `mmap`), the mmap args in `x0`–`x5`, points
   `pc` at the gadget, single-steps with `PTRACE_SYSCALL` twice (syscall-enter stop,
   then syscall-exit stop), and reads the result back from `x0`.
3. `remote_mprotect_svc` does the same with `x8=226` (`mprotect`) once the scratch page
   needs to flip from writable to executable.

This avoids ever needing a "landing pad" BRK instruction for the syscall path — the
kernel's own `PTRACE_SYSCALL` enter/exit stops are the synchronization primitive.

### 3.4 Resolving `dlopen` in the *target's* address space

The injector cannot use its own `dlsym("dlopen")` — it needs `dlopen`'s address inside
**the target process's** libc/libdl mapping, which has an independent ASLR slide. It:

1. Parses `/proc/<pid>/maps` for a mapping whose path matches `libdl.so` / `linker64` /
   `libc.so`, and computes the **load bias** as `map_start - file_offset` of that
   mapping (see [§3.6](#36-the-load-bias-bug) for why this must be done per-mapping,
   not from the first mapping of the file).
2. Reads the ELF file's bytes (from the device filesystem directly, or via
   `/proc/<pid>/root<path>` as a fallback) and walks `PT_DYNAMIC` → `DT_SYMTAB` /
   `DT_STRTAB` by hand (`find_dynsym_offset` in `goauld-inject::inject`) to find
   `dlopen`'s `st_value`. There is no ELF crate dependency here — it's ~80 lines of
   manual `Elf64_*` struct parsing, matching the equally hand-rolled GOT parser in
   `goauld-native-hook::got` and the libart symbol scanner in `goauld-art-bridge`.
3. Falls back to `android_dlopen_ext` (3-arg form, with a null `android_dlextinfo*`) if
   plain 2-arg `dlopen` isn't exported, to sidestep some linker-namespace ABI quirks.
4. Sanity-checks that the resolved address actually falls inside an `r-xp` mapping
   before calling it — a wrong load-bias calculation would otherwise manifest as a
   `SIGSEGV` deep inside `cont_until_pc` with a confusing stack.

### 3.5 The remote call itself

A small stub is assembled in the scratch page:

```
LDR X16, #12      ; +0
BLR X16           ; +4
BRK #0            ; +8   ← expected landing pad after the callee returns
<u64 dlopen_addr> ; +12
```

`remote_call_stub` writes the target's arguments into `x0..xN`, sets `pc` to the stub,
and calls `cont_until_pc`, which loops on `PTRACE_CONT` + `waitpid`, logging every
intermediate stop, until `pc` equals the `BRK`'s address (or the instruction right after
it — some kernels report the stop one instruction late). Any `SIGILL`/`SIGBUS`/
`SIGFPE`/`SIGSEGV` along the way is treated as a hard error rather than something to
retry through, per the lesson in `KNOWN_ISSUES.md` ("First `PTRACE_CONT` stop is not
always the planted BRK"). On success, `x0` (the `dlopen` return value / handle) is read
back and the original register file is restored.

The path in `inject_library` composes all of the above: mmap a scratch page → write the
library path string + the call stub into it → resolve `dlopen`/`android_dlopen_ext` →
mprotect the page `R-X` → run the stub → detach. If `--stage-into-app` is set, the
`.so` is first copied into `/data/data/<pkg>/files/` (via root `cp`+`chown`, or
`run-as` as a fallback) because Android's linker namespaces (API 24+) can refuse to
`dlopen` a path under `/data/local/tmp` from inside an **app** process — see
`KNOWN_ISSUES.md`.

### 3.6 The load-bias bug

This is worth calling out on its own because it's the canonical Android/arm64 injection
footgun and shows up in `KNOWN_ISSUES.md`: on 64K-page devices, a shared object's first
mapping in `/proc/pid/maps` is sometimes a read-only mapping at file offset 0, with
`.text` living in a *later*, separately-mapped, executable region. Computing
`load_bias = first_map_start - 0` and adding a symbol's `st_value` to it can land on a
non-executable page — `dlopen` then faults immediately on the remote call. The fix
implemented here (`find_so_load_bias`) is to compute the bias from *whichever* mapping
of the library actually contains the resolved symbol, using that mapping's own
`(start, file_offset)` pair, and to verify post-hoc that the resolved address falls in
an `r-xp` region before ever branching to it.

## 4. Native inline hooking (`goauld-native-hook`)

This crate implements Frida-style inline hooking on raw AArch64 machine code: given a
live function address, splice in a jump to attacker-controlled code, run a
enter/leave callback with full register access, and jump back — all without a disassembly
library beyond the sibling `arm_disassembler` crate (accessed through a 12-line
`Arm64Decoder` trait so `goauld-native-hook` has no direct Capstone/etc. dependency).

### 4.1 Patch layout

`ABS_BRANCH_LEN = 16` bytes is both the minimum instruction range overwritten at the
target and the shape of an absolute branch:

```
LDR X17, #8   ; 0x58000051
BR  X17       ; 0xD61F0220
<u64 target>  ; 8-byte literal
```

`attach()` (`patch.rs`) always overwrites *whole* instructions covering at least 16
bytes (`compute_patch_insns`/`MIN_PATCH_INSNS = 4`), never a partial instruction, since
AArch64 is fixed 4-byte width.

### 4.2 Relocating displaced instructions

The 4 (or more) instructions displaced from the target can't simply be copied into the
trampoline verbatim if they're PC-relative — their encoded offsets would now point at
the wrong place relative to the new emission address. `relocator.rs` walks each
decoded instruction and re-encodes it for its new location:

| Original | Trampoline rewrite |
|---|---|
| `B`/`BL` | 16-byte absolute branch/call to the *original* target |
| `B.cond` / `CBZ`/`CBNZ` / `TBZ`/`TBNZ` | inverted-condition branch that skips a 16-byte absolute jump to the *original* target, falling through otherwise (§4.2.1) |
| `ADR`/`ADRP` | re-encoded `ADR`, or `ADRP`+`ADD` if the new PC-relative delta is out of the ±1MB `ADR` range |
| `LDR` (literal) | re-encoded literal load if still in range, else a `LDR X17,#8; B #12; <addr>; LDR Xt,[X17]` expansion that materializes the absolute address into a scratch register (X17, matching the same convention as the abs-branch stub) |
| `BR`/`BLR`/`RET` | copied verbatim — register-indirect, no PC dependency |
| everything else | copied verbatim |

The trampoline always ends with a 16-byte absolute branch back to
`target + patch_len` (the first untouched instruction).

**4.2.1 — rewriting short conditional branches.** A `B.cond`/`CBZ`/`TBZ` only encodes a
19- or 14-bit signed offset, far too small to reach an arbitrary absolute address. The
relocator instead emits:

```
<inverted-cond> → skip   ; branches over the next 16 bytes if the ORIGINAL cond is false
LDR X17, #8
BR  X17
<u64 original_target>
skip:                    ; fallthrough continues here
```

i.e. it flips the sense of the test so that "condition true" falls through into the
absolute jump, and "condition false" skips straight past it — functionally identical to
the original short branch, just with the true-target reachable from anywhere in the
64-bit address space.

### 4.3 I-cache/D-cache coherency (`icache.rs`)

AArch64 does not guarantee I/D cache coherency for self-modified code. After writing
either the trampoline or the live patch, `clear_icache` reads `CTR_EL0` to get the
minimum D-cache/I-cache line size, then runs `dc cvau` (clean to point of unification)
over every line of the range followed by `dsb ish`, then `ic ivau` (invalidate) over the
same range followed by another `dsb ish` + `isb`. Skipping this is one of the classic
"my hook silently doesn't fire, or the CPU executes stale bytes" bugs on real hardware
(less visible on x86 emulators, which are cache-coherent by construction — a good reason
this only matters when testing on physical devices or a faithfully-modeled AVD).

### 4.4 Enter/leave dispatch and `CpuContext`

`build_enter_thunk` hand-assembles a prologue that:

1. `STP X29,X30,[SP,#-16]!` then `SUB SP,SP,#256` to open a stack frame shaped like
   [`CpuContext`](../crates/goauld-native-hook/src/trampoline.rs) (`x[31]`, `sp`, `pc`,
   `pstate` — deliberately mirroring `user_regs_struct` field order so a JS
   `this.context.x0` maps straight onto ptrace's own register layout).
2. `STP` pairs to spill `X0`–`X30` into that frame.
3. `MOV X0, SP` (context pointer) / `MOVZ W1, #hook_id` (dispatch key), then an absolute
   `BLR` to `goauld_dispatch_enter`.
4. Reloads `X0`–`X30` from the frame (the dispatcher may have mutated them — this is how
   a JS `onEnter` callback can rewrite arguments before the real function runs).
5. Tears down the frame and branches to the relocated trampoline.

`goauld_dispatch_enter`/`goauld_dispatch_leave` (`trampoline.rs`) are `extern "C"`
functions the thunk calls into. The hook registry (`HOOKS: Mutex<HashMap<HookId,
HookEntry>>`) is keyed by a monotonically-increasing `HookId`. When a hook has an
`on_leave` callback, `goauld_dispatch_enter` swaps `x[30]` (LR) for a leave-thunk address
and stashes the real LR on a **per-thread stack** (`saved_lr: Mutex<HashMap<tid,
Vec<u64>>>`) inside the `HookEntry` — necessary because the same hook can be re-entered
recursively or from multiple threads concurrently, and each return must unwind to the
correct original caller.

### 4.5 Patching live memory

On Android/aarch64, `attach()` allocates an RWX (or RW→mprotect-RX, W^X-friendly) scratch
page via `mmap`, copies the enter thunk + relocated trampoline into it, flushes caches,
then `mprotect`s the *target's* page(s) writable, overwrites the first 16 bytes with the
absolute-branch patch (padding any remainder up to `patch_len` with `NOP`), flushes
caches again, and records a `HookEntry` with the original bytes so `detach()` can restore
them byte-for-byte. On non-Android host builds the same relocation/allocation logic runs
(so the relocator and trampoline builder are unit-testable), but the live target patch is
skipped — the hook is only "recorded."

### 4.6 GOT/PLT hooking (`got.rs`)

For `Interceptor.replace`-style hooking at a library's *import* boundary rather than
inline in the callee's body, `got.rs` hand-parses `PT_DYNAMIC` → `DT_JMPREL` /
`DT_SYMTAB` / `DT_STRTAB` to find a symbol's `Elf64_Rela` entry and computes its GOT
slot as `base + r_offset`. `replace_got` then `mprotect`s just that page RW, swaps the
8-byte pointer, and returns the page to read-only — much cheaper than an inline patch
since it doesn't need relocation or a trampoline, but only intercepts calls that go
through the PLT (not direct/inlined calls).

## 5. Java/ART hooking (`goauld-art-bridge`)

This is "Technique A" in Frida's own terminology: instead of patching machine code
inside the JIT/AOT-compiled method body (fragile across ART versions and compilation
states), rewrite the `ArtMethod` C++ struct itself so ART's own dispatcher treats the
method as a **native** method and routes calls through a JNI bridge function goauld
controls.

### 5.1 Layout assumptions and calibration

`goauld-art-bridge::android::mod` hardcodes the Android 14 arm64 `ArtMethod` field
offsets it needs (`access_flags_` at `+4`, `data_` at `+16` — the
`entry_point_from_jni_` union member used for native methods — and
`entry_point_from_quick_compiled_code_` at `+24`), plus a 32-byte fallback struct size.
Because these offsets are ABI details that drift across ART releases, the crate never
trusts them blindly for the *size*: `calibrate_art_method_size` takes two adjacent
`ArtMethod*` (resolved via reflection for two different methods on the same class) and
uses their address delta as the true struct stride, sanity-bounded to `16..=512` bytes.
If calibration fails, it falls back to the hardcoded `ART_METHOD_SIZE_A14 = 32`.

### 5.2 Resolving a real `ArtMethod*`

Modern ART does **not** let you treat a JNI `jmethodID` as an `ArtMethod*` directly (it
can be an opaque index under "JNI ID indirection", and dereferencing it as a pointer
segfaults at a suspiciously small address — documented in `KNOWN_ISSUES.md`). Instead,
`resolve_art_method_ptr` goes through Java reflection:
`class.getDeclaredMethod(name, ...paramClasses)` → `java.lang.reflect.Executable`'s
private `long artMethod` field, read via `env.get_field(reflected, "artMethod", "J")`.
This is the same pointer ART's own interpreter/compiler use internally, with no
indirection layer in between.

Resolving *application* classes also can't use `FindClass` from a thread that was
`AttachCurrentThread`'d — that JNIEnv only sees the boot/system classloader.
`find_app_class` instead walks `ActivityThread.currentApplication() → getClassLoader()
→ loadClass(name)`, which is why hooks can't be installed before the `Application`
object exists.

### 5.3 The rewrite

`install_hook_env` backs up `art_method_size()` bytes of the live `ArtMethod`, resolves
`art_quick_generic_jni_trampoline`'s address (first via `dlsym`, then falling back to a
hand-rolled full `.symtab` scan of `libart.so` — the symbol is frequently **local**, not
in `.dynsym` — and if even that fails, by "stealing" the
`entry_point_from_quick_compiled_code_` off `java.lang.System.currentTimeMillis`, a
method guaranteed to already be native), then in a single unsafe write:

```
access_flags |= kAccNative;             // 0x0100
access_flags &= !(kAccFastNative | kAccCriticalNative | <2 fast-path bits>);
data_        = <one of 16 hand-written bridge_fn thunks, per hook slot>;
entry_point_from_quick_compiled_code_ = art_quick_generic_jni_trampoline;
```

From this point, any call to the hooked method — from managed (interpreted/JIT/AOT) Java
code — goes through ART's generic JNI trampoline exactly as if it were a real `native`
method, which lands in `bridge_fn_for_slot(slot)`. There are 16 statically-defined
`extern "system" fn bridgeN(...)` thunks (`bridge0`..`bridge15`, via the `def_bridge!`
macro) because a native Rust closure can't be handed to ART as a raw C function pointer
— each live hook claims one free slot out of `MAX_SLOTS = 16`, capping concurrent
Technique-A hooks at 16 in the current implementation.

*(Note: the milestone/`KNOWN_ISSUES` notes describe the JNI signature as `(I)I` in the
working test target — the bridge thunks and the `jint` marshalling in `dispatch_slot`
are shaped around that single-int-arg/int-return signature for now; extending the
argument marshalling to arbitrary JNI shorty signatures is future work, not yet wired
end-to-end.)*

### 5.4 Dispatch: bridge → JS worker → back

`dispatch_slot` (called on whatever thread ART invoked the method on — could be a
binder thread, a UI thread, anything) does the following, guarding against re-entrancy
with a thread-local `IN_BRIDGE`/`IN_ORIGINAL` pair:

1. Looks up the `LiveHook` for this slot from a `RwLock<Vec<Option<LiveHook>>>`.
2. Promotes the JNI `thiz` to a `GlobalRef` (so it survives being handed to a *different*
   thread — the QuickJS worker — with its own JNIEnv).
3. Stashes `(env, thiz, art_method)` into thread-locals (`CUR_ENV`/`CUR_THIZ`/`CUR_ART`)
   so `js_call_original` can later find them.
4. Calls `try_js_invoke`, which is wired (once, via `set_js_invoke_callback`) to
   `goauld_script::bindings::art_js_invoke_cb` — this does **not** run JS on the current
   (ART) thread; it posts a `JavaInvokeJob` onto `goauld-script`'s dedicated worker
   thread (§6) and blocks on a reply channel with a 10s timeout.
5. If the JS side had no registered `implementation` for this method, or the worker
   timed out, the bridge falls back to `x + 1000` as an observable "the patch fired but
   nothing hooked it" sentinel used by the integration tests.

### 5.5 `callOriginal` without re-entering the hook

Because the live `ArtMethod` has been permanently rewritten to be native, there is no
"original bytecode" to fall back into. Instead, `install_hook_env` heap-clones (`malloc`
+ `memcpy`) the **pre-patch** `ArtMethod` bytes into `backup_art`, and
`invoke_backup_art_method` calls `art::ArtMethod::Invoke` (resolved by mangled symbol
name via the same libart symtab scanner) directly against that clone, using
`art::Thread::Current()` and `Thread::DecodeJObject` (also resolved by mangled symbol)
to turn the JNI `thiz` handle back into a raw `mirror::Object*`. This sidesteps the
documented footgun of calling `env->CallIntMethod` (or similar) on the *live*, hooked
frame, which would just recurse back into the same bridge. `args_size` is passed to
`ArtMethod::Invoke` in **bytes**, not argument count — a detail called out explicitly in
`KNOWN_ISSUES.md` because getting it wrong corrupts the callee's argument array silently.

### 5.6 Android framework API tracing

`start_android_api_trace` reuses the native inline-hook engine (not the ArtMethod
rewrite) by hooking `art_quick_invoke_stub` / `art_quick_invoke_static_stub` (the
runtime→managed call bridges — falling back to `ArtMethod::Invoke` itself on older
images where those quick stubs aren't resolvable). Its `on_enter` callback
(`on_invoke_enter`) reads the `ArtMethod*` out of `x0`, calls
`ArtMethod::GetDeclaringClassDescriptor` (or falls back to `PrettyMethod`) to get a
class descriptor like `Landroid/app/Activity;`, converts it to dotted form, and checks
it against a configurable set of package prefixes (default: `android.`, `androidx.`,
`java.`, `javax.`, `com.android.`, `dalvik.` — i.e. platform + Jetpack + core Java per
the [Android API reference](https://developer.android.com/reference)). A matching call
gets `PrettyMethod`'d (with or without signature) and emitted as a
`{"type":"android-api","n":N,"method":"...","shorty":"…","args":[…]}` `send()` payload.

**Argument decoding** reads the ART `uint32_t* args` / `args_size` / `shorty` registers
from `art_quick_invoke_{,static_}stub` (`x1`/`x2`/`x5`) or `ArtMethod::Invoke`
(`x2`/`x3`/`x5`). Primitives are typed; `java.lang.String` refs are expanded to
`{"t":"string","v":"…"}` via `art::mirror::String::ToModifiedUtf8` (klass cached from a
JNI-created String at trace start); all other objects/arrays stay as compressed-ref hex
`{"t":"ref","v":"0x…"}`. Optional host `--java-hooks` also installs Technique-A
`Java.use` hooks that `send` `{type:"java-api",…,args:[…]}` with the full JS `arguments`
list.

Because
`art::ArtMethod::PrettyMethod` returns a libc++ `std::string` by value, and AArch64's
AAPCS64 calling convention returns non-trivial C++ objects via a hidden `x8` sret
pointer, the call is made through a small hand-written `asm!` block
(`call_pretty_method_aarch64`) that sets `x8`/`x0`/`w1` explicitly and `blr`s through
`x16` (keeping the callee address out of the argument registers so it can't be clobbered
by the argument moves). The same sret pattern is used for `String::ToModifiedUtf8`.
The returned `std::string`'s bytes are then read directly by
replicating libc++'s short-string-optimization layout (bit 0 of byte 0 = "is heap
allocated"; heap case reads `size`/`ptr` at fixed offsets and frees the buffer
afterward via `operator delete`).

A thread-local `IN_TRACE` flag prevents the trace hook's own bookkeeping (string
formatting, JSON escaping) from re-triggering itself if any of that machinery happens to
call back into a traced method.

## 6. Scripting layer (`goauld-script`)

### 6.1 Single-writer QuickJS

QuickJS (via `rquickjs`) is **not thread-safe to share across threads without external
synchronization**, and ART hook callbacks can fire from arbitrary app threads
concurrently. goauld's answer is architectural rather than lock-based: exactly one
`goauld-js-worker` OS thread owns the `Runtime`/`Context` for the process's lifetime
(`js_queue::ensure_started`), and every other thread — the agent's socket-reader thread,
every ART hook callback thread — only ever *posts a job* (`JsJob::Eval` /
`JsJob::JavaInvoke`) over an `mpsc::channel` and blocks on a `sync_channel` reply with a
timeout. `QuickJsEngine` is manually marked `unsafe impl Send + Sync` on the strength of
this invariant, not because QuickJS itself is actually safe to touch concurrently.

Separately, `JsLock` (`js_lock.rs`) provides thread-*local* re-entrancy tracking (a
`Cell<bool>` per thread plus a global depth counter) for the case where JS calling into
a hook triggers another hook that calls back into JS *on the same thread* — that nested
call must not deadlock trying to re-acquire a lock it already holds.

### 6.2 Frida-shaped JS surface

`bindings.rs` installs a Rust-backed `__goauld` helper object into the QuickJS global
scope (`send`, `findExport`, `findBase`, `readUtf8`, `attach`, `javaHook`,
`javaCallOriginal`, `traceAndroidApi`, `androidToast`), then evaluates a JS **prelude**
(`const PRELUDE`, inline in `bindings.rs`) that layers Frida's actual API shape on top:
`Module.findExportByName`/`findBaseAddress`, `Memory.read*`, `Interceptor.attach` (with
an `onEnter`/`invocation.context.x0..x7` object mirroring Frida's `InvocationContext`),
and — the most involved piece — `Java`:

- `Java.use(className)` returns a `Proxy` whose property access builds a `{_key,
  _sig}` method descriptor; setting `.implementation = fn` records the JS function in
  `__javaImpls[key]` and calls the native `__goauld.javaHook(class, method, sig)`,
  which is what actually triggers the ArtMethod rewrite in §5.3.
- Inside that JS implementation function, `this.<methodName>(x)` (Frida's idiom for
  "call the original") resolves through `__goauld_java_invoke`'s synthesized `self`
  object to `__goauld.javaCallOriginal(key, x)`, which calls back into Rust
  (`goauld_art_bridge::js_call_original`) and from there into §5.5's
  `invoke_backup_art_method` — using the `(env, thiz, art)` triple stashed in
  thread-locals by `dispatch_slot` for the *currently executing* hook (this only works
  because the JS worker runs the callback synchronously while the ART hook thread is
  still blocked waiting on the reply channel — the thread-local context is still valid).
- `Java.available` is computed by checking whether `libart.so` is a loaded module at
  all, so scripts can branch on non-Android hosts.
- `android.app.ActivityThread` / `android.widget.Toast` / `java.lang.String` get
  hand-written JS shims (rather than going through the general Technique-A path) so a
  script can show a toast without needing a live ART hook — `Toast.makeText(...).show()`
  routes to `__goauld.androidToast`, which loads a tiny embedded `classes.dex`
  (`goauld.ToastBridge`, via `InMemoryDexClassLoader`) and posts through the real
  framework `Toast` API on the app's own classloader (§6.3).

`worker_java_invoke` is the glue that actually runs on the JS worker thread for each
`JavaInvokeJob`: it sets the ART hook thread-local context (so `javaCallOriginal` inside
the *worker* thread's JS execution resolves correctly), calls a JS dispatcher function
(`__goauld_java_invoke`) that looks up `__javaImpls[key]` and invokes it, catches thrown
JS exceptions (sent back over the wire as `java-invoke-err:<message>` rather than
crashing the hook), and clears the context afterward.

### 6.3 Toast bridge (`android/toast.rs`)

A standalone illustration of "run framework Java code from the agent, not from the
target app's own code": an embedded pre-compiled `classes.dex` containing a
`goauld.ToastBridge.show(Context, String)` static method is loaded via
`dalvik/system/InMemoryDexClassLoader`, parented to the app's own `ClassLoader`
(`ActivityThread.currentApplication().getClassLoader()`) so it can resolve
`android.widget.Toast`, and invoked directly through JNI — the same idea as Frida's
published ["simple Android toast" codeshare](https://codeshare.frida.re/@yodiaditya/simple-android-toast/),
reimplemented without a JS-side `Java.use` shim for the toast class itself.

## 7. Agent runtime (`goauld-agent`)

The cdylib's entire bootstrap is an ELF constructor:

```rust
#[ctor::ctor]
fn agent_init() { /* spawn a thread; return immediately */ }
```

`dlopen()` runs ELF constructors synchronously as part of the call, so the injector's
remote `dlopen` call would deadlock (or at least stall the ptrace'd thread indefinitely)
if `agent_init` did any blocking work inline — it immediately spawns a detached thread
(`run_agent`) and returns, letting the injector's remote call complete normally.

`run_agent` creates one process-wide `ScriptEngine` and opens a listening socket:
on Android, a raw `AF_UNIX` socket bound into the **abstract namespace**
(`sun_path[0] = 0`, named `goauld-agent-<pid>`) — chosen over a filesystem socket
because it needs no writable directory inside the app's sandbox and is automatically
reclaimed on process exit; on non-Android host builds (for `cargo test`), a normal
filesystem `UnixListener` under `$TMPDIR` instead. Each accepted connection gets a
`Hello{pid, package, sdk_int, abi}` handshake, spawns an outbound pump thread that
drains the `ScriptEngine`'s `mpsc::Sender<Message>` onto the socket, and runs an inbound
loop dispatching `ScriptLoad`/`ScriptUnload`/`RpcCall` messages until the host
disconnects — at which point it loops back to `accept()` for the next session (a fresh
`adb forward` + reconnect from the host reuses the same in-process agent and its
already-installed hooks).

## 8. Host CLI (`goauld-host`)

Everything here is `adb` orchestration plus the client side of the wire protocol —
there is intentionally no `libc`/`ptrace` dependency in this crate. Key flows:

- **`deploy`** — `adb push`es `goauld-injector` and `libgoauld_agent.so` to
  `/data/local/tmp/goauld/`, `chmod`s them (`755` executable, `644` for the `.so`).
- **`inject`** — deploys, then runs the on-device injector via `su -c '...'` (falling
  back to a non-root shell invocation if `su` isn't available), passing through
  `--pid`/`--package`/`--so`/`--stage-into-app`.
- **`attach`** — `adb forward tcp:<local> localabstract:goauld-agent-<pid>` (removing
  any stale forward first), then a plain `TcpStream::connect(("127.0.0.1", port))`,
  after which it speaks the exact same `goauld-proto` framing the agent's Unix socket
  side speaks — `adb forward` is what bridges an abstract Unix socket on the phone to a
  TCP port on the desktop. From here it can push a `ScriptLoad`, wait (with a timeout)
  for a `send()` payload matching `--expect-send`, and print `Log`/`Send` traffic.
- **`trace syscalls`** — runs `goauld-injector trace-syscalls` on-device (no agent
  `.so` involved at all — this path only needs `goauld-inject::syscall_trace`, which
  seizes every thread with `PTRACE_SYSCALL` + `PTRACE_O_TRACE{CLONE,FORK,VFORK}` so new
  threads spawned mid-trace are automatically picked up, decodes syscall numbers via a
  small `aarch64` syscall-number → name table, and prints `enter(args…) = retval` lines
  filtered by an optional name-substring list).
- **`trace java`** — the full pipeline: deploy → inject the agent → `adb forward` →
  connect → push a `ScriptLoad` (either a built-in fixture or `--script`) that calls
  `__goauld.traceAndroidApi(filter, max_events)` and optionally installs Technique-A
  `--java-hooks` → stream `android-api` / `send()` events for up to `--max-wait-secs`.
- **`stress`** — a throughput/overhead harness: floods the agent with N `send()`
  round-trips of a configurable payload size against `java-target`, sampling APK-side
  tick counters before and during, to characterize the cost of the hook + QuickJS +
  socket pipeline under load.

## 9. Repository map

| Crate | Runs where | Responsibility |
|---|---|---|
| `goauld-proto` | both | Wire framing + message types (§2) |
| `goauld-inject` | on-device (no-ops on host) | `ptrace` seize/detach, remote call, ELF symbol resolution, syscall tracer (§3) |
| `goauld-injector` | on-device (arm64 bin) | CLI wrapping `goauld-inject`: `ps` / `inject` / `trace-syscalls` |
| `goauld-native-hook` | in-process (agent) | AArch64 decoder adapter, instruction relocator, inline-hook patcher, enter/leave thunks, icache maintenance, GOT/PLT hooking (§4) |
| `goauld-art-bridge` | in-process (agent) | ArtMethod struct rewrite, JNI/reflection plumbing, `callOriginal`, Android API tracer, toast bridge (§5) |
| `goauld-script` | in-process (agent) | QuickJS worker thread, Frida-shaped JS globals, `Java.use` prelude (§6) |
| `goauld-agent` | in-process (agent, cdylib) | ELF-ctor bootstrap, socket server, message pump (§7) |
| `goauld-host` | desktop | `adb` orchestration CLI, wire-protocol client (§8) |

Disassembly is a path dependency on the sibling `arm_disassembler` crate, consumed only
through `goauld-native-hook::decoder::Arm64Decoder` — no other crate depends on it
directly.

## 10. Build & test topology

- `cargo build -p goauld-host --release` builds only the desktop CLI and its
  dependency graph (`goauld-proto`); nothing arm64-specific is compiled.
- `./scripts/build-android.sh` cross-compiles `goauld-injector` and
  `libgoauld_agent.so` for `aarch64-linux-android` via the pinned NDK in `ndk.txt`,
  producing `dist/android-arm64/{goauld-injector,libgoauld_agent.so}`.
- Unit tests run on the desktop host for everything that has a host-side code path:
  protocol round-trips, the relocator/encoder (against literal instruction bytes and
  cross-checked by re-decoding), the ART bridge's Technique-A struct-copy logic (against
  plain heap buffers standing in for a real `ArtMethod`), and the full QuickJS
  `Java.use`/`implementation`/`this.method()`/exception-handling flow (against the
  in-process `js_queue` worker, without any real ART underneath — see the
  `js_engine_*` + Java tests in `crates/goauld-script/src/engine.rs`; run both engines via `./scripts/test-js-engines.sh`).
- `./scripts/run_milestone.sh <1..8|unit|device-smoke|all>` and `./scripts/emulator.sh`
  drive the device-dependent integration milestones listed in `README.md` against a
  rooted AVD (SELinux permissive, `ptrace_scope=0`).
