# Known issues

Track SELinux / Yama / linker-namespace denials here as they are discovered so they
are not re-debugged across milestones.

## Development baseline (milestone 1–5)

- Rooted emulator
- `setenforce 0` (SELinux permissive)
- `/proc/sys/kernel/yama/ptrace_scope` = `0`

## Observed denials / inject bugs

| Android / device | Context | Denial / symptom | Workaround |
|---|---|---|---|
| API 34 `google_apis` arm64 | Symbol resolve | Using `r-xp` map start as ELF base made `dlopen` point at a non-exec page (64K alignment gap) → SIGSEGV on remote call | Use `load_bias = map_start - file_offset` |
| API 34 | Remote call | First `PTRACE_CONT` stop is not always the planted BRK | `cont_until_pc` until BRK; treat SIGSEGV/SIGILL as hard errors |

## Known limitations

- Production attach on Yama `ptrace_scope=1` may require zygote-side injection (not in scope for early milestones).
- Linker namespaces (API 24+) can block `dlopen` of `/data/local/tmp/*.so` from **app** processes; prefer `--stage-into-app` / `run-as` copy into `/data/data/<pkg>/files/` on rooted devices. Native `sleep` targets are fine with `/data/local/tmp`.
- Java Technique A on-device: `jmethodID` may be an index (not `ArtMethod*`) — resolve via `Executable.artMethod`. `art_quick_generic_jni_trampoline` is often a local ELF symbol; fall back to stealing the quick entry from `System.currentTimeMillis`. App classes must be loaded via `ActivityThread.currentApplication().getClassLoader()`, not `FindClass`.
- QuickJS is single-threaded: ART hook threads only post to `goauld-js-worker` (owns Runtime; permanent JNI attach). Do not call QJS from binder/hook threads.
- `javaCallOriginal` / `this.method()`: JNI re-invoke of the live hooked ArtMethod recurses. Use a malloc'd ArtMethod clone + `art::ArtMethod::Invoke` (`args_size` in **bytes**) after `Thread::DecodeJObject`; never `CallMethod` on the hooked frame.
