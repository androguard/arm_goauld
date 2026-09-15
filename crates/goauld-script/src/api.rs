//! Frida-shaped JS API surface (§6.2) — Rust-side implementations.
//!
//! Bound into QuickJS; also callable from Rust tests.

use goauld_native_hook::patch::{attach, detach, HookError};
use goauld_native_hook::trampoline::{CpuContext, HookCallbacks};

#[derive(Debug, Clone, Copy)]
pub struct NativePointer(pub u64);

impl NativePointer {
    pub fn add(&self, n: i64) -> Self {
        Self((self.0 as i64).wrapping_add(n) as u64)
    }
    pub fn sub(&self, n: i64) -> Self {
        Self((self.0 as i64).wrapping_sub(n) as u64)
    }
    pub fn to_u64(&self) -> u64 {
        self.0
    }
}

pub mod memory {
    use super::NativePointer;
    use std::alloc::{alloc_zeroed, Layout};
    use std::fs;

    pub fn read_u8(p: NativePointer) -> u8 {
        unsafe { *(p.0 as *const u8) }
    }
    pub fn read_u16(p: NativePointer) -> u16 {
        unsafe { *(p.0 as *const u16) }
    }
    pub fn read_u32(p: NativePointer) -> u32 {
        unsafe { *(p.0 as *const u32) }
    }
    pub fn read_u64(p: NativePointer) -> u64 {
        unsafe { *(p.0 as *const u64) }
    }
    pub fn read_pointer(p: NativePointer) -> NativePointer {
        NativePointer(read_u64(p))
    }
    pub fn write_u8(p: NativePointer, v: u8) {
        unsafe { *(p.0 as *mut u8) = v }
    }
    pub fn write_u16(p: NativePointer, v: u16) {
        unsafe { *(p.0 as *mut u16) = v }
    }
    pub fn write_u32(p: NativePointer, v: u32) {
        unsafe { *(p.0 as *mut u32) = v }
    }
    pub fn write_u64(p: NativePointer, v: u64) {
        unsafe { *(p.0 as *mut u64) = v }
    }
    pub fn write_pointer(p: NativePointer, v: NativePointer) {
        write_u64(p, v.0)
    }
    pub fn read_byte_array(p: NativePointer, len: usize) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(p.0 as *const u8, len).to_vec() }
    }
    pub fn write_byte_array(p: NativePointer, bytes: &[u8]) {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), p.0 as *mut u8, bytes.len());
        }
    }
    pub fn read_c_string(p: NativePointer) -> String {
        unsafe {
            let mut len = 0usize;
            let base = p.0 as *const u8;
            while *base.add(len) != 0 {
                len += 1;
                if len > 1 << 20 {
                    break;
                }
            }
            String::from_utf8_lossy(std::slice::from_raw_parts(base, len)).into_owned()
        }
    }
    pub fn read_utf8_string(p: NativePointer, len: Option<usize>) -> String {
        match len {
            Some(n) => String::from_utf8_lossy(&read_byte_array(p, n)).into_owned(),
            None => read_c_string(p),
        }
    }

    /// Heap allocation (leaked until process exit — Frida pins via JS refs).
    pub fn alloc(size: usize) -> NativePointer {
        let size = size.max(1);
        #[cfg(unix)]
        {
            let p = unsafe { libc::malloc(size) };
            if !p.is_null() {
                unsafe { std::ptr::write_bytes(p as *mut u8, 0, size) };
                return NativePointer(p as u64);
            }
        }
        let layout =
            Layout::from_size_align(size, 16).unwrap_or_else(|_| Layout::from_size_align(size, 1).unwrap());
        let p = unsafe { alloc_zeroed(layout) };
        NativePointer(p as u64)
    }

    /// Page-aligned anonymous mapping (preferred for `MemoryAccessMonitor` targets).
    pub fn alloc_anonymous(size: usize) -> NativePointer {
        let ps = page_size() as usize;
        let size = size.max(ps);
        let size = (size + ps - 1) & !(ps - 1);
        #[cfg(unix)]
        {
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p != libc::MAP_FAILED {
                return NativePointer(p as u64);
            }
        }
        alloc(size)
    }

    pub fn alloc_utf8_string(s: &str) -> NativePointer {
        let mut bytes = s.as_bytes().to_vec();
        bytes.push(0);
        let p = alloc(bytes.len());
        write_byte_array(p, &bytes);
        p
    }

    pub fn copy(dst: NativePointer, src: NativePointer, n: usize) {
        unsafe {
            std::ptr::copy_nonoverlapping(src.0 as *const u8, dst.0 as *mut u8, n);
        }
    }

    pub fn dup(address: NativePointer, size: usize) -> NativePointer {
        let p = alloc(size);
        copy(p, address, size);
        p
    }

    pub fn protect(address: NativePointer, size: usize, protection: &str) -> bool {
        let page = page_size();
        let start = address.0 & !(page - 1);
        let end = (address.0 + size as u64 + page - 1) & !(page - 1);
        let len = (end - start) as usize;
        #[cfg(unix)]
        {
            let prot = parse_prot(protection);
            let rc = unsafe { libc::mprotect(start as *mut libc::c_void, len, prot) };
            rc == 0
        }
        #[cfg(not(unix))]
        {
            let _ = (protection, len, start);
            false
        }
    }

    pub fn query_protection(address: NativePointer) -> Option<String> {
        crate::api::module::find_range_by_address(address).map(|r| r.protection)
    }

    #[cfg(unix)]
    fn parse_prot(s: &str) -> libc::c_int {
        let mut p = libc::PROT_NONE;
        let chars: Vec<char> = s.chars().take(3).collect();
        if chars.first() == Some(&'r') {
            p |= libc::PROT_READ;
        }
        if chars.get(1) == Some(&'w') {
            p |= libc::PROT_WRITE;
        }
        if chars.get(2) == Some(&'x') {
            p |= libc::PROT_EXEC;
        }
        p
    }

    pub fn page_size() -> u64 {
        #[cfg(unix)]
        {
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }.max(4096)
        }
        #[cfg(not(unix))]
        {
            4096
        }
    }

    pub fn scan_sync(address: NativePointer, size: usize, pattern: &str) -> Vec<(u64, usize)> {
        let needle = parse_scan_pattern(pattern);
        if needle.is_empty() || size < needle.len() {
            return Vec::new();
        }
        let addr = address.0 & 0x00FF_FFFF_FFFF_FFFF;
        let hay = unsafe { std::slice::from_raw_parts(addr as *const u8, size) };
        let mut out = Vec::new();
        let nlen = needle.len();
        // Cap hits so a broad pattern cannot blow memory.
        const MAX_HITS: usize = 4096;
        for i in 0..=(hay.len() - nlen) {
            let mut ok = true;
            for (j, (byte, mask)) in needle.iter().enumerate() {
                if hay[i + j] & mask != *byte & mask {
                    ok = false;
                    break;
                }
            }
            if ok {
                out.push((addr + i as u64, nlen));
                if out.len() >= MAX_HITS {
                    break;
                }
            }
        }
        out
    }

    fn parse_scan_pattern(pattern: &str) -> Vec<(u8, u8)> {
        // Optional `: mask` suffix ignored for now except full-byte masks via `??`.
        // Also accept continuous hex like "41424344" or mixed "41 42??44".
        let main = pattern.split(':').next().unwrap_or(pattern).trim();
        let mut out = Vec::new();
        if main.is_empty() {
            return out;
        }
        // If there is no whitespace and length is even hex-ish, treat as packed bytes.
        let has_space = main.chars().any(|c| c.is_whitespace());
        if !has_space && main.len() >= 2 && main.len() % 2 == 0 && !main.contains('?') {
            let mut i = 0;
            while i + 2 <= main.len() {
                if let Ok(b) = u8::from_str_radix(&main[i..i + 2], 16) {
                    out.push((b, 0xff));
                } else {
                    out.clear();
                    break;
                }
                i += 2;
            }
            if !out.is_empty() {
                return out;
            }
        }
        for tok in main.split_whitespace() {
            if tok == "??" || tok == "?" {
                out.push((0, 0));
                continue;
            }
            if tok.len() == 2 && tok.as_bytes()[0] == b'?' {
                let lo = u8::from_str_radix(&tok[1..], 16).unwrap_or(0);
                out.push((lo, 0x0f));
                continue;
            }
            if tok.len() == 2 && tok.as_bytes()[1] == b'?' {
                let hi = u8::from_str_radix(&tok[..1], 16).unwrap_or(0) << 4;
                out.push((hi, 0xf0));
                continue;
            }
            // "41??" style inside a token — expand nibble wildcards pairwise.
            if tok.len() > 2 && tok.len() % 2 == 0 {
                let bytes = tok.as_bytes();
                let mut ok = true;
                let mut local = Vec::new();
                let mut i = 0;
                while i + 2 <= bytes.len() {
                    let a = bytes[i] as char;
                    let b = bytes[i + 1] as char;
                    let pair: String = [a, b].iter().collect();
                    if pair == "??" {
                        local.push((0, 0));
                    } else if a == '?' {
                        if let Ok(lo) = u8::from_str_radix(&pair[1..], 16) {
                            local.push((lo, 0x0f));
                        } else {
                            ok = false;
                            break;
                        }
                    } else if b == '?' {
                        if let Ok(hi) = u8::from_str_radix(&pair[..1], 16) {
                            local.push((hi << 4, 0xf0));
                        } else {
                            ok = false;
                            break;
                        }
                    } else if let Ok(v) = u8::from_str_radix(&pair, 16) {
                        local.push((v, 0xff));
                    } else {
                        ok = false;
                        break;
                    }
                    i += 2;
                }
                if ok {
                    out.extend(local);
                    continue;
                }
            }
            if let Ok(b) = u8::from_str_radix(tok, 16) {
                out.push((b, 0xff));
            }
        }
        out
    }

    pub fn maps_readable() -> bool {
        fs::metadata("/proc/self/maps").is_ok()
    }

    #[cfg(test)]
    mod scan_tests {
        use super::*;

        #[test]
        fn packed_and_wildcard_patterns() {
            let buf = [0x47u8, 0x4f, 0x41, 0x55, 0xaa, 0x4c];
            let p = NativePointer(buf.as_ptr() as u64);
            let hits = scan_sync(p, buf.len(), "474f4155");
            assert_eq!(hits.len(), 1);
            let hits2 = scan_sync(p, buf.len(), "47 4f ?? 55");
            assert_eq!(hits2.len(), 1);
        }
    }
}

pub mod process {
    use super::module::{self, ModuleInfo, RangeInfo};
    use super::NativePointer;
    use std::env;
    use std::path::PathBuf;

    #[derive(Debug, Clone)]
    pub struct ProcessInfo {
        pub id: u32,
        pub arch: &'static str,
        pub platform: &'static str,
        pub page_size: u64,
        pub pointer_size: u32,
        pub code_signing_policy: &'static str,
    }

    pub fn info() -> ProcessInfo {
        ProcessInfo {
            id: std::process::id(),
            arch: "arm64",
            platform: if cfg!(target_os = "android") {
                "linux"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else if cfg!(target_os = "macos") {
                "darwin"
            } else {
                "linux"
            },
            page_size: super::memory::page_size(),
            pointer_size: 8,
            code_signing_policy: "optional",
        }
    }

    pub fn get_current_dir() -> String {
        env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "/".into())
    }

    pub fn get_home_dir() -> String {
        env::var("HOME")
            .or_else(|_| env::var("ANDROID_DATA").map(|d| format!("{d}/data")))
            .unwrap_or_else(|_| "/data".into())
    }

    pub fn get_tmp_dir() -> String {
        env::temp_dir().display().to_string()
    }

    pub fn is_debugger_attached() -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
                for line in s.lines() {
                    if let Some(rest) = line.strip_prefix("TracerPid:") {
                        let n: i32 = rest.trim().parse().unwrap_or(0);
                        return n != 0;
                    }
                }
            }
        }
        false
    }

    pub fn get_current_thread_id() -> u64 {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            unsafe { libc::syscall(libc::SYS_gettid) as u64 }
        }
        #[cfg(target_os = "macos")]
        {
            let mut tid = 0u64;
            unsafe {
                libc::pthread_threadid_np(0, &mut tid);
            }
            tid
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        {
            0
        }
    }

    pub fn main_module() -> Option<ModuleInfo> {
        module::enumerate_modules().into_iter().next()
    }

    pub fn find_module_by_name(name: &str) -> Option<ModuleInfo> {
        module::find_module_by_name(name)
    }

    pub fn find_module_by_address(addr: NativePointer) -> Option<ModuleInfo> {
        module::find_module_by_address(addr)
    }

    pub fn enumerate_modules() -> Vec<ModuleInfo> {
        module::enumerate_modules()
    }

    pub fn enumerate_ranges(protection: &str, coalesce: bool) -> Vec<RangeInfo> {
        module::enumerate_ranges(protection, coalesce)
    }

    pub fn find_range_by_address(addr: NativePointer) -> Option<RangeInfo> {
        module::find_range_by_address(addr)
    }

    pub fn exe_path() -> Option<PathBuf> {
        std::fs::read_link("/proc/self/exe").ok()
    }
}

pub mod thread {
    use super::module;
    use super::NativePointer;
    use parking_lot::Mutex;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Debug, Clone)]
    pub struct ThreadInfo {
        pub id: u64,
        pub name: Option<String>,
        pub state: String,
    }

    pub fn sleep(delay_secs: f64) {
        let nanos = (delay_secs.max(0.0) * 1_000_000_000.0) as u64;
        std::thread::sleep(Duration::from_nanos(nanos));
    }

    pub fn enumerate_threads() -> Vec<ThreadInfo> {
        let path = Path::new("/proc/self/task");
        let Ok(rd) = fs::read_dir(path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for ent in rd.flatten() {
            let tid: u64 = ent.file_name().to_string_lossy().parse().unwrap_or(0);
            if tid == 0 {
                continue;
            }
            if crate::cloak::has_thread(tid) {
                continue;
            }
            let name = fs::read_to_string(ent.path().join("comm"))
                .ok()
                .map(|s| s.trim_end_matches('\n').to_string());
            let state = fs::read_to_string(ent.path().join("stat"))
                .ok()
                .and_then(|s| {
                    // comm is in parens; state is after closing paren.
                    let idx = s.rfind(')')?;
                    s[idx + 1..].split_whitespace().next().map(|c| match c {
                        "R" => "running",
                        "S" => "waiting",
                        "D" => "uninterruptible",
                        "T" | "t" => "stopped",
                        "Z" => "halted",
                        _ => "running",
                    }.to_string())
                })
                .unwrap_or_else(|| "running".into());
            out.push(ThreadInfo { id: tid, name, state });
        }
        out.sort_by_key(|t| t.id);
        out
    }

    /// Frida-style backtrace. `accurate` walks x29 frames when possible; otherwise
    /// (and for `fuzzy`) scans the current stack for executable return addresses.
    pub fn backtrace(accurate: bool, max_frames: usize) -> Vec<NativePointer> {
        let max_frames = max_frames.clamp(1, 64);
        let mut frames = if accurate {
            backtrace_fp(max_frames)
        } else {
            Vec::new()
        };
        if frames.len() < 2 {
            let fuzzy = backtrace_fuzzy(max_frames);
            if frames.is_empty() {
                frames = fuzzy;
            } else {
                // Fill remaining slots from fuzzy without dupes.
                let mut seen: std::collections::HashSet<u64> =
                    frames.iter().map(|p| p.0).collect();
                for p in fuzzy {
                    if seen.insert(p.0) {
                        frames.push(p);
                        if frames.len() >= max_frames {
                            break;
                        }
                    }
                }
            }
        }
        frames
    }

    /// Snapshot of live threads keyed by tid (for observers).
    pub fn thread_map() -> std::collections::HashMap<u64, ThreadInfo> {
        enumerate_threads()
            .into_iter()
            .map(|t| (t.id, t))
            .collect()
    }

    // --- Thread observer (poll /proc/self/task) ---

    #[derive(Clone)]
    struct ObserverState {
        stop: Arc<AtomicBool>,
    }

    static OBSERVER: Mutex<Option<ObserverState>> = Mutex::new(None);

    /// Start polling for thread add/remove/rename. Events are delivered as JSON
    /// lines via `on_event(json)` from a background thread (caller should post to JS).
    pub fn start_thread_observer(on_event: impl Fn(String) + Send + Sync + 'static) {
        stop_thread_observer();
        let stop = Arc::new(AtomicBool::new(false));
        {
            *OBSERVER.lock() = Some(ObserverState {
                stop: stop.clone(),
            });
        }
        let on_event = Arc::new(on_event);
        std::thread::Builder::new()
            .name("goauld-thread-obs".into())
            .spawn(move || {
                let mut prev = thread_map();
                // Emit initial snapshot as onAdded for each existing thread? Frida does
                // not; only subsequent changes. Keep prev seeded.
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let now = thread_map();
                    for (id, t) in &now {
                        if let Some(old) = prev.get(id) {
                            let old_name = old.name.clone().unwrap_or_default();
                            let new_name = t.name.clone().unwrap_or_default();
                            if old_name != new_name {
                                let json = serde_json::json!({
                                    "kind": "renamed",
                                    "id": t.id,
                                    "name": t.name,
                                    "state": t.state,
                                    "previousName": old.name,
                                })
                                .to_string();
                                on_event(json);
                            }
                        } else {
                            let json = serde_json::json!({
                                "kind": "added",
                                "id": t.id,
                                "name": t.name,
                                "state": t.state,
                            })
                            .to_string();
                            on_event(json);
                        }
                    }
                    for (id, t) in &prev {
                        if !now.contains_key(id) {
                            let json = serde_json::json!({
                                "kind": "removed",
                                "id": t.id,
                                "name": t.name,
                                "state": t.state,
                            })
                            .to_string();
                            on_event(json);
                        }
                    }
                    prev = now;
                }
            })
            .ok();
    }

    pub fn stop_thread_observer() {
        if let Some(st) = OBSERVER.lock().take() {
            st.stop.store(true, Ordering::Relaxed);
        }
    }

    // --- Exception handler (Frida-shaped; probe synthesizes a recoverable fault) ---

    #[derive(Debug, Clone)]
    pub struct ExceptionDetails {
        pub type_name: String,
        pub address: u64,
        pub memory_operation: Option<String>,
        pub memory_address: Option<u64>,
    }

    static EXCEPTION_HANDLER_ON: AtomicBool = AtomicBool::new(false);

    pub fn set_exception_handler_enabled(on: bool) {
        EXCEPTION_HANDLER_ON.store(on, Ordering::SeqCst);
    }

    pub fn exception_handler_enabled() -> bool {
        EXCEPTION_HANDLER_ON.load(Ordering::SeqCst)
    }

    /// Synthesize a recoverable access-violation for tests / handler smoke.
    /// Real signal interception is not fully wired (would need async-signal-safe
    /// recovery); this exercises the JS `Process.setExceptionHandler` path.
    pub fn exception_probe_details() -> Option<ExceptionDetails> {
        if !EXCEPTION_HANDLER_ON.load(Ordering::SeqCst) {
            return None;
        }
        Some(ExceptionDetails {
            type_name: "access-violation".into(),
            address: 0x8,
            memory_operation: Some("read".into()),
            memory_address: Some(0x8),
        })
    }

    fn exec_ranges() -> Vec<(u64, u64)> {
        module::enumerate_ranges("r-x", false)
            .into_iter()
            .map(|r| (r.base, r.base.saturating_add(r.size)))
            .collect()
    }

    fn looks_like_code(addr: u64, ranges: &[(u64, u64)]) -> bool {
        if addr < 0x1000 || addr & 0x3 != 0 {
            return false;
        }
        ranges.iter().any(|(s, e)| addr >= *s && addr < *e)
    }

    fn backtrace_fp(max_frames: usize) -> Vec<NativePointer> {
        let ranges = exec_ranges();
        let mut out = Vec::new();
        #[cfg(target_arch = "aarch64")]
        {
            let mut fp: u64;
            unsafe {
                core::arch::asm!("mov {}, x29", out(reg) fp, options(nomem, nostack));
            }
            let mut guard = 0usize;
            while fp != 0 && out.len() < max_frames && guard < 128 {
                guard += 1;
                let fp_now = fp;
                let pair = std::panic::catch_unwind(|| unsafe {
                    let saved_fp = std::ptr::read_unaligned(fp_now as *const u64);
                    let lr = std::ptr::read_unaligned((fp_now + 8) as *const u64);
                    (saved_fp, lr)
                });
                let Ok((saved_fp, lr)) = pair else {
                    break;
                };
                if looks_like_code(lr, &ranges) {
                    out.push(NativePointer(lr));
                }
                if saved_fp <= fp || saved_fp.wrapping_sub(fp) > 0x100000 {
                    break;
                }
                fp = saved_fp;
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (max_frames, ranges);
        }
        out
    }

    fn backtrace_fuzzy(max_frames: usize) -> Vec<NativePointer> {
        let ranges = exec_ranges();
        if ranges.is_empty() {
            return Vec::new();
        }
        // Approximate SP via a stack local.
        let marker = 0u64;
        let sp = &marker as *const u64 as u64;
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        // Scan up to 64 KiB of stack words.
        for i in 0..(64 * 1024 / 8) {
            let addr = sp.wrapping_add((i * 8) as u64);
            let word = unsafe {
                match std::panic::catch_unwind(|| std::ptr::read_unaligned(addr as *const u64)) {
                    Ok(w) => w,
                    Err(_) => break,
                }
            };
            if looks_like_code(word, &ranges) && seen.insert(word) {
                out.push(NativePointer(word));
                if out.len() >= max_frames {
                    break;
                }
            }
        }
        out
    }
}

pub mod module {
    use super::NativePointer;
    use std::fs;
    use std::path::Path;

    #[derive(Debug, Clone)]
    pub struct ModuleInfo {
        pub name: String,
        pub base: u64,
        pub size: u64,
        pub path: String,
    }

    #[derive(Debug, Clone)]
    pub struct RangeInfo {
        pub base: u64,
        pub size: u64,
        pub protection: String,
        pub file_path: Option<String>,
        pub file_offset: Option<u64>,
    }

    #[derive(Debug, Clone)]
    pub struct ExportInfo {
        pub name: String,
        pub address: NativePointer,
        pub kind: String, // "function" | "variable"
    }

    #[derive(Debug, Clone)]
    pub struct ImportInfo {
        pub name: String,
        pub kind: String, // "function" | "variable"
        pub address: Option<NativePointer>, // GOT/PLT slot when known
        pub slot: Option<NativePointer>,
        pub module: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct SymbolInfo {
        pub name: String,
        pub address: NativePointer,
        pub size: u64,
        pub kind: String, // "function" | "object" | "section" | "undefined" | ...
        pub is_global: bool,
        pub is_weak: bool,
    }

    #[derive(Debug, Clone)]
    pub struct SectionInfo {
        pub id: u32,
        pub name: String,
        pub address: NativePointer,
        pub size: u64,
    }

    pub fn find_base_address(module_name: &str) -> Option<NativePointer> {
        find_module_by_name(module_name).map(|m| NativePointer(m.base))
    }

    pub fn find_module_by_name(module_name: &str) -> Option<ModuleInfo> {
        enumerate_modules().into_iter().find(|m| {
            m.name == module_name
                || m.name.ends_with(module_name)
                || m.path.ends_with(module_name)
                || m.path.contains(module_name)
        })
    }

    pub fn find_module_by_address(addr: NativePointer) -> Option<ModuleInfo> {
        enumerate_modules()
            .into_iter()
            .find(|m| addr.0 >= m.base && addr.0 < m.base.saturating_add(m.size))
    }

    pub fn find_export_by_name(
        module_name: Option<&str>,
        export_name: &str,
    ) -> Option<NativePointer> {
        #[cfg(unix)]
        {
            unsafe {
                if let Some(mod_name) = module_name {
                    let handle = {
                        // Prefer opening the module so dlsym is scoped when possible.
                        if let Some(m) = find_module_by_name(mod_name) {
                            let c = std::ffi::CString::new(m.path.as_str()).ok()?;
                            let h = libc::dlopen(c.as_ptr(), libc::RTLD_NOLOAD | libc::RTLD_LAZY);
                            if h.is_null() {
                                libc::RTLD_DEFAULT
                            } else {
                                h
                            }
                        } else {
                            libc::RTLD_DEFAULT
                        }
                    };
                    let c = std::ffi::CString::new(export_name).ok()?;
                    let p = libc::dlsym(handle, c.as_ptr());
                    if p.is_null() {
                        None
                    } else {
                        Some(NativePointer(p as u64))
                    }
                } else {
                    let c = std::ffi::CString::new(export_name).ok()?;
                    let p = libc::dlsym(libc::RTLD_DEFAULT, c.as_ptr());
                    if p.is_null() {
                        None
                    } else {
                        Some(NativePointer(p as u64))
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (module_name, export_name);
            None
        }
    }

    /// Load a shared library (`dlopen`) and return its ModuleInfo.
    pub fn load(path: &str) -> Result<ModuleInfo, String> {
        #[cfg(unix)]
        {
            let c = std::ffi::CString::new(path).map_err(|e| e.to_string())?;
            let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW) };
            if h.is_null() {
                let err = unsafe {
                    let p = libc::dlerror();
                    if p.is_null() {
                        "dlopen failed".into()
                    } else {
                        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
                    }
                };
                return Err(err);
            }
            // Refresh maps and find by path / basename.
            if let Some(m) = find_module_by_name(path) {
                return Ok(m);
            }
            let base = Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(path);
            find_module_by_name(base).ok_or_else(|| format!("loaded but not in maps: {path}"))
        }
        #[cfg(not(unix))]
        {
            Err(format!("Module.load unsupported: {path}"))
        }
    }

    pub fn enumerate_exports(module: &ModuleInfo) -> Vec<ExportInfo> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            enumerate_exports_elf_file(module).unwrap_or_default()
        })) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    }

    /// Parse ELF64 `.dynsym` from the on-disk file (safer than walking mapped memory).
    fn enumerate_exports_elf_file(module: &ModuleInfo) -> Option<Vec<ExportInfo>> {
        let bytes = fs::read(&module.path).ok()?;
        if bytes.len() < 64 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 {
            return None;
        }
        let e_phoff = u64_at(&bytes, 32)? as usize;
        let e_phentsize = u16_at(&bytes, 54)? as usize;
        let e_phnum = u16_at(&bytes, 56)? as usize;
        let mut load_bias = module.base;
        let mut dyn_off = None;
        let mut dyn_filesz = 0usize;
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            let p_type = u32_at(&bytes, ph)?;
            let p_offset = u64_at(&bytes, ph + 8)? as usize;
            let p_vaddr = u64_at(&bytes, ph + 16)?;
            let p_filesz = u64_at(&bytes, ph + 32)? as usize;
            if p_type == 1 && i == 0 {
                load_bias = module.base.wrapping_sub(p_vaddr);
            }
            if p_type == 1 {
                // first PT_LOAD wins for bias
            }
            if p_type == 2 {
                dyn_off = Some(p_offset);
                dyn_filesz = p_filesz;
            }
        }
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            if u32_at(&bytes, ph)? == 1 {
                load_bias = module.base.wrapping_sub(u64_at(&bytes, ph + 16)?);
                break;
            }
        }
        let dyn_off = dyn_off?;
        let mut symtab_va = 0u64;
        let mut strtab_va = 0u64;
        let mut syment = 24u64;
        let mut hash_va = 0u64;
        let mut gnu_hash_va = 0u64;
        let dyn_end = dyn_off.saturating_add(dyn_filesz.min(bytes.len().saturating_sub(dyn_off)));
        let mut off = dyn_off;
        while off + 16 <= dyn_end && off + 16 <= bytes.len() {
            let tag = i64_at(&bytes, off)?;
            let val = u64_at(&bytes, off + 8)?;
            match tag {
                0 => break,
                5 => strtab_va = val,
                6 => symtab_va = val,
                11 => syment = val,
                4 => hash_va = val,
                0x6fff_fef5 => gnu_hash_va = val,
                _ => {}
            }
            off += 16;
        }
        if symtab_va == 0 || strtab_va == 0 {
            return None;
        }
        let sym_file = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, symtab_va)?;
        let str_file = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, strtab_va)?;
        let nsyms = if gnu_hash_va != 0 {
            let gh = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, gnu_hash_va)?;
            count_gnu_hash_file(&bytes, gh).unwrap_or(0)
        } else if hash_va != 0 {
            let h = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, hash_va)?;
            u32_at(&bytes, h + 4).unwrap_or(0) as usize
        } else {
            0
        };
        if nsyms == 0 || nsyms > 500_000 {
            return None;
        }
        let mut out = Vec::new();
        for i in 0..nsyms {
            let sym = sym_file + i * syment as usize;
            if sym + syment as usize > bytes.len() {
                break;
            }
            let st_name = u32_at(&bytes, sym)? as usize;
            let st_info = bytes.get(sym + 4).copied()?;
            let st_shndx = u16_at(&bytes, sym + 6)?;
            let st_value = u64_at(&bytes, sym + 8)?;
            if st_name == 0 || st_shndx == 0 {
                continue;
            }
            let bind = st_info >> 4;
            if bind != 1 && bind != 2 {
                continue;
            }
            // STT_FUNC=1, STT_OBJECT=2, STT_NOTYPE=0, STT_GNU_IFUNC=10
            let kind = match st_info & 0xf {
                1 | 10 => "function",
                2 => "variable",
                0 if st_value != 0 => "function",
                _ => continue,
            };
            let name = cstr_at(&bytes, str_file + st_name)?;
            if name.is_empty() {
                continue;
            }
            out.push(ExportInfo {
                name,
                address: NativePointer(load_bias.wrapping_add(st_value)),
                kind: kind.into(),
            });
        }
        Some(out)
    }

    pub fn enumerate_imports(module: &ModuleInfo) -> Vec<ImportInfo> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            enumerate_imports_elf_file(module).unwrap_or_default()
        })) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    }

    fn enumerate_imports_elf_file(module: &ModuleInfo) -> Option<Vec<ImportInfo>> {
        let bytes = fs::read(&module.path).ok()?;
        if bytes.len() < 64 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 {
            return None;
        }
        let e_phoff = u64_at(&bytes, 32)? as usize;
        let e_phentsize = u16_at(&bytes, 54)? as usize;
        let e_phnum = u16_at(&bytes, 56)? as usize;
        let mut load_bias = module.base;
        let mut dyn_off = None;
        let mut dyn_filesz = 0usize;
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            let p_type = u32_at(&bytes, ph)?;
            let p_offset = u64_at(&bytes, ph + 8)? as usize;
            let p_filesz = u64_at(&bytes, ph + 32)? as usize;
            if p_type == 1 && i == 0 {
                load_bias = module.base.wrapping_sub(u64_at(&bytes, ph + 16)?);
            }
            if p_type == 2 {
                dyn_off = Some(p_offset);
                dyn_filesz = p_filesz;
            }
        }
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            if u32_at(&bytes, ph)? == 1 {
                load_bias = module.base.wrapping_sub(u64_at(&bytes, ph + 16)?);
                break;
            }
        }
        let dyn_off = dyn_off?;
        let mut symtab_va = 0u64;
        let mut strtab_va = 0u64;
        let mut syment = 24u64;
        let mut jmprel_va = 0u64;
        let mut pltrelsz = 0u64;
        let mut rela_va = 0u64;
        let mut relasz = 0u64;
        let mut relaent = 24u64;
        let dyn_end = dyn_off.saturating_add(dyn_filesz.min(bytes.len().saturating_sub(dyn_off)));
        let mut off = dyn_off;
        while off + 16 <= dyn_end && off + 16 <= bytes.len() {
            let tag = i64_at(&bytes, off)?;
            let val = u64_at(&bytes, off + 8)?;
            match tag {
                0 => break,
                5 => strtab_va = val,
                6 => symtab_va = val,
                11 => syment = val,
                7 => rela_va = val,     // DT_RELA
                8 => relasz = val,      // DT_RELASZ
                9 => relaent = val,     // DT_RELAENT
                23 => jmprel_va = val,  // DT_JMPREL
                2 => pltrelsz = val,    // DT_PLTRELSZ
                _ => {}
            }
            off += 16;
        }
        if symtab_va == 0 || strtab_va == 0 {
            return None;
        }
        let sym_file = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, symtab_va)?;
        let str_file = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, strtab_va)?;

        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let mut parse_rela = |va: u64, size: u64| -> Option<()> {
            if va == 0 || size == 0 {
                return Some(());
            }
            let file = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, va)?;
            let n = (size / relaent) as usize;
            for i in 0..n {
                let rel = file + i * relaent as usize;
                if rel + 16 > bytes.len() {
                    break;
                }
                let r_offset = u64_at(&bytes, rel)?;
                let r_info = u64_at(&bytes, rel + 8)?;
                let r_type = (r_info & 0xffff_ffff) as u32;
                let r_sym = (r_info >> 32) as usize;
                // AArch64: JUMP_SLOT=1026, GLOB_DAT=1025, ABS64=257
                let kind = match r_type {
                    1026 | 1025 | 257 => {
                        if r_type == 1026 {
                            "function"
                        } else {
                            "variable"
                        }
                    }
                    _ => continue,
                };
                let sym = sym_file + r_sym * syment as usize;
                if sym + 8 > bytes.len() {
                    continue;
                }
                let st_name = u32_at(&bytes, sym)? as usize;
                if st_name == 0 {
                    continue;
                }
                let name = cstr_at(&bytes, str_file + st_name)?;
                if name.is_empty() || !seen.insert(name.clone()) {
                    continue;
                }
                let slot = NativePointer(load_bias.wrapping_add(r_offset));
                out.push(ImportInfo {
                    name,
                    kind: kind.into(),
                    address: Some(slot),
                    slot: Some(slot),
                    module: None,
                });
            }
            Some(())
        };

        let _ = parse_rela(jmprel_va, pltrelsz);
        let _ = parse_rela(rela_va, relasz);
        Some(out)
    }

    pub fn enumerate_symbols(module: &ModuleInfo) -> Vec<SymbolInfo> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            enumerate_symbols_elf_file(module).unwrap_or_default()
        })) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    }

    pub fn enumerate_sections(module: &ModuleInfo) -> Vec<SectionInfo> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            enumerate_sections_elf_file(module).unwrap_or_default()
        })) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    }

    pub fn enumerate_dependencies(module: &ModuleInfo) -> Vec<String> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            enumerate_dependencies_elf_file(module).unwrap_or_default()
        })) {
            Ok(v) => v,
            Err(_) => Vec::new(),
        }
    }

    fn enumerate_symbols_elf_file(module: &ModuleInfo) -> Option<Vec<SymbolInfo>> {
        let bytes = fs::read(&module.path).ok()?;
        if bytes.len() < 64 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 {
            return None;
        }
        let e_shoff = u64_at(&bytes, 40)? as usize;
        let e_shentsize = u16_at(&bytes, 58)? as usize;
        let e_shnum = u16_at(&bytes, 60)? as usize;
        let e_shstrndx = u16_at(&bytes, 62)? as usize;
        if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 {
            // Fall back to dynsym-only via exports-shaped walk.
            return symbols_from_dynsym(module, &bytes);
        }
        let shstr_off = {
            let sh = e_shoff + e_shstrndx * e_shentsize;
            u64_at(&bytes, sh + 24)? as usize
        };
        let mut load_bias = module.base;
        let e_phoff = u64_at(&bytes, 32)? as usize;
        let e_phentsize = u16_at(&bytes, 54)? as usize;
        let e_phnum = u16_at(&bytes, 56)? as usize;
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            if u32_at(&bytes, ph)? == 1 {
                load_bias = module.base.wrapping_sub(u64_at(&bytes, ph + 16)?);
                break;
            }
        }

        // Prefer .symtab (full); else .dynsym.
        let mut symtab: Option<(usize, usize, usize, usize)> = None; // sym_off, sym_size, str_off, entsize
        let mut dynsym: Option<(usize, usize, usize, usize)> = None;
        for i in 0..e_shnum {
            let sh = e_shoff + i * e_shentsize;
            let name_off = u32_at(&bytes, sh)? as usize;
            let sh_type = u32_at(&bytes, sh + 4)?;
            let sh_offset = u64_at(&bytes, sh + 24)? as usize;
            let sh_size = u64_at(&bytes, sh + 32)? as usize;
            let sh_link = u32_at(&bytes, sh + 40)? as usize;
            let sh_entsize = u64_at(&bytes, sh + 56).unwrap_or(24) as usize;
            let name = cstr_at(&bytes, shstr_off + name_off).unwrap_or_default();
            if sh_type == 2 || sh_type == 11 {
                // SHT_SYMTAB=2, SHT_DYNSYM=11
                let str_sh = e_shoff + sh_link * e_shentsize;
                let str_off = u64_at(&bytes, str_sh + 24)? as usize;
                let entry = (sh_offset, sh_size, str_off, sh_entsize.max(24));
                if name == ".symtab" || sh_type == 2 {
                    symtab = Some(entry);
                } else if name == ".dynsym" || sh_type == 11 {
                    dynsym = Some(entry);
                }
            }
        }
        let (sym_off, sym_size, str_off, entsize) = symtab.or(dynsym)?;
        let nsyms = sym_size / entsize;
        if nsyms == 0 || nsyms > 500_000 {
            return None;
        }
        let mut out = Vec::new();
        for i in 0..nsyms {
            let sym = sym_off + i * entsize;
            if sym + entsize > bytes.len() {
                break;
            }
            let st_name = u32_at(&bytes, sym)? as usize;
            let st_info = bytes.get(sym + 4).copied()?;
            let st_shndx = u16_at(&bytes, sym + 6)?;
            let st_value = u64_at(&bytes, sym + 8)?;
            let st_size = u64_at(&bytes, sym + 16).unwrap_or(0);
            if st_name == 0 {
                continue;
            }
            let name = cstr_at(&bytes, str_off + st_name)?;
            if name.is_empty() {
                continue;
            }
            let bind = st_info >> 4;
            let typ = st_info & 0xf;
            let kind = match typ {
                0 => {
                    if st_shndx == 0 {
                        "undefined"
                    } else {
                        "object"
                    }
                }
                1 | 10 => "function",
                2 => "object",
                3 => "section",
                4 => "file",
                _ => "unknown",
            };
            // Skip anonymous section/file clutter unless named meaningfully.
            if kind == "file" {
                continue;
            }
            out.push(SymbolInfo {
                name,
                address: NativePointer(load_bias.wrapping_add(st_value)),
                size: st_size,
                kind: kind.into(),
                is_global: bind == 1,
                is_weak: bind == 2,
            });
        }
        Some(out)
    }

    fn symbols_from_dynsym(module: &ModuleInfo, bytes: &[u8]) -> Option<Vec<SymbolInfo>> {
        // Reuse export enumeration and map kinds.
        let exports = enumerate_exports_elf_file(module)?;
        let _ = bytes;
        Some(
            exports
                .into_iter()
                .map(|e| SymbolInfo {
                    name: e.name,
                    address: e.address,
                    size: 0,
                    kind: if e.kind == "variable" {
                        "object".into()
                    } else {
                        e.kind
                    },
                    is_global: true,
                    is_weak: false,
                })
                .collect(),
        )
    }

    fn enumerate_sections_elf_file(module: &ModuleInfo) -> Option<Vec<SectionInfo>> {
        let bytes = fs::read(&module.path).ok()?;
        if bytes.len() < 64 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 {
            return None;
        }
        let e_shoff = u64_at(&bytes, 40)? as usize;
        let e_shentsize = u16_at(&bytes, 58)? as usize;
        let e_shnum = u16_at(&bytes, 60)? as usize;
        let e_shstrndx = u16_at(&bytes, 62)? as usize;
        if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 {
            return None;
        }
        let shstr_off = {
            let sh = e_shoff + e_shstrndx * e_shentsize;
            u64_at(&bytes, sh + 24)? as usize
        };
        let mut load_bias = module.base;
        let e_phoff = u64_at(&bytes, 32)? as usize;
        let e_phentsize = u16_at(&bytes, 54)? as usize;
        let e_phnum = u16_at(&bytes, 56)? as usize;
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            if u32_at(&bytes, ph)? == 1 {
                load_bias = module.base.wrapping_sub(u64_at(&bytes, ph + 16)?);
                break;
            }
        }
        let mut out = Vec::new();
        for i in 0..e_shnum {
            let sh = e_shoff + i * e_shentsize;
            if sh + e_shentsize > bytes.len() {
                break;
            }
            let name_off = u32_at(&bytes, sh)? as usize;
            let sh_addr = u64_at(&bytes, sh + 16)?;
            let sh_size = u64_at(&bytes, sh + 32)?;
            let name = cstr_at(&bytes, shstr_off + name_off).unwrap_or_default();
            if name.is_empty() && sh_size == 0 {
                continue;
            }
            out.push(SectionInfo {
                id: i as u32,
                name,
                address: NativePointer(load_bias.wrapping_add(sh_addr)),
                size: sh_size,
            });
        }
        Some(out)
    }

    fn enumerate_dependencies_elf_file(module: &ModuleInfo) -> Option<Vec<String>> {
        let bytes = fs::read(&module.path).ok()?;
        if bytes.len() < 64 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] || bytes[4] != 2 {
            return None;
        }
        let e_phoff = u64_at(&bytes, 32)? as usize;
        let e_phentsize = u16_at(&bytes, 54)? as usize;
        let e_phnum = u16_at(&bytes, 56)? as usize;
        let mut dyn_off = None;
        let mut dyn_filesz = 0usize;
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            let p_type = u32_at(&bytes, ph)?;
            if p_type == 2 {
                dyn_off = Some(u64_at(&bytes, ph + 8)? as usize);
                dyn_filesz = u64_at(&bytes, ph + 32)? as usize;
            }
        }
        let dyn_off = dyn_off?;
        let mut strtab_va = 0u64;
        let mut needed_offs: Vec<u64> = Vec::new();
        let dyn_end = dyn_off.saturating_add(dyn_filesz.min(bytes.len().saturating_sub(dyn_off)));
        let mut off = dyn_off;
        while off + 16 <= dyn_end && off + 16 <= bytes.len() {
            let tag = i64_at(&bytes, off)?;
            let val = u64_at(&bytes, off + 8)?;
            match tag {
                0 => break,
                5 => strtab_va = val, // DT_STRTAB
                1 => needed_offs.push(val), // DT_NEEDED
                _ => {}
            }
            off += 16;
        }
        if strtab_va == 0 {
            return None;
        }
        let str_file = vaddr_to_offset(&bytes, e_phoff, e_phentsize, e_phnum, strtab_va)?;
        let mut out = Vec::new();
        for n in needed_offs {
            if let Some(name) = cstr_at(&bytes, str_file + n as usize) {
                if !name.is_empty() {
                    out.push(name);
                }
            }
        }
        Some(out)
    }

    fn vaddr_to_offset(
        bytes: &[u8],
        e_phoff: usize,
        e_phentsize: usize,
        e_phnum: usize,
        vaddr: u64,
    ) -> Option<usize> {
        for i in 0..e_phnum {
            let ph = e_phoff + i * e_phentsize;
            if u32_at(bytes, ph)? != 1 {
                continue;
            }
            let p_offset = u64_at(bytes, ph + 8)?;
            let p_vaddr = u64_at(bytes, ph + 16)?;
            let p_filesz = u64_at(bytes, ph + 32)?;
            if vaddr >= p_vaddr && vaddr < p_vaddr.saturating_add(p_filesz) {
                return Some((p_offset + (vaddr - p_vaddr)) as usize);
            }
        }
        None
    }

    fn count_gnu_hash_file(bytes: &[u8], gnu: usize) -> Option<usize> {
        let nbuckets = u32_at(bytes, gnu)? as usize;
        let symoffset = u32_at(bytes, gnu + 4)? as usize;
        let bloom_size = u32_at(bytes, gnu + 8)? as usize;
        let buckets = gnu + 16 + bloom_size * 8;
        let mut max_sym = symoffset;
        for i in 0..nbuckets {
            let b = u32_at(bytes, buckets + i * 4)? as usize;
            if b != 0 {
                max_sym = max_sym.max(b);
            }
        }
        let chains = buckets + nbuckets * 4;
        let mut idx = max_sym;
        for _ in 0..100_000 {
            let off = chains + (idx - symoffset) * 4;
            if off + 4 > bytes.len() {
                break;
            }
            let c = u32_at(bytes, off)?;
            idx += 1;
            if c & 1 != 0 {
                break;
            }
        }
        Some(idx)
    }

    fn u16_at(b: &[u8], off: usize) -> Option<u16> {
        Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
    }
    fn u32_at(b: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
    }
    fn u64_at(b: &[u8], off: usize) -> Option<u64> {
        Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
    }
    fn i64_at(b: &[u8], off: usize) -> Option<i64> {
        Some(i64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
    }
    fn cstr_at(b: &[u8], off: usize) -> Option<String> {
        if off >= b.len() {
            return None;
        }
        let end = b[off..].iter().position(|&c| c == 0).unwrap_or(b.len() - off);
        Some(String::from_utf8_lossy(&b[off..off + end]).into_owned())
    }

    // Keep legacy in-memory helpers unused — file parse is preferred.
    #[allow(dead_code)]
    fn enumerate_exports_elf(_module: &ModuleInfo) -> Option<Vec<ExportInfo>> {
        None
    }

    pub fn enumerate_modules() -> Vec<ModuleInfo> {
        let mut by_path: Vec<ModuleInfo> = Vec::new();
        for r in raw_maps() {
            let path = match &r.file_path {
                Some(p) if !p.is_empty() && !p.starts_with('[') => p.clone(),
                _ => continue,
            };
            let name = Path::new(&path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());
            if let Some(last) = by_path.last_mut() {
                if last.path == path {
                    let end = r.base.saturating_add(r.size);
                    let cur_end = last.base.saturating_add(last.size);
                    if end > cur_end {
                        last.size = end.saturating_sub(last.base);
                    }
                    if r.base < last.base {
                        let new_end = last.base.saturating_add(last.size);
                        last.base = r.base;
                        last.size = new_end.saturating_sub(last.base);
                    }
                    continue;
                }
            }
            by_path.push(ModuleInfo {
                name,
                base: r.base,
                size: r.size,
                path,
            });
        }
        by_path
    }

    pub fn enumerate_ranges(protection: &str, coalesce: bool) -> Vec<RangeInfo> {
        let mut ranges: Vec<RangeInfo> = raw_maps()
            .into_iter()
            .filter(|r| prot_matches(&r.protection, protection))
            .filter(|r| !crate::cloak::range_overlaps_cloaked(r.base, r.size))
            .collect();
        if coalesce {
            ranges = coalesce_ranges(ranges);
        }
        ranges
    }

    pub fn find_range_by_address(addr: NativePointer) -> Option<RangeInfo> {
        if crate::cloak::has_range_containing(addr.0) {
            return None;
        }
        raw_maps()
            .into_iter()
            .find(|r| addr.0 >= r.base && addr.0 < r.base.saturating_add(r.size))
    }

    pub fn enumerate_module_ranges(module: &ModuleInfo, protection: &str) -> Vec<RangeInfo> {
        enumerate_ranges(protection, false)
            .into_iter()
            .filter(|r| {
                r.file_path
                    .as_ref()
                    .map(|p| p == &module.path)
                    .unwrap_or(false)
                    || (r.base >= module.base && r.base < module.base.saturating_add(module.size))
            })
            .collect()
    }

    fn prot_matches(have: &str, want: &str) -> bool {
        if want.is_empty() || want == "---" {
            return true;
        }
        let h: Vec<char> = have.chars().take(3).collect();
        let w: Vec<char> = want.chars().take(3).collect();
        for i in 0..3 {
            let wc = w.get(i).copied().unwrap_or('-');
            if wc == '-' {
                continue;
            }
            if h.get(i).copied().unwrap_or('-') != wc {
                return false;
            }
        }
        true
    }

    fn coalesce_ranges(ranges: Vec<RangeInfo>) -> Vec<RangeInfo> {
        let mut out: Vec<RangeInfo> = Vec::new();
        for r in ranges {
            if let Some(last) = out.last_mut() {
                let last_end = last.base.saturating_add(last.size);
                if last.protection == r.protection
                    && last.file_path == r.file_path
                    && last_end == r.base
                {
                    last.size += r.size;
                    continue;
                }
            }
            out.push(r);
        }
        out
    }

    fn raw_maps() -> Vec<RangeInfo> {
        let Ok(text) = fs::read_to_string("/proc/self/maps") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let range = parts.next().unwrap_or("");
            let perms = parts.next().unwrap_or("---p");
            let off = parts.next().unwrap_or("0");
            let _dev = parts.next();
            let _inode = parts.next();
            let file = parts.collect::<Vec<_>>().join(" ");
            let mut segs = range.split('-');
            let start = u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
            let end = u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
            let protection: String = perms.chars().take(3).collect();
            let file_offset = u64::from_str_radix(off, 16).ok();
            let file_path = if file.is_empty() {
                None
            } else {
                Some(file)
            };
            out.push(RangeInfo {
                base: start,
                size: end.saturating_sub(start),
                protection,
                file_path,
                file_offset,
            });
        }
        out
    }
}

pub mod interceptor {
    use super::*;
    use goauld_native_hook::HookId;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    static LIVE: Mutex<Option<HashMap<u64, HookId>>> = Mutex::new(None);

    fn live() -> parking_lot::MutexGuard<'static, Option<HashMap<u64, HookId>>> {
        let mut g = LIVE.lock();
        if g.is_none() {
            *g = Some(HashMap::new());
        }
        g
    }

    pub fn attach_log_enter(target: NativePointer, nbytes: usize) -> Result<HookId, HookError> {
        let code = unsafe { std::slice::from_raw_parts(target.0 as *const u8, nbytes.max(16)) };
        let code = code.to_vec();
        let hook = attach(
            target.0,
            &code,
            HookCallbacks {
                on_enter: Some(Box::new(|ctx: &mut CpuContext| {
                    log::info!("hook enter x0={:#x}", ctx.x[0]);
                })),
                on_leave: None,
                save_simd: false,
                replace_mode: false,
            },
        )?;
        live().as_mut().unwrap().insert(target.0, hook.id);
        Ok(hook.id)
    }

    pub fn detach_all() {
        let ids: Vec<_> = live()
            .as_mut()
            .map(|m| m.drain().map(|(_, id)| id).collect())
            .unwrap_or_default();
        for id in ids {
            let _ = detach(id);
        }
    }
}
