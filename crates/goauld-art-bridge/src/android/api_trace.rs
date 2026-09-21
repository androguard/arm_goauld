//! Trace Android framework / platform Java APIs by hooking `art::ArtMethod::Invoke`.
//!
//! This covers methods from the [Android API reference](https://developer.android.com/reference)
//! (and related `java.*` / `androidx.*` surfaces) without enumerating each class. Filtering is by
//! declaring-class package prefix (converted from ART descriptors like `Landroid/app/Activity;`).

use crate::ArtError;
use goauld_native_hook::patch::attach;
use goauld_native_hook::trampoline::{CpuContext, HookCallbacks};
use jni::sys::jobject;
use parking_lot::RwLock;
use std::cell::Cell;
use std::ffi::CStr;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use super::{scan_libart_symbol, with_attached_jni, SEND_CB};

const INVOKE_SYM: &str = "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc";
/// Runtime→managed bridges; `ArtMethod*` is in x0 (same as `ArtMethod::Invoke`).
const QUICK_INVOKE_STUBS: &[&str] = &[
    "art_quick_invoke_stub",
    "art_quick_invoke_static_stub",
];
const DESC_SYM: &str = "_ZN3art9ArtMethod27GetDeclaringClassDescriptorEv";
const PRETTY_SYM: &str = "_ZN3art9ArtMethod12PrettyMethodEPS0_b";
/// Non-const on modern ART (note: `ZN`, not `ZNK`).
const TO_MUTF8_SYM: &str = "_ZN3art6mirror6String14ToModifiedUtf8Ev";
const TO_MUTF8_SYM_CONST: &str = "_ZNK3art6mirror6String14ToModifiedUtf8Ev";
const THREAD_CURRENT_SYM: &str = "_ZN3art6Thread7CurrentEv";
const DECODE_JOBJECT_SYM: &str = "_ZNK3art6Thread13DecodeJObjectEP8_jobject";

/// Default prefixes matching platform + Jetpack + core Java APIs from the Android docs.
pub const DEFAULT_API_PREFIXES: &[&str] = &[
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "com.android.",
    "dalvik.",
];

static ENABLED: AtomicBool = AtomicBool::new(false);
static MAX_EVENTS: AtomicU64 = AtomicU64::new(0);
static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static WITH_SIGNATURE: AtomicBool = AtomicBool::new(true);
static INSTALLED: AtomicBool = AtomicBool::new(false);
/// Compressed `Class*` for `java.lang.String` (0 = unresolved).
static STRING_KLASS: AtomicUsize = AtomicUsize::new(0);

static PREFIXES: RwLock<Vec<String>> = RwLock::new(Vec::new());
static PRETTY: OnceLock<usize> = OnceLock::new();
static TO_MUTF8: OnceLock<usize> = OnceLock::new();
static GET_SHORTY: OnceLock<GetShortyLenFn> = OnceLock::new();
static GET_COMPONENT: OnceLock<GetComponentFn> = OnceLock::new();
static GET_DESC: OnceLock<GetDescFn> = OnceLock::new();
static OP_DELETE: OnceLock<OpDeleteFn> = OnceLock::new();
static THREAD_CURRENT: OnceLock<ThreadCurrentFn> = OnceLock::new();
static DECODE_JOBJECT: OnceLock<DecodeJObjectFn> = OnceLock::new();

type GetDescFn = unsafe extern "C" fn(*mut c_void) -> *const libc::c_char;
/// `ArtMethod::GetShorty(uint32_t* out_length)` when present in .symtab (often LOCAL).
type GetShortyLenFn = unsafe extern "C" fn(*mut c_void, *mut u32) -> *const libc::c_char;
type GetComponentFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type OpDeleteFn = unsafe extern "C" fn(*mut c_void);
type ThreadCurrentFn = unsafe extern "C" fn() -> *mut c_void;
type DecodeJObjectFn = unsafe extern "C" fn(thread: *mut c_void, obj: jobject) -> *mut c_void;

thread_local! {
    static IN_TRACE: Cell<bool> = const { Cell::new(false) };
}

#[derive(Clone, Debug)]
pub struct AndroidApiTraceConfig {
    pub prefixes: Vec<String>,
    /// 0 = unlimited.
    pub max_events: u64,
    pub with_signature: bool,
}

impl Default for AndroidApiTraceConfig {
    fn default() -> Self {
        Self {
            prefixes: DEFAULT_API_PREFIXES.iter().map(|s| (*s).to_string()).collect(),
            max_events: 0,
            with_signature: true,
        }
    }
}

/// Install (once) an inline hook on `ArtMethod::Invoke` and enable filtered tracing.
pub fn start_android_api_trace(cfg: AndroidApiTraceConfig) -> Result<u32, ArtError> {
    let prefixes = if cfg.prefixes.is_empty() {
        DEFAULT_API_PREFIXES.iter().map(|s| (*s).to_string()).collect()
    } else {
        cfg.prefixes
            .into_iter()
            .map(|p| {
                let mut s = p.trim().to_string();
                if !s.is_empty() && !s.ends_with('.') {
                    s.push('.');
                }
                s
            })
            .filter(|s| !s.is_empty())
            .collect()
    };
    *PREFIXES.write() = prefixes;
    MAX_EVENTS.store(cfg.max_events, Ordering::Relaxed);
    EVENT_COUNT.store(0, Ordering::Relaxed);
    WITH_SIGNATURE.store(cfg.with_signature, Ordering::Relaxed);

    resolve_helpers()?;
    let hook_id = ensure_invoke_hook()?;
    ENABLED.store(true, Ordering::Release);
    log::info!(
        "android API trace enabled (hook_id={hook_id}, sdk_int={}, release={:?}, prefixes={:?})",
        goauld_art_bridge_sdk(),
        crate_android_release(),
        *PREFIXES.read()
    );
    Ok(hook_id)
}

fn goauld_art_bridge_sdk() -> u32 {
    super::java_api::android_sdk_int_or_0()
}

fn crate_android_release() -> String {
    super::java_api::android_version().unwrap_or_else(|_| "?".into())
}

pub fn stop_android_api_trace() {
    ENABLED.store(false, Ordering::Release);
}

fn resolve_helpers() -> Result<(), ArtError> {
    if PRETTY.get().is_none() {
        let addr = scan_libart_symbol(PRETTY_SYM)
            .or_else(|| scan_libart_symbol("_ZN3art9ArtMethod12PrettyMethodEb"))
            .ok_or_else(|| ArtError::Msg("ArtMethod::PrettyMethod not found".into()))?;
        let _ = PRETTY.set(addr);
    }
    if TO_MUTF8.get().is_none() {
        // Resolved for diagnostics only — hot-path string decode uses mirror field layout
        // (ToModifiedUtf8 under invoke stubs has been a SEGV source without SOA).
        let addr = scan_libart_symbol(TO_MUTF8_SYM)
            .or_else(|| scan_libart_symbol(TO_MUTF8_SYM_CONST));
        if let Some(addr) = addr {
            let _ = TO_MUTF8.set(addr);
            log::info!("String::ToModifiedUtf8 present @ {addr:#x} (layout decode used in-hook)");
        }
    }
    if GET_SHORTY.get().is_none() {
        // Do NOT call NterpGetShortyFromMethodId — that symbol is an nterp helper with a
        // different ABI; passing ArtMethod* SEGV'd (tombstone: NterpGetShortyFromMethodId+48).
        // ArtMethod::GetShorty is often LOCAL/stripped; try ELF symtab, else PrettyMethod/x5.
        for sym in [
            "_ZN3art9ArtMethod9GetShortyEPj",
            "_ZNK3art9ArtMethod9GetShortyEPj",
        ] {
            if let Some(addr) = scan_libart_symbol(sym) {
                let f: GetShortyLenFn = unsafe { std::mem::transmute(addr) };
                let _ = GET_SHORTY.set(f);
                log::info!("resolved ArtMethod::GetShorty(len) via {sym} @ {addr:#x}");
                break;
            }
        }
        if GET_SHORTY.get().is_none() {
            log::info!("ArtMethod::GetShorty unavailable — using PrettyMethod signature / stub x5");
        }
    }
    if GET_COMPONENT.get().is_none() {
        for sym in [
            "_ZNK3art6mirror5Class16GetComponentTypeEv",
            "_ZN3art6mirror5Class16GetComponentTypeEv",
        ] {
            if let Some(addr) = scan_libart_symbol(sym) {
                let f: GetComponentFn = unsafe { std::mem::transmute(addr) };
                let _ = GET_COMPONENT.set(f);
                break;
            }
        }
    }
    if GET_DESC.get().is_none() {
        if let Some(addr) = scan_libart_symbol(DESC_SYM) {
            let f: GetDescFn = unsafe { std::mem::transmute(addr) };
            let _ = GET_DESC.set(f);
        }
    }
    if OP_DELETE.get().is_none() {
        let name = std::ffi::CString::new("_ZdlPv").unwrap();
        let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        if !p.is_null() {
            let f: OpDeleteFn = unsafe { std::mem::transmute(p) };
            let _ = OP_DELETE.set(f);
        }
    }
    if THREAD_CURRENT.get().is_none() {
        if let Some(addr) = scan_libart_symbol(THREAD_CURRENT_SYM) {
            let f: ThreadCurrentFn = unsafe { std::mem::transmute(addr) };
            let _ = THREAD_CURRENT.set(f);
        }
    }
    if DECODE_JOBJECT.get().is_none() {
        if let Some(addr) = scan_libart_symbol(DECODE_JOBJECT_SYM) {
            let f: DecodeJObjectFn = unsafe { std::mem::transmute(addr) };
            let _ = DECODE_JOBJECT.set(f);
        }
    }
    cache_string_klass();
    Ok(())
}

/// Cache compressed `Class*` for `java.lang.String` via a live instance.
fn cache_string_klass() {
    if STRING_KLASS.load(Ordering::Acquire) != 0 {
        return;
    }
    let (Some(current), Some(decode)) = (THREAD_CURRENT.get().copied(), DECODE_JOBJECT.get().copied())
    else {
        log::warn!("cannot cache String klass (Thread helpers missing)");
        return;
    };
    let ok = with_attached_jni(|env| {
        let js = env
            .new_string("")
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let thread = unsafe { current() };
        if thread.is_null() {
            return Err(ArtError::Msg("Thread::Current null while caching String klass".into()));
        }
        let obj = unsafe { decode(thread, js.as_raw()) };
        if obj.is_null() {
            return Err(ArtError::Msg("DecodeJObject(String) null".into()));
        }
        // Object::klass_ is a compressed HeapReference at offset 0.
        let klass = unsafe { std::ptr::read_unaligned(obj as *const u32) } as usize;
        if klass == 0 {
            return Err(ArtError::Msg("String klass_ is 0".into()));
        }
        STRING_KLASS.store(klass, Ordering::Release);
        log::info!("cached java.lang.String klass compressed={klass:#x}");
        Ok(())
    });
    if let Err(e) = ok {
        log::warn!("cache String klass failed: {e}");
    }
}

fn ensure_invoke_hook() -> Result<u32, ArtError> {
    if INSTALLED.load(Ordering::Acquire) {
        return Ok(1);
    }
    let mut last_id = 0u32;
    let mut hooked = 0u32;

    // Prefer quick stubs: they see ArtMethod::Invoke traffic and other runtime→Java calls.
    // Still install ArtMethod::Invoke as a fallback if stubs are missing (older images).
    let mut targets: Vec<(String, usize, InvokeLayout)> = Vec::new();
    for name in QUICK_INVOKE_STUBS {
        if let Some(addr) = scan_libart_symbol(name) {
            let layout = if name.contains("static") {
                InvokeLayout::QuickStatic
            } else {
                InvokeLayout::QuickInstance
            };
            targets.push(((*name).to_string(), addr, layout));
        }
    }
    if targets.is_empty() {
        let addr = scan_libart_symbol(INVOKE_SYM)
            .ok_or_else(|| ArtError::Msg("no ArtMethod invoke entrypoints found".into()))?;
        targets.push((INVOKE_SYM.to_string(), addr, InvokeLayout::ArtInvoke));
    }

    for (name, addr, layout) in targets {
        let code = unsafe { std::slice::from_raw_parts(addr as *const u8, 16) }.to_vec();
        match attach(
            addr as u64,
            &code,
            HookCallbacks {
                on_enter: Some(Box::new(move |cpu: &mut CpuContext| {
                    on_invoke_enter(cpu, layout);
                })),
                on_leave: None,
                save_simd: false,
                replace_mode: false,
            },
        ) {
            Ok(hook) => {
                log::info!("android API trace hooked {name} @ {addr:#x} id={}", hook.id);
                last_id = hook.id;
                hooked += 1;
            }
            Err(e) => {
                log::warn!("android API trace: failed to hook {name}: {e}");
            }
        }
    }
    if hooked == 0 {
        return Err(ArtError::Msg("failed to hook any ART invoke entrypoint".into()));
    }
    INSTALLED.store(true, Ordering::Release);
    Ok(last_id)
}

/// Register layout for ART invoke entrypoints (AArch64).
#[derive(Clone, Copy)]
enum InvokeLayout {
    /// `art_quick_invoke_stub`: x0=method, x1=args, x2=argsize, x5=shorty (args[0]=this).
    QuickInstance,
    /// `art_quick_invoke_static_stub`: same regs, no this slot.
    QuickStatic,
    /// `ArtMethod::Invoke`: x0=method, x1=thread, x2=args, x3=argsize, x5=shorty.
    ArtInvoke,
}

fn on_invoke_enter(cpu: &CpuContext, layout: InvokeLayout) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if IN_TRACE.get() {
        return;
    }
    let max = MAX_EVENTS.load(Ordering::Relaxed);
    if max > 0 && EVENT_COUNT.load(Ordering::Relaxed) >= max {
        ENABLED.store(false, Ordering::Relaxed);
        return;
    }

    let method = cpu.x[0] as *mut c_void;
    if method.is_null() {
        return;
    }

    IN_TRACE.set(true);

    // Prefer descriptor-based package filter; fall back to PrettyMethod (no signature).
    let class_dotted = declaring_descriptor(method)
        .map(|d| descriptor_to_dotted(&d))
        .or_else(|| pretty_method(method, false));
    let Some(class_key) = class_dotted else {
        IN_TRACE.set(false);
        return;
    };
    if !class_matches_filter(&class_key) {
        IN_TRACE.set(false);
        return;
    }

    let label = pretty_method(method, WITH_SIGNATURE.load(Ordering::Relaxed)).unwrap_or(class_key);

    // Prefer ArtMethod access flags over which stub we hooked — static methods must not
    // consume a synthetic "this" slot.
    let is_static = art_method_is_static(method);
    let (args_ptr, args_size) = match layout {
        InvokeLayout::QuickInstance | InvokeLayout::QuickStatic => {
            (cpu.x[1] as *const u32, cpu.x[2] as u32)
        }
        InvokeLayout::ArtInvoke => (cpu.x[2] as *const u32, cpu.x[3] as u32),
    };
    // Prefer PrettyMethod-derived shorty (safe), then stub x5, then ArtMethod::GetShorty if present.
    // Never call NterpGetShorty* — wrong ABI (caused SEGV at NterpGetShortyFromMethodId+48).
    let shorty = shorty_from_pretty(&label)
        .or_else(|| read_cstr(cpu.x[5] as *const libc::c_char))
        .or_else(|| art_method_shorty(method))
        .unwrap_or_default();
    let args_json = format_invoke_args_json(&shorty, args_ptr, args_size, is_static);

    let n = EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if let Some(cb) = SEND_CB.get() {
        let mut escaped = String::with_capacity(label.len() + 8);
        for ch in label.chars() {
            match ch {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                c if c.is_control() => {}
                c => escaped.push(c),
            }
        }
        let shorty_esc = escape_json_str(&shorty);
        let payload = format!(
            r#"{{"type":"android-api","n":{n},"method":"{escaped}","shorty":"{shorty_esc}","static":{},"args":{args_json}}}"#,
            if is_static { "true" } else { "false" }
        );
        cb(&payload);
    } else {
        log::info!("android-api #{n} {label} shorty={shorty} args={args_json}");
    }
    IN_TRACE.set(false);
}

fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn art_method_is_static(method: *mut c_void) -> bool {
    // ArtMethod::access_flags_ @ +4 on arm64 across API 24–34 (and current mainline).
    // String mirror compression is the main API-gated layout (see try_java_string_contents).
    if method.is_null() {
        return false;
    }
    let flags = unsafe { std::ptr::read_unaligned((method as *const u8).add(4) as *const u32) };
    flags & 0x0008 != 0
}

fn art_method_shorty(method: *mut c_void) -> Option<String> {
    let f = GET_SHORTY.get()?;
    let mut len = 0u32;
    let p = unsafe { f(method, &mut len) };
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy();
    if len > 0 && (len as usize) < s.len() {
        return validate_shorty(&s[..len as usize]);
    }
    validate_shorty(&s)
}

/// Build ART shorty from PrettyMethod text like
/// `java.net.InetAddress.getByAddress(java.lang.String, byte[], int)`.
fn shorty_from_pretty(pretty: &str) -> Option<String> {
    let open = pretty.rfind('(')?;
    let close = pretty.rfind(')')?;
    if close <= open {
        return None;
    }
    let params = &pretty[open + 1..close];
    let mut out = String::from("L"); // unknown return → object; enough for arg slots
    if params.trim().is_empty() {
        return validate_shorty(&out);
    }
    for raw in params.split(',') {
        let p = raw.trim();
        if p.is_empty() {
            continue;
        }
        let ch = if p.ends_with("[]") {
            '['
        } else {
            match p {
                "boolean" => 'Z',
                "byte" => 'B',
                "char" => 'C',
                "short" => 'S',
                "int" => 'I',
                "long" => 'J',
                "float" => 'F',
                "double" => 'D',
                "void" => continue,
                _ => 'L',
            }
        };
        out.push(ch);
    }
    validate_shorty(&out)
}

fn validate_shorty(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    if !s
        .chars()
        .all(|c| matches!(c, 'V' | 'Z' | 'B' | 'C' | 'S' | 'I' | 'J' | 'F' | 'D' | 'L' | '['))
    {
        return None;
    }
    Some(s.to_string())
}

fn read_cstr(p: *const libc::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let addr = p as usize;
    if addr < 0x1000 {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy();
    validate_shorty(&s)
}

/// Decode ART `uint32_t* args` using shorty (first char = return type).
fn format_invoke_args_json(
    shorty: &str,
    args_ptr: *const u32,
    args_size: u32,
    is_static: bool,
) -> String {
    if args_ptr.is_null() || args_size == 0 {
        return "[]".into();
    }
    // Cap generously — wide args (J/D) need 2 slots; allow leftover dump.
    let nwords = (args_size as usize / 4).min(64);
    let words = unsafe { std::slice::from_raw_parts(args_ptr, nwords) };
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0usize;

    if !is_static {
        if let Some(&w) = words.get(i) {
            parts.push(format!(
                r#"{{"t":"this","v":{}}}"#,
                object_value_json(w)
            ));
            i += 1;
        }
    }

    for ch in shorty.chars().skip(1) {
        if i >= words.len() {
            parts.push(format!(
                r#"{{"t":"missing","shorty":"{ch}"}}"#
            ));
            continue;
        }
        match ch {
            'Z' => {
                parts.push(format!(r#"{{"t":"boolean","v":{}}}"#, words[i] != 0));
                i += 1;
            }
            'B' => {
                parts.push(format!(r#"{{"t":"byte","v":{}}}"#, words[i] as i8));
                i += 1;
            }
            'C' => {
                parts.push(format!(r#"{{"t":"char","v":{}}}"#, words[i] as u16));
                i += 1;
            }
            'S' => {
                parts.push(format!(r#"{{"t":"short","v":{}}}"#, words[i] as i16));
                i += 1;
            }
            'I' => {
                parts.push(format!(r#"{{"t":"int","v":{}}}"#, words[i] as i32));
                i += 1;
            }
            'F' => {
                let f = f32::from_bits(words[i]);
                parts.push(format!(r#"{{"t":"float","v":{f}}}"#));
                i += 1;
            }
            'J' => {
                if i + 1 >= words.len() {
                    parts.push(r#"{"t":"long","v":null,"err":"truncated"}"#.into());
                    break;
                }
                let lo = words[i] as u64;
                let hi = words[i + 1] as u64;
                let v = (hi << 32) | lo;
                parts.push(format!(r#"{{"t":"long","v":"{v}"}}"#));
                i += 2;
            }
            'D' => {
                if i + 1 >= words.len() {
                    parts.push(r#"{"t":"double","v":null,"err":"truncated"}"#.into());
                    break;
                }
                let lo = words[i] as u64;
                let hi = words[i + 1] as u64;
                let d = f64::from_bits((hi << 32) | lo);
                parts.push(format!(r#"{{"t":"double","v":{d}}}"#));
                i += 2;
            }
            'L' | '[' => {
                parts.push(format_object_arg(words[i], ch == '['));
                i += 1;
            }
            other => {
                parts.push(format!(r#"{{"t":"{other}","v":"{:#x}"}}"#, words[i]));
                i += 1;
            }
        }
    }

    // If the arg array had more slots than shorty consumed, surface them (debug mis-parses).
    if i < words.len() {
        let extra: Vec<String> = words[i..]
            .iter()
            .take(8)
            .map(|w| format!("{w:#x}"))
            .collect();
        parts.push(format!(
            r#"{{"t":"extra_slots","v":[{}],"words_total":{}}}"#,
            extra
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(","),
            words.len()
        ));
    }

    format!("[{}]", parts.join(","))
}

fn object_value_json(compressed: u32) -> String {
    if compressed == 0 {
        return "null".into();
    }
    if let Some(s) = try_java_string_contents(compressed) {
        let mut body = s;
        if body.len() > 512 {
            body.truncate(512);
            body.push('…');
        }
        return format!("\"{}\"", escape_json_str(&body));
    }
    format!("\"{compressed:#x}\"")
}

fn format_object_arg(compressed: u32, hint_array: bool) -> String {
    if compressed == 0 {
        return r#"{"t":"ref","v":null}"#.into();
    }
    if !hint_array {
        if let Some(s) = try_java_string_contents(compressed) {
            let mut body = s;
            if body.len() > 512 {
                body.truncate(512);
                body.push('…');
            }
            return format!(
                r#"{{"t":"string","v":"{}"}}"#,
                escape_json_str(&body)
            );
        }
    }
    // Decode arrays only when shorty says `[` (GetComponentType in the hook is unsafe).
    if hint_array {
        if let Some(arr_json) = try_java_array_contents(compressed) {
            return arr_json;
        }
    }
    format!(r#"{{"t":"ref","v":"{compressed:#x}"}}"#)
}

/// Decode `mirror::Array` (esp. `byte[]` for InetAddress etc.).
/// Layout (compressed oops): klass@0, monitor@4, length@8, data@12 (byte) or 16 (aligned).
fn try_java_array_contents(compressed: u32) -> Option<String> {
    let obj = compressed as usize;
    if obj < 0x1000 || obj & 0x7 != 0 {
        return None;
    }
    let length = unsafe { std::ptr::read_unaligned((obj + 8) as *const i32) };
    if !(0..=256).contains(&length) {
        return None;
    }
    // Byte/boolean arrays: data at +12. Long/double arrays align to 16 — try +12 first for IP sizes.
    let data_off = if length == 4 || length == 16 || length <= 32 {
        12usize
    } else {
        12usize
    };
    let bytes =
        unsafe { std::slice::from_raw_parts((obj + data_off) as *const u8, length as usize) };

    let hex = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    let nums = bytes
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let ip = if length == 4 {
        Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
    } else if length == 16 {
        let mut parts = Vec::with_capacity(8);
        for c in bytes.chunks(2) {
            parts.push(format!("{:x}", u16::from_be_bytes([c[0], c[1]])));
        }
        Some(parts.join(":"))
    } else {
        None
    };

    if let Some(ip) = ip {
        Some(format!(
            r#"{{"t":"bytes","length":{length},"v":[{nums}],"hex":"{hex}","ip":"{ip}"}}"#
        ))
    } else {
        Some(format!(
            r#"{{"t":"bytes","length":{length},"v":[{nums}],"hex":"{hex}"}}"#
        ))
    }
}

/// Read `java.lang.String` via mirror field layout (avoid ToModifiedUtf8 in the hook —
/// that path needs a full ScopedObjectAccess and has SEGV'd under invoke stubs).
fn try_java_string_contents(compressed: u32) -> Option<String> {
    let want = STRING_KLASS.load(Ordering::Acquire);
    if want == 0 {
        return None;
    }
    let obj = compressed as usize;
    if obj < 0x1000 || obj & 0x7 != 0 {
        return None;
    }
    let klass = unsafe { std::ptr::read_unaligned(obj as *const u32) } as usize;
    if klass != want {
        return None;
    }
    // count_: on API 26+ with string compression, length = count >> 1, bit0 = compressed.
    // Pre-O (API < 26) stores plain length (no compression flag).
    let count = unsafe { std::ptr::read_unaligned((obj + 8) as *const i32) };
    let sdk = super::java_api::android_sdk_int_or_0();
    let (len, is_compressed) = if sdk > 0 && sdk < 26 {
        (count as usize, false)
    } else {
        // Default / unknown: assume compression encoding (API 26+ / modern ART).
        (((count >> 1) as usize), (count & 1) != 0)
    };
    if len > 512 {
        return None;
    }
    // hash_code_ at +12; value payload at +16 (compact / inlined value_[0]).
    let data = obj + 16;
    if is_compressed {
        let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    } else {
        let u16s = unsafe { std::slice::from_raw_parts(data as *const u16, len) };
        Some(String::from_utf16_lossy(u16s))
    }
}
/// Frame-pump classes. They match `android.` but are not the API a script just called
/// (a toast still shows up as `android.widget.Toast`).
const NOISE_API_PREFIXES: &[&str] = &[
    "android.view.DisplayEventReceiver",
    "android.view.Choreographer",
    "android.view.ViewRootImpl",
    "android.view.ThreadedRenderer",
    "android.view.SurfaceControl",
    "android.view.InsetsController",
    "android.view.SyncRtSurfaceTransactionApplier",
    "android.graphics.HardwareRenderer",
    "android.animation.AnimationHandler",
];

fn is_noisy_api_class(class_dotted: &str) -> bool {
    NOISE_API_PREFIXES.iter().any(|p| {
        class_dotted == *p
            || class_dotted.starts_with(&format!("{p}$"))
            || class_dotted.starts_with(&format!("{p}."))
    })
}

fn class_matches_filter(class_dotted: &str) -> bool {
    if is_noisy_api_class(class_dotted) {
        return false;
    }
    let prefixes = PREFIXES.read();
    if prefixes.is_empty() {
        return true;
    }
    prefixes.iter().any(|p| class_dotted.starts_with(p.as_str()))
}

fn descriptor_to_dotted(desc: &str) -> String {
    let body = desc
        .trim_start_matches('L')
        .split(';')
        .next()
        .unwrap_or(desc);
    body.replace('/', ".")
}

fn declaring_descriptor(method: *mut c_void) -> Option<String> {
    let get = GET_DESC.get()?;
    let p = unsafe { get(method) };
    if p.is_null() {
        return None;
    }
    let desc = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    if desc.is_empty() {
        None
    } else {
        Some(desc)
    }
}

/// Call `std::string ArtMethod::PrettyMethod(ArtMethod*, bool)` (AArch64: sret in x8).
fn pretty_method(method: *mut c_void, with_sig: bool) -> Option<String> {
    let f = *PRETTY.get()?;
    // libc++ std::string is 24 bytes on Android arm64; keep 32 for alignment slack.
    let mut buf = [0u8; 32];
    unsafe {
        call_pretty_method_aarch64(f, method, with_sig, buf.as_mut_ptr());
        read_destroy_libcpp_string(&mut buf)
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn call_pretty_method_aarch64(
    f: usize,
    method: *mut c_void,
    with_sig: bool,
    sret: *mut u8,
) {
    // AAPCS64: non-trivial C++ returns use x8 as the indirect result register.
    // Keep the callee address in x16 so mov into x0/x1 cannot clobber it.
    core::arch::asm!(
        "mov x8, {sret}",
        "mov x0, {method}",
        "mov w1, {ws:w}",
        "blr x16",
        sret = in(reg) sret,
        method = in(reg) method,
        ws = in(reg) u32::from(with_sig),
        in("x16") f,
        clobber_abi("C"),
    );
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn call_pretty_method_aarch64(
    _f: usize,
    _method: *mut c_void,
    _with_sig: bool,
    _sret: *mut u8,
) {
}

/// libc++ `std::string` layout used by Frida / Android (SSO bit 0 of first byte).
unsafe fn read_destroy_libcpp_string(buf: &mut [u8; 32]) -> Option<String> {
    let is_large = (buf[0] & 1) != 0;
    let s = if is_large {
        let size = usize::from_le_bytes(buf[8..16].try_into().ok()?);
        let ptr = usize::from_le_bytes(buf[16..24].try_into().ok()?) as *const u8;
        if ptr.is_null() || size > 4096 {
            return None;
        }
        let bytes = std::slice::from_raw_parts(ptr, size);
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        // Tiny: payload starts at offset 1, NUL-terminated.
        let mut end = 1usize;
        while end < 24 && buf[end] != 0 {
            end += 1;
        }
        String::from_utf8_lossy(&buf[1..end]).into_owned()
    };
    if is_large {
        let ptr = usize::from_le_bytes(buf[16..24].try_into().ok()?) as *mut c_void;
        if let Some(del) = OP_DELETE.get() {
            del(ptr);
        }
    }
    if s.is_empty() || s == "null" {
        None
    } else {
        Some(s)
    }
}
