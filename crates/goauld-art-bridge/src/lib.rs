//! ART / Java hooking — Technique A: ArtMethod struct replacement (§5.1).
//!
//! On Android, `Java.use(...).implementation = fn` resolves the `ArtMethod*` via
//! JNI, calibrates `sizeof(ArtMethod)`, then rewrites the method as JNI-native
//! (Frida-style): `kAccNative` + `data_` = our bridge + quick entry =
//! `art_quick_generic_jni_trampoline`.

use parking_lot::RwLock;
use std::collections::HashMap;
use thiserror::Error;

#[cfg(target_os = "android")]
mod android;

#[derive(Debug, Error)]
pub enum ArtError {
    #[error("not calibrated")]
    NotCalibrated,
    #[error("jni: {0}")]
    Jni(String),
    #[error("hook not found")]
    NotFound,
    #[error("{0}")]
    Msg(String),
}

static ART_METHOD_SIZE: RwLock<Option<usize>> = RwLock::new(None);

#[derive(Clone)]
pub struct JavaHook {
    pub target: usize,
    pub saved: Vec<u8>,
    pub bridge: usize,
}

static HOOKS: RwLock<Vec<JavaHook>> = RwLock::new(Vec::new());

pub(crate) fn push_hook_backup(target: usize, saved: Vec<u8>) {
    HOOKS.write().push(JavaHook {
        target,
        saved,
        bridge: target,
    });
}

/// Calibrate `sizeof(ArtMethod)` from two adjacent method pointers.
pub fn calibrate_art_method_size(method_a: usize, method_b: usize) -> Result<usize, ArtError> {
    if method_a == 0 || method_b == 0 || method_a == method_b {
        return Err(ArtError::Msg("invalid calibration pointers".into()));
    }
    let size = method_a.abs_diff(method_b);
    if !(16..=512).contains(&size) {
        return Err(ArtError::Msg(format!(
            "implausible ArtMethod size {size}"
        )));
    }
    *ART_METHOD_SIZE.write() = Some(size);
    Ok(size)
}

pub fn set_art_method_size(size: usize) -> Result<(), ArtError> {
    if !(16..=512).contains(&size) {
        return Err(ArtError::Msg(format!(
            "implausible ArtMethod size {size}"
        )));
    }
    *ART_METHOD_SIZE.write() = Some(size);
    Ok(())
}

pub fn art_method_size() -> Result<usize, ArtError> {
    ART_METHOD_SIZE.read().ok_or(ArtError::NotCalibrated)
}

/// # Safety
/// Both pointers must be live `ArtMethod*` / calibrated buffers of `art_method_size()` bytes.
pub unsafe fn hook_art_method(target: usize, bridge: usize) -> Result<(), ArtError> {
    let size = art_method_size()?;
    let mut saved = vec![0u8; size];
    std::ptr::copy_nonoverlapping(target as *const u8, saved.as_mut_ptr(), size);
    std::ptr::copy_nonoverlapping(bridge as *const u8, target as *mut u8, size);
    HOOKS.write().push(JavaHook {
        target,
        saved,
        bridge,
    });
    Ok(())
}

pub unsafe fn unhook_art_method(target: usize) -> Result<(), ArtError> {
    let mut hooks = HOOKS.write();
    let idx = hooks
        .iter()
        .position(|h| h.target == target)
        .ok_or(ArtError::NotFound)?;
    let h = hooks.remove(idx);
    std::ptr::copy_nonoverlapping(h.saved.as_ptr(), target as *mut u8, h.saved.len());
    Ok(())
}

pub unsafe fn call_original<R>(target: usize, call: impl FnOnce() -> R) -> Result<R, ArtError> {
    let hooks = HOOKS.read();
    let h = hooks
        .iter()
        .find(|h| h.target == target)
        .ok_or(ArtError::NotFound)?
        .clone();
    drop(hooks);
    let size = h.saved.len();
    let mut hooked = vec![0u8; size];
    std::ptr::copy_nonoverlapping(target as *const u8, hooked.as_mut_ptr(), size);
    std::ptr::copy_nonoverlapping(h.saved.as_ptr(), target as *mut u8, size);
    let result = call();
    std::ptr::copy_nonoverlapping(hooked.as_ptr(), target as *mut u8, size);
    Ok(result)
}

pub const JNI_REGISTER_NATIVES_INDEX: usize = 215;

pub fn hook_register_natives_stub() {
    log::debug!("RegisterNatives hook: install on Android agent init");
}

static JS_IMPLS: RwLock<Option<HashMap<u64, u64>>> = RwLock::new(None);

fn js_impls() -> parking_lot::RwLockWriteGuard<'static, Option<HashMap<u64, u64>>> {
    let mut g = JS_IMPLS.write();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    g
}

pub fn set_js_implementation(bridge_id: u64, script_fn_token: u64) {
    js_impls().as_mut().unwrap().insert(bridge_id, script_fn_token);
}

pub fn take_js_implementation(bridge_id: u64) -> Option<u64> {
    JS_IMPLS
        .read()
        .as_ref()
        .and_then(|m| m.get(&bridge_id).copied())
}

/// True when a JS implementation has been assigned for `Class.method` key hash.
pub fn has_js_implementation(bridge_id: u64) -> bool {
    JS_IMPLS
        .read()
        .as_ref()
        .is_some_and(|m| m.contains_key(&bridge_id))
}

/// Install a live ART hook for `class_name.method_name` with JNI signature `sig`.
///
/// On non-Android hosts this records the JS registration only.
pub fn hook_java_method(class_name: &str, method_name: &str, sig: &str) -> Result<(), ArtError> {
    let key = format!("{class_name}.{method_name}");
    set_js_implementation(fxhash(&key), 1);
    #[cfg(target_os = "android")]
    {
        android::install_hook(class_name, method_name, sig)?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = sig;
        log::info!("Java hook recorded (host stub): {key}");
    }
    Ok(())
}

pub fn fxhash(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(target_os = "android")]
pub use android::{
    android_sdk_int, android_sdk_int_or_0, android_version, clear_hook_context,
    current_hook_context, dump_app_storage_json, enumerate_class_fields, enumerate_class_loaders,
    enumerate_class_methods, enumerate_loaded_classes, is_main_thread, js_call_original,
    next_main_token, read_static_field_json, schedule_on_main, set_hook_context,
    set_js_invoke_callback, set_main_token_callback, set_send_callback, show_android_toast,
    start_android_api_trace, stop_android_api_trace, with_attached_jni, AndroidApiTraceConfig,
    FieldDesc, MethodDesc, DEFAULT_API_PREFIXES,
};

#[cfg(not(target_os = "android"))]
pub fn set_send_callback(_cb: fn(&str)) {}

#[cfg(not(target_os = "android"))]
pub fn set_js_invoke_callback(_cb: fn(&str, i32) -> Option<i32>) {}

#[cfg(not(target_os = "android"))]
pub fn js_call_original(_key: &str, _x: i32) -> Option<i32> {
    None
}

#[cfg(not(target_os = "android"))]
#[derive(Clone, Debug, Default)]
pub struct AndroidApiTraceConfig {
    pub prefixes: Vec<String>,
    pub max_events: u64,
    pub with_signature: bool,
}

#[cfg(not(target_os = "android"))]
pub const DEFAULT_API_PREFIXES: &[&str] = &[
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "com.android.",
    "dalvik.",
];

#[cfg(not(target_os = "android"))]
pub fn start_android_api_trace(_cfg: AndroidApiTraceConfig) -> Result<u32, ArtError> {
    Err(ArtError::Msg(
        "android API trace only available on Android targets".into(),
    ))
}

#[cfg(not(target_os = "android"))]
pub fn stop_android_api_trace() {}

#[cfg(not(target_os = "android"))]
pub fn show_android_toast(_message: &str) -> Result<(), ArtError> {
    Err(ArtError::Msg(
        "android toast only available on Android targets".into(),
    ))
}

#[cfg(not(target_os = "android"))]
#[derive(Debug, Clone)]
pub struct MethodDesc {
    pub name: String,
    pub sig: String,
    pub is_static: bool,
    pub flags: u32,
}

#[cfg(not(target_os = "android"))]
#[derive(Debug, Clone)]
pub struct FieldDesc {
    pub name: String,
    pub type_name: String,
    pub is_static: bool,
    pub flags: u32,
}

#[cfg(not(target_os = "android"))]
pub fn android_version() -> Result<String, ArtError> {
    Ok("host".into())
}

#[cfg(not(target_os = "android"))]
pub fn android_sdk_int() -> Result<u32, ArtError> {
    Ok(0)
}

#[cfg(not(target_os = "android"))]
pub fn android_sdk_int_or_0() -> u32 {
    0
}

#[cfg(not(target_os = "android"))]
pub fn is_main_thread() -> Result<bool, ArtError> {
    Ok(false)
}

#[cfg(not(target_os = "android"))]
pub fn enumerate_loaded_classes() -> Result<Vec<String>, ArtError> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "android"))]
pub fn enumerate_class_loaders() -> Result<Vec<String>, ArtError> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "android"))]
pub fn enumerate_class_methods(_class_name: &str) -> Result<Vec<MethodDesc>, ArtError> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "android"))]
pub fn enumerate_class_fields(_class_name: &str) -> Result<Vec<FieldDesc>, ArtError> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "android"))]
pub fn read_static_field_json(_class_name: &str, _field_name: &str) -> Result<String, ArtError> {
    Ok("null".into())
}

#[cfg(not(target_os = "android"))]
pub fn dump_app_storage_json() -> Result<String, ArtError> {
    Ok("{}".into())
}

#[cfg(not(target_os = "android"))]
pub fn set_main_token_callback(_cb: fn(u64)) {}

#[cfg(not(target_os = "android"))]
pub fn schedule_on_main(_token: u64) -> Result<(), ArtError> {
    Err(ArtError::Msg("schedule_on_main: Android only".into()))
}

#[cfg(not(target_os = "android"))]
pub fn next_main_token() -> u64 {
    0
}

#[cfg(not(target_os = "android"))]
mod host_hook_ctx {
    use std::cell::Cell;
    thread_local! {
        static ENV: Cell<usize> = const { Cell::new(0) };
        static THIZ: Cell<usize> = const { Cell::new(0) };
        static ART: Cell<usize> = const { Cell::new(0) };
    }
    pub fn current() -> Option<(usize, usize, usize)> {
        let env = ENV.with(|c| c.get());
        let thiz = THIZ.with(|c| c.get());
        let art = ART.with(|c| c.get());
        if art == 0 || thiz == 0 {
            None
        } else {
            Some((env, thiz, art))
        }
    }
    pub fn set(env: usize, thiz: usize, art: usize) {
        ENV.with(|c| c.set(env));
        THIZ.with(|c| c.set(thiz));
        ART.with(|c| c.set(art));
    }
    pub fn clear() {
        set(0, 0, 0);
    }
}

#[cfg(not(target_os = "android"))]
pub fn current_hook_context() -> Option<(usize, usize, usize)> {
    host_hook_ctx::current()
}

#[cfg(not(target_os = "android"))]
pub fn set_hook_context(env: usize, thiz: usize, art: usize) {
    host_hook_ctx::set(env, thiz, art);
}

#[cfg(not(target_os = "android"))]
pub fn clear_hook_context() {
    host_hook_ctx::clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_a_struct_copy_roundtrip() {
        let size = 64usize;
        let mut target = vec![0xAAu8; size];
        let bridge = vec![0xBBu8; size];
        let a = target.as_ptr() as usize;
        let b = a + size;
        *ART_METHOD_SIZE.write() = Some(size);
        assert_eq!(art_method_size().unwrap(), size);

        unsafe {
            hook_art_method(target.as_mut_ptr() as usize, bridge.as_ptr() as usize).unwrap();
        }
        assert_eq!(target, bridge);

        let observed = unsafe {
            call_original(target.as_mut_ptr() as usize, || target[0]).unwrap()
        };
        assert_eq!(observed, 0xAA);
        assert_eq!(target[0], 0xBB);

        unsafe {
            unhook_art_method(target.as_mut_ptr() as usize).unwrap();
        }
        assert_eq!(target[0], 0xAA);
        let _ = (a, b);
    }

    #[test]
    fn call_original_restores_after_nested_read() {
        let size = 32usize;
        let mut target = vec![0x11u8; size];
        target[0] = 0xAA;
        let bridge = vec![0x22u8; size];
        *ART_METHOD_SIZE.write() = Some(size);
        unsafe {
            hook_art_method(target.as_mut_ptr() as usize, bridge.as_ptr() as usize).unwrap();
        }
        let seen = unsafe {
            call_original(target.as_mut_ptr() as usize, || {
                // While unhooked, bytes are original; nested read still original.
                let inner = call_original(target.as_mut_ptr() as usize, || target[0]).unwrap();
                assert_eq!(inner, 0xAA);
                target[0]
            })
            .unwrap()
        };
        assert_eq!(seen, 0xAA);
        assert_eq!(target[0], 0x22, "hook bytes restored after call_original");
        unsafe {
            unhook_art_method(target.as_mut_ptr() as usize).unwrap();
        }
    }

    #[test]
    fn js_call_original_outside_hook_is_none() {
        assert!(js_call_original("com.example.Target.hookMe", 1).is_none());
    }

    #[test]
    fn hook_context_roundtrip() {
        assert!(current_hook_context().is_none());
        set_hook_context(0x10, 0x20, 0x30);
        assert_eq!(current_hook_context(), Some((0x10, 0x20, 0x30)));
        clear_hook_context();
        assert!(current_hook_context().is_none());
    }

    #[test]
    fn hook_context_requires_thiz_and_art() {
        set_hook_context(1, 0, 3);
        assert!(current_hook_context().is_none());
        set_hook_context(1, 2, 0);
        assert!(current_hook_context().is_none());
        clear_hook_context();
    }

    #[test]
    fn calibrate_rejects_bad_delta() {
        assert!(calibrate_art_method_size(100, 100).is_err());
        assert!(calibrate_art_method_size(0, 64).is_err());
        assert!(calibrate_art_method_size(1000, 1000 + 8).is_err());
    }

    #[test]
    fn calibrate_accepts_plausible() {
        let sz = calibrate_art_method_size(0x1000, 0x1000 + 72).unwrap();
        assert_eq!(sz, 72);
    }

    #[test]
    fn has_js_implementation_after_hook_java_method() {
        let key = "com.example.javatarget.Target.hookMe";
        assert!(!has_js_implementation(fxhash(key)));
        hook_java_method(
            "com.example.javatarget.Target",
            "hookMe",
            "(I)I",
        )
        .unwrap();
        assert!(has_js_implementation(fxhash(key)));
    }
}
