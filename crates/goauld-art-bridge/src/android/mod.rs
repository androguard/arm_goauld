//! Android-only: JNI resolve + ArtMethod "make native" hook.

mod api_trace;
mod java_api;
mod toast;

pub use api_trace::{
    start_android_api_trace, stop_android_api_trace, AndroidApiTraceConfig, DEFAULT_API_PREFIXES,
};
pub use java_api::{
    android_sdk_int, android_sdk_int_or_0, android_version, dump_app_storage_json,
    enumerate_class_fields, enumerate_class_loaders, enumerate_class_methods,
    enumerate_loaded_classes, is_main_thread, next_main_token, read_static_field_json,
    schedule_on_main, set_main_token_callback, FieldDesc, MethodDesc,
};
pub use toast::show_android_toast;

use crate::{
    art_method_size, calibrate_art_method_size, set_art_method_size, ArtError,
};
use jni::objects::{JClass, JObject, JValue};
use jni::sys::{jint, jobject, JNIEnv, JavaVM as RawJavaVM, JNI_OK, JNI_VERSION_1_6};
use jni::JavaVM;
use parking_lot::RwLock;
use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::c_void;
use std::ptr;
use std::sync::OnceLock;

const K_ACC_NATIVE: u32 = 0x0100;
const K_ACC_FAST_NATIVE: u32 = 0x0008_0000;
const K_ACC_CRITICAL_NATIVE: u32 = 0x0020_0000;

/// Android 14 arm64 ArtMethod layout (art_method.h android14-release).
const OFF_ACCESS_FLAGS: usize = 4;
const OFF_DATA: usize = 16;
const OFF_ENTRY: usize = 24;
const ART_METHOD_SIZE_A14: usize = 32;

const MAX_SLOTS: usize = 16;

#[derive(Clone)]
struct LiveHook {
    key: String,
    art_method: usize,
    saved: Vec<u8>,
    /// Heap clone of the original ArtMethod bytes (for callOriginal).
    backup_art: Option<usize>,
    /// GlobalRef to `java.lang.reflect.Method` (artMethod field retargeted for backup invoke).
    reflected_method: usize,
    /// GlobalRef to declaring `jclass`.
    declaring_class: usize,
    sig: String,
    is_static: bool,
    slot: usize,
}

static LIVE: RwLock<Option<HashMap<usize, LiveHook>>> = RwLock::new(None);
static SLOTS: RwLock<Option<Vec<Option<LiveHook>>>> = RwLock::new(None);
static TRAMPOLINE: OnceLock<usize> = OnceLock::new();

thread_local! {
    static CUR_ENV: Cell<usize> = const { Cell::new(0) };
    static CUR_THIZ: Cell<usize> = const { Cell::new(0) };
    static CUR_ART: Cell<usize> = const { Cell::new(0) };
    static IN_BRIDGE: Cell<bool> = const { Cell::new(false) };
    static IN_ORIGINAL: Cell<bool> = const { Cell::new(false) };
}

fn live_map() -> parking_lot::RwLockWriteGuard<'static, Option<HashMap<usize, LiveHook>>> {
    let mut g = LIVE.write();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    g
}

fn slots() -> parking_lot::RwLockWriteGuard<'static, Option<Vec<Option<LiveHook>>>> {
    let mut g = SLOTS.write();
    if g.is_none() {
        *g = Some(vec![None; MAX_SLOTS]);
    }
    g
}

pub fn install_hook(class_name: &str, method_name: &str, sig: &str) -> Result<(), ArtError> {
    with_vm(|vm| {
        // Attach if this thread has no env yet (agent JS thread).
        let env_result = vm.get_env();
        match env_result {
            Ok(mut env) => install_hook_env(&mut env, class_name, method_name, sig),
            Err(_) => {
                let mut env = vm
                    .attach_current_thread()
                    .map_err(|e| ArtError::Jni(format!("AttachCurrentThread: {e}")))?;
                install_hook_env(&mut env, class_name, method_name, sig)
            }
        }
    })
}

fn install_hook_env(
    env: &mut jni::JNIEnv,
    class_name: &str,
    method_name: &str,
    sig: &str,
) -> Result<(), ArtError> {
    let class = find_app_class(env, class_name)?;

    // Resolve a real ArtMethod* via reflection — on modern ART, jmethodID may be
    // an index (JNI ID indirection), not a pointer (fault addr 0x7 seen in the wild).
    let (art, static_method, reflected) =
        resolve_art_method_ptr(env, &class, class_name, method_name, sig)?;

    ensure_calibrated_ptr(env, &class, art)?;

    let size = art_method_size()?;
    let mut saved = vec![0u8; size];
    unsafe {
        ptr::copy_nonoverlapping(art as *const u8, saved.as_mut_ptr(), size);
    }

    let trampoline = {
        let cached = TRAMPOLINE.get().copied();
        if let Some(t) = cached {
            t
        } else {
            let t = resolve_jni_trampoline()
                .or_else(|_| steal_jni_trampoline_from_native(env))
                .unwrap_or(0);
            let _ = TRAMPOLINE.set(t);
            t
        }
    };
    if trampoline == 0 {
        return Err(ArtError::Msg(
            "art_quick_generic_jni_trampoline not found in libart".into(),
        ));
    }
    if art < 0x1000 {
        return Err(ArtError::Msg(format!(
            "ArtMethod pointer looks invalid: {art:#x}"
        )));
    }

    let slot = {
        let mut s = slots();
        let vec = s.as_mut().unwrap();
        vec.iter()
            .position(|e| e.is_none())
            .ok_or_else(|| ArtError::Msg("too many concurrent Java hooks".into()))?
    };

    let bridge_fn = bridge_fn_for_slot(slot);

    unsafe {
        let flags_ptr = (art + OFF_ACCESS_FLAGS) as *mut u32;
        let mut flags = ptr::read(flags_ptr);
        flags |= K_ACC_NATIVE;
        flags &= !(K_ACC_FAST_NATIVE | K_ACC_CRITICAL_NATIVE);
        flags &= !0x8000_0000;
        flags &= !0x4000_0000;
        ptr::write(flags_ptr, flags);
        ptr::write((art + OFF_DATA) as *mut usize, bridge_fn);
        ptr::write((art + OFF_ENTRY) as *mut usize, trampoline);
    }

    let backup_art = unsafe {
        let p = libc::malloc(size) as usize;
        if p != 0 {
            ptr::copy_nonoverlapping(saved.as_ptr(), p as *mut u8, size);
            Some(p)
        } else {
            None
        }
    };

    let reflected_g = env
        .new_global_ref(&reflected)
        .map_err(|e| ArtError::Jni(format!("NewGlobalRef Method: {e}")))?;
    let class_g = env
        .new_global_ref(&class)
        .map_err(|e| ArtError::Jni(format!("NewGlobalRef Class: {e}")))?;

    let key = format!("{class_name}.{method_name}");
    let hook = LiveHook {
        key: key.clone(),
        art_method: art,
        saved: saved.clone(),
        backup_art,
        reflected_method: reflected_g.as_raw() as usize,
        declaring_class: class_g.as_raw() as usize,
        sig: sig.to_string(),
        is_static: static_method,
        slot,
    };
    // Leak GlobalRefs for process lifetime (hooks are permanent for now).
    std::mem::forget(reflected_g);
    std::mem::forget(class_g);

    slots().as_mut().unwrap()[slot] = Some(hook.clone());
    live_map().as_mut().unwrap().insert(art, hook);
    crate::push_hook_backup(art, saved);

    log::info!(
        "ART hook installed: {key}{sig} art={art:#x} size={size} slot={slot} trampoline={trampoline:#x} static={static_method}"
    );
    Ok(())
}

/// Get ArtMethod* from `java.lang.reflect.Executable.artMethod` (long).
/// Also returns the local `java.lang.reflect.Method` jobject.
fn resolve_art_method_ptr<'a>(
    env: &mut jni::JNIEnv<'a>,
    class: &JClass<'a>,
    class_name: &str,
    method_name: &str,
    sig: &str,
) -> Result<(usize, bool, JObject<'a>), ArtError> {
    let (param_classes, is_void_ret) = jni_sig_param_classes(env, sig)?;
    let _ = is_void_ret;
    let name = env
        .new_string(method_name)
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let params = env
        .new_object_array(
            param_classes.len() as i32,
            "java/lang/Class",
            JObject::null(),
        )
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    for (i, c) in param_classes.iter().enumerate() {
        env.set_object_array_element(&params, i as i32, c)
            .map_err(|e| ArtError::Jni(e.to_string()))?;
    }

    let mut static_method = false;
    let reflected = match env.call_method(
        class,
        "getDeclaredMethod",
        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
        &[JValue::Object(&name), JValue::Object(&params)],
    ) {
        Ok(v) => v.l().map_err(|e| ArtError::Jni(e.to_string()))?,
        Err(_) => {
            let _ = env.exception_clear();
            static_method = true;
            env.call_method(
                class,
                "getDeclaredMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
                &[JValue::Object(&name), JValue::Object(&params)],
            )
            .map_err(|e| {
                let _ = env.exception_clear();
                ArtError::Jni(format!(
                    "getDeclaredMethod {class_name}.{method_name}{sig}: {e}"
                ))
            })?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?
        }
    };

    let art = env
        .get_field(&reflected, "artMethod", "J")
        .map_err(|e| ArtError::Jni(format!("Executable.artMethod: {e}")))?
        .j()
        .map_err(|e| ArtError::Jni(e.to_string()))? as usize;
    if art == 0 {
        return Err(ArtError::Msg("Executable.artMethod == 0".into()));
    }
    log::info!("resolved ArtMethod* via reflection: {art:#x}");
    Ok((art, static_method, reflected))
}

fn jni_sig_param_classes<'a>(
    env: &mut jni::JNIEnv<'a>,
    sig: &str,
) -> Result<(Vec<JObject<'a>>, bool), ArtError> {
    let start = sig
        .find('(')
        .ok_or_else(|| ArtError::Msg(format!("bad sig {sig}")))?
        + 1;
    let end = sig
        .find(')')
        .ok_or_else(|| ArtError::Msg(format!("bad sig {sig}")))?;
    let mut i = start;
    let bytes = sig.as_bytes();
    let mut out = Vec::new();
    while i < end {
        let (cls, next) = match bytes[i] as char {
            'I' => (primitive_class(env, "int")?, i + 1),
            'Z' => (primitive_class(env, "boolean")?, i + 1),
            'B' => (primitive_class(env, "byte")?, i + 1),
            'C' => (primitive_class(env, "char")?, i + 1),
            'S' => (primitive_class(env, "short")?, i + 1),
            'J' => (primitive_class(env, "long")?, i + 1),
            'F' => (primitive_class(env, "float")?, i + 1),
            'D' => (primitive_class(env, "double")?, i + 1),
            'L' => {
                let semi = sig[i..]
                    .find(';')
                    .ok_or_else(|| ArtError::Msg(format!("bad object in {sig}")))?
                    + i;
                let name = &sig[i + 1..semi];
                let c = env
                    .find_class(name)
                    .or_else(|_| {
                        let _ = env.exception_clear();
                        // App class — load via app ClassLoader path.
                        find_app_class(env, &name.replace('/', ".")).map(|jc| jc.into())
                    })
                    .map_err(|e| ArtError::Jni(format!("param class {name}: {e}")))?;
                (JObject::from(c), semi + 1)
            }
            '[' => {
                // Array — find_class with the array type descriptor.
                let mut j = i;
                while j < end && bytes[j] == b'[' {
                    j += 1;
                }
                if j < end && bytes[j] == b'L' {
                    while j < end && bytes[j] != b';' {
                        j += 1;
                    }
                    j += 1;
                } else {
                    j += 1;
                }
                let desc = &sig[i..j];
                let c = env
                    .find_class(desc)
                    .map_err(|e| ArtError::Jni(format!("array class {desc}: {e}")))?;
                (JObject::from(c), j)
            }
            other => {
                return Err(ArtError::Msg(format!(
                    "unsupported sig char {other} in {sig}"
                )))
            }
        };
        out.push(cls);
        i = next;
    }
    let ret_void = sig.ends_with('V');
    Ok((out, ret_void))
}

fn primitive_class<'a>(env: &mut jni::JNIEnv<'a>, name: &str) -> Result<JObject<'a>, ArtError> {
    // java.lang.Integer.TYPE etc.
    let wrapper = match name {
        "int" => "java/lang/Integer",
        "boolean" => "java/lang/Boolean",
        "byte" => "java/lang/Byte",
        "char" => "java/lang/Character",
        "short" => "java/lang/Short",
        "long" => "java/lang/Long",
        "float" => "java/lang/Float",
        "double" => "java/lang/Double",
        "void" => "java/lang/Void",
        _ => return Err(ArtError::Msg(format!("unknown primitive {name}"))),
    };
    let cls = env
        .find_class(wrapper)
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let ty = env
        .get_static_field(cls, "TYPE", "Ljava/lang/Class;")
        .map_err(|e| ArtError::Jni(e.to_string()))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    Ok(ty)
}

fn ensure_calibrated_ptr<'a>(
    env: &mut jni::JNIEnv<'a>,
    class: &JClass<'a>,
    primary: usize,
) -> Result<(), ArtError> {
    if art_method_size().is_ok() {
        return Ok(());
    }
    // Try onCreate on the same class for adjacent ArtMethod delta.
    if let Ok((other, _, _)) = resolve_art_method_ptr(
        env,
        class,
        "local",
        "onCreate",
        "(Landroid/os/Bundle;)V",
    ) {
        let delta = primary.abs_diff(other);
        if (16..=512).contains(&delta) && delta % 8 == 0 {
            log::info!("calibrated ArtMethod size={delta} via onCreate");
            return calibrate_art_method_size(primary, other).map(|_| ());
        }
    } else {
        let _ = env.exception_clear();
    }
    let sdk = java_api::android_sdk_int_or_0();
    // arm64 ArtMethod is 32 bytes on API 34 (A14) and typically the same on 26–33;
    // pre-O layouts differed — prefer calibration above when possible.
    let fallback = if sdk > 0 && sdk < 26 {
        24
    } else {
        ART_METHOD_SIZE_A14
    };
    log::warn!(
        "using fallback ArtMethod size {fallback} (sdk_int={sdk}; calibrate via adjacent methods when possible)"
    );
    set_art_method_size(fallback)
}

/// Load an application class via ActivityThread → Application → ClassLoader.
/// Never use FindClass for app classes: an AttachCurrentThread env only sees
/// the boot/system ClassLoader.
pub(super) fn find_app_class<'a>(
    env: &mut jni::JNIEnv<'a>,
    class_name: &str,
) -> Result<JClass<'a>, ArtError> {
    let dotted = class_name.replace('/', ".");
    let slash = dotted.replace('.', "/");

    // Framework / JDK classes are visible to FindClass.
    let is_framework = dotted.starts_with("android.")
        || dotted.starts_with("java.")
        || dotted.starts_with("javax.")
        || dotted.starts_with("dalvik.")
        || dotted.starts_with("org.apache.")
        || dotted.starts_with("kotlin.");
    if is_framework {
        return env
            .find_class(&slash)
            .map_err(|e| ArtError::Jni(format!("FindClass {dotted}: {e}")));
    }

    let at = env
        .find_class("android/app/ActivityThread")
        .map_err(|e| ArtError::Jni(format!("ActivityThread: {e}")))?;
    let app = env
        .call_static_method(
            at,
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        )
        .map_err(|e| ArtError::Jni(format!("currentApplication: {e}")))?
        .l()
        .map_err(|e| ArtError::Jni(format!("currentApplication obj: {e}")))?;
    if app.is_null() {
        return Err(ArtError::Jni(
            "currentApplication() is null — too early?".into(),
        ));
    }
    let loader = env
        .call_method(&app, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
        .map_err(|e| ArtError::Jni(format!("getClassLoader: {e}")))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let name = env
        .new_string(&dotted)
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let cls_obj = env
        .call_method(
            &loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name)],
        )
        .map_err(|e| {
            let _ = env.exception_clear();
            ArtError::Jni(format!("loadClass {dotted}: {e}"))
        })?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    Ok(JClass::from(cls_obj))
}

fn bridge_fn_for_slot(slot: usize) -> usize {
    match slot {
        0 => bridge0 as usize,
        1 => bridge1 as usize,
        2 => bridge2 as usize,
        3 => bridge3 as usize,
        4 => bridge4 as usize,
        5 => bridge5 as usize,
        6 => bridge6 as usize,
        7 => bridge7 as usize,
        8 => bridge8 as usize,
        9 => bridge9 as usize,
        10 => bridge10 as usize,
        11 => bridge11 as usize,
        12 => bridge12 as usize,
        13 => bridge13 as usize,
        14 => bridge14 as usize,
        _ => bridge15 as usize,
    }
}

macro_rules! def_bridge {
    ($name:ident, $slot:expr) => {
        extern "system" fn $name(env: *mut JNIEnv, thiz: jobject, x: jint) -> jint {
            dispatch_slot($slot, env, thiz, x)
        }
    };
}

def_bridge!(bridge0, 0);
def_bridge!(bridge1, 1);
def_bridge!(bridge2, 2);
def_bridge!(bridge3, 3);
def_bridge!(bridge4, 4);
def_bridge!(bridge5, 5);
def_bridge!(bridge6, 6);
def_bridge!(bridge7, 7);
def_bridge!(bridge8, 8);
def_bridge!(bridge9, 9);
def_bridge!(bridge10, 10);
def_bridge!(bridge11, 11);
def_bridge!(bridge12, 12);
def_bridge!(bridge13, 13);
def_bridge!(bridge14, 14);
def_bridge!(bridge15, 15);

fn dispatch_slot(slot: usize, env: *mut JNIEnv, thiz: jobject, x: jint) -> jint {
    let hook = {
        let g = SLOTS.read();
        g.as_ref()
            .and_then(|v| v.get(slot).and_then(|h| h.clone()))
    };
    let Some(hook) = hook else {
        log::error!("java bridge: empty slot {slot}");
        return x;
    };

    // Nested entry must not re-enter JS — invoke backup ArtMethod only.
    if IN_BRIDGE.get() {
        if IN_ORIGINAL.get() {
            log::error!("java bridge: recursive callOriginal for slot {slot}");
            return x;
        }
        return call_original_int(env, thiz, x, &hook).unwrap_or(x);
    }

    IN_BRIDGE.set(true);
    CUR_ENV.set(env as usize);
    CUR_ART.set(hook.art_method);

    // Promote thiz to a GlobalRef so the JS worker can use it with its own JNIEnv.
    // Keep the GlobalRef alive until after try_js_invoke returns (Drop deletes it).
    let thiz_global = unsafe {
        let jenv = match jni::JNIEnv::from_raw(env) {
            Ok(e) => e,
            Err(_) => {
                IN_BRIDGE.set(false);
                CUR_ENV.set(0);
                CUR_ART.set(0);
                return x;
            }
        };
        let obj = JObject::from_raw(thiz);
        match jenv.new_global_ref(&obj) {
            Ok(g) => g,
            Err(e) => {
                log::error!("NewGlobalRef thiz: {e}");
                IN_BRIDGE.set(false);
                CUR_ENV.set(0);
                CUR_ART.set(0);
                return x;
            }
        }
    };
    CUR_THIZ.set(thiz_global.as_raw() as usize);

    emit_called(&hook.key, x);

    let ret = match try_js_invoke(&hook.key, x) {
        Some(v) => v,
        None => {
            // Queue/JS unavailable — still prove the ArtMethod patch.
            if let Some(cb) = SEND_CB.get() {
                cb(&format!("called with {x}"));
            }
            x.saturating_add(1000)
        }
    };

    drop(thiz_global);
    CUR_ENV.set(0);
    CUR_THIZ.set(0);
    CUR_ART.set(0);
    IN_BRIDGE.set(false);
    ret
}

/// Snapshot of the active hook context (for the JS worker / callOriginal).
pub fn current_hook_context() -> Option<(usize, usize, usize)> {
    let env = CUR_ENV.get();
    let thiz = CUR_THIZ.get();
    let art = CUR_ART.get();
    if art == 0 || thiz == 0 {
        None
    } else {
        Some((env, thiz, art))
    }
}

/// Install TLS hook context on the JS worker before running user JS.
pub fn set_hook_context(env: usize, thiz: usize, art: usize) {
    CUR_ENV.set(env);
    CUR_THIZ.set(thiz);
    CUR_ART.set(art);
    IN_BRIDGE.set(true);
}

pub fn clear_hook_context() {
    CUR_ENV.set(0);
    CUR_THIZ.set(0);
    CUR_ART.set(0);
    IN_BRIDGE.set(false);
}

/// Run `f` with a JNIEnv on this thread (attaches permanently if needed).
///
/// Uses permanent attach so `ArtMethod::Invoke` leaving the thread in
/// `kRunnable` does not trip DetachCurrentThread CheckJNI aborts.
pub fn with_attached_jni<F, R>(f: F) -> Result<R, ArtError>
where
    F: FnOnce(&mut jni::JNIEnv) -> Result<R, ArtError>,
{
    with_vm(|vm| match vm.get_env() {
        Ok(mut env) => f(&mut env),
        Err(_) => {
            let mut env = vm
                .attach_current_thread_permanently()
                .map_err(|e| ArtError::Jni(format!("AttachCurrentThread: {e}")))?;
            f(&mut env)
        }
    })
}

fn resolve_jni_trampoline() -> Result<usize, ArtError> {
    for name in [
        "art_quick_generic_jni_trampoline",
        "art_quick_generic_jni_trampoline_cfi",
    ] {
        let c = CString::new(name).unwrap();
        let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c.as_ptr()) };
        if !p.is_null() {
            log::info!("resolved {name} at {p:?}");
            return Ok(p as usize);
        }
    }
    // Symbol is often local (not in dynsym) — scan full ELF symtab.
    if let Some(addr) = scan_libart_symbol("art_quick_generic_jni_trampoline") {
        log::info!("resolved trampoline via symtab at {addr:#x}");
        return Ok(addr);
    }
    Err(ArtError::Msg("jni trampoline not found".into()))
}

/// Steal `entry_point_from_quick_compiled_code_` from a known native method.
fn steal_jni_trampoline_from_native(env: &mut jni::JNIEnv) -> Result<usize, ArtError> {
    // java.lang.System.currentTimeMillis() is native.
    let cls = env
        .find_class("java/lang/System")
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let (art, _, _) = resolve_art_method_ptr(env, &cls, "java.lang.System", "currentTimeMillis", "()J")?;
    let entry = unsafe { ptr::read((art + OFF_ENTRY) as *const usize) };
    if entry < 0x1000 {
        return Err(ArtError::Msg(format!(
            "stolen trampoline looks invalid: {entry:#x}"
        )));
    }
    log::info!("stolen jni trampoline from System.currentTimeMillis entry={entry:#x}");
    Ok(entry)
}

pub(super) fn scan_libart_symbol(sym: &str) -> Option<usize> {
    // Prefer dlsym — GLOBAL/PROTECTED exports resolve even when .symtab is thin.
    if let Ok(c) = CString::new(sym) {
        let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c.as_ptr()) };
        if !p.is_null() {
            return Some(p as usize);
        }
        for lib in [
            "libart.so",
            "/apex/com.android.art/lib64/libart.so",
            "/apex/com.android.runtime/lib64/libart.so",
        ] {
            let Ok(clib) = CString::new(lib) else {
                continue;
            };
            let h = unsafe { libc::dlopen(clib.as_ptr(), libc::RTLD_NOW) };
            if h.is_null() {
                continue;
            }
            let p = unsafe { libc::dlsym(h, c.as_ptr()) };
            if !p.is_null() {
                return Some(p as usize);
            }
        }
    }

    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    let mut bias = None;
    let mut path = None;
    for line in maps.lines() {
        if !line.contains("libart.so") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let _perms = parts.next()?;
        let off = u64::from_str_radix(parts.next()?, 16).ok()?;
        let start = u64::from_str_radix(range.split('-').next()?, 16).ok()?;
        if start >= off {
            bias = Some(start - off);
        }
        if let Some(p) = parts.last() {
            if p.starts_with('/') {
                path = Some(p.to_string());
            }
        }
        if bias.is_some() && path.is_some() {
            break;
        }
    }
    let bias = bias?;
    let path = path?;
    let bytes = std::fs::read(&path).ok()?;
    let off = find_dynsym(&bytes, sym)?;
    Some((bias + off) as usize)
}

fn find_dynsym(image: &[u8], symbol: &str) -> Option<u64> {
    find_elf_symbol(image, symbol, /*dyn_only*/ true)
        .or_else(|| find_elf_symbol(image, symbol, /*dyn_only*/ false))
}

fn find_elf_symbol(image: &[u8], symbol: &str, dyn_only: bool) -> Option<u64> {
    if image.len() < 64 || &image[0..4] != b"\x7fELF" || image[4] != 2 {
        return None;
    }
    if dyn_only {
        let phoff = u64::from_le_bytes(image[32..40].try_into().ok()?) as usize;
        let phentsize = u16::from_le_bytes(image[54..56].try_into().ok()?) as usize;
        let phnum = u16::from_le_bytes(image[56..58].try_into().ok()?) as usize;
        let mut dyn_vaddr = None;
        for i in 0..phnum {
            let off = phoff + i * phentsize;
            let p_type = u32::from_le_bytes(image[off..off + 4].try_into().ok()?);
            if p_type == 2 {
                dyn_vaddr = Some(u64::from_le_bytes(image[off + 16..off + 24].try_into().ok()?));
            }
        }
        let dyn_off = vaddr_to_off(image, phoff, phentsize, phnum, dyn_vaddr?)?;
        let mut symtab = None;
        let mut strtab = None;
        let mut syment = 24u64;
        let mut pos = dyn_off;
        while pos + 16 <= image.len() {
            let tag = i64::from_le_bytes(image[pos..pos + 8].try_into().ok()?);
            let val = u64::from_le_bytes(image[pos + 8..pos + 16].try_into().ok()?);
            pos += 16;
            match tag {
                0 => break,
                6 => symtab = Some(val),
                5 => strtab = Some(val),
                11 => syment = val,
                _ => {}
            }
        }
        let symtab = vaddr_to_off(image, phoff, phentsize, phnum, symtab?)?;
        let strtab = vaddr_to_off(image, phoff, phentsize, phnum, strtab?)?;
        return scan_symtab(image, symtab, strtab, syment as usize, symbol, true);
    }

    // Full .symtab via section headers.
    let shoff = u64::from_le_bytes(image[40..48].try_into().ok()?) as usize;
    let shentsize = u16::from_le_bytes(image[58..60].try_into().ok()?) as usize;
    let shnum = u16::from_le_bytes(image[60..62].try_into().ok()?) as usize;
    let shstrndx = u16::from_le_bytes(image[62..64].try_into().ok()?) as usize;
    let shstr = shoff + shstrndx * shentsize;
    let shstr_off = u64::from_le_bytes(image[shstr + 24..shstr + 32].try_into().ok()?) as usize;
    let mut symtab_off = None;
    let mut symtab_size = 0usize;
    let mut strtab_off = None;
    for i in 0..shnum {
        let off = shoff + i * shentsize;
        let name_off = u32::from_le_bytes(image[off..off + 4].try_into().ok()?) as usize;
        let sh_type = u32::from_le_bytes(image[off + 4..off + 8].try_into().ok()?);
        let sh_offset = u64::from_le_bytes(image[off + 24..off + 32].try_into().ok()?) as usize;
        let sh_size = u64::from_le_bytes(image[off + 32..off + 40].try_into().ok()?) as usize;
        let name = read_cstr(image, shstr_off + name_off);
        if name == ".symtab" && sh_type == 2 {
            symtab_off = Some(sh_offset);
            symtab_size = sh_size;
        }
        if name == ".strtab" && sh_type == 3 {
            strtab_off = Some(sh_offset);
        }
    }
    let symtab = symtab_off?;
    let strtab = strtab_off?;
    let syment = 24usize;
    let count = symtab_size / syment;
    for i in 0..count {
        let sym = symtab + i * syment;
        if sym + 24 > image.len() {
            break;
        }
        let st_name = u32::from_le_bytes(image[sym..sym + 4].try_into().ok()?) as usize;
        let st_value = u64::from_le_bytes(image[sym + 8..sym + 16].try_into().ok()?);
        if st_value == 0 {
            continue;
        }
        let name = read_cstr(image, strtab + st_name);
        if name == symbol {
            return Some(st_value);
        }
    }
    None
}

fn scan_symtab(
    image: &[u8],
    symtab: usize,
    strtab: usize,
    syment: usize,
    symbol: &str,
    require_bind: bool,
) -> Option<u64> {
    for i in 0..65536 {
        let sym = symtab + i * syment;
        if sym + 24 > image.len() {
            break;
        }
        let st_name = u32::from_le_bytes(image[sym..sym + 4].try_into().ok()?) as usize;
        let st_value = u64::from_le_bytes(image[sym + 8..sym + 16].try_into().ok()?);
        let st_info = image[sym + 4];
        let bind = st_info >> 4;
        if st_value == 0 {
            continue;
        }
        if require_bind && bind == 0 {
            continue;
        }
        let name = read_cstr(image, strtab + st_name);
        if name == symbol {
            return Some(st_value);
        }
    }
    None
}

fn vaddr_to_off(
    image: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    vaddr: u64,
) -> Option<usize> {
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(image[off..off + 4].try_into().ok()?);
        if p_type != 1 {
            continue;
        }
        let p_offset = u64::from_le_bytes(image[off + 8..off + 16].try_into().ok()?);
        let p_vaddr = u64::from_le_bytes(image[off + 16..off + 24].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(image[off + 32..off + 40].try_into().ok()?);
        if vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz {
            return Some((p_offset + (vaddr - p_vaddr)) as usize);
        }
    }
    None
}

fn read_cstr(image: &[u8], start: usize) -> String {
    if start >= image.len() {
        return String::new();
    }
    let slice = &image[start..];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(0);
    String::from_utf8_lossy(&slice[..nul]).into_owned()
}

fn emit_called(key: &str, x: jint) {
    log::info!("java bridge invoked {key} x={x}");
}

type SendCb = fn(&str);
pub(super) static SEND_CB: OnceLock<SendCb> = OnceLock::new();

pub fn set_send_callback(cb: SendCb) {
    let _ = SEND_CB.set(cb);
}

fn try_js_invoke(key: &str, x: jint) -> Option<jint> {
    JS_INVOKE_CB.get().and_then(|cb| cb(key, x))
}

type JsInvokeCb = fn(&str, jint) -> Option<jint>;
static JS_INVOKE_CB: OnceLock<JsInvokeCb> = OnceLock::new();

pub fn set_js_invoke_callback(cb: JsInvokeCb) {
    let _ = JS_INVOKE_CB.set(cb);
}

pub fn js_call_original(key: &str, x: jint) -> Option<jint> {
    let art = CUR_ART.get();
    let env = CUR_ENV.get() as *mut JNIEnv;
    let thiz = CUR_THIZ.get() as jobject;
    if art == 0 || env.is_null() {
        log::warn!("javaCallOriginal outside hook: {key}");
        return None;
    }
    let hooks = LIVE.read();
    let hook = hooks.as_ref()?.get(&art)?.clone();
    drop(hooks);
    call_original_int(env, thiz, x, &hook).ok()
}

fn call_original_int(
    env_ptr: *mut JNIEnv,
    thiz: jobject,
    x: jint,
    hook: &LiveHook,
) -> Result<jint, ArtError> {
    if IN_ORIGINAL.get() {
        return Err(ArtError::Msg("callOriginal re-entered".into()));
    }
    let backup = hook
        .backup_art
        .ok_or_else(|| ArtError::Msg("no backup ArtMethod".into()))?;
    IN_ORIGINAL.set(true);
    let result = unsafe { invoke_backup_art_method(backup, thiz, x, hook.is_static) };
    IN_ORIGINAL.set(false);
    let _ = env_ptr;
    result
}

type ArtMethodInvokeFn = unsafe extern "C" fn(
    this: *mut c_void,
    thread: *mut c_void,
    args: *mut u32,
    args_size: u32,
    result: *mut u64,
    shorty: *const libc::c_char,
);
type ThreadCurrentFn = unsafe extern "C" fn() -> *mut c_void;
/// `Thread::DecodeJObject(jobject) const` — returns `ObjPtr`/`mirror::Object*`.
type DecodeJObjectFn =
    unsafe extern "C" fn(thread: *mut c_void, obj: jobject) -> *mut c_void;

static ART_INVOKE: OnceLock<ArtMethodInvokeFn> = OnceLock::new();
static THREAD_CURRENT: OnceLock<ThreadCurrentFn> = OnceLock::new();
static DECODE_JOBJECT: OnceLock<DecodeJObjectFn> = OnceLock::new();

fn resolve_art_invoke() -> Result<ArtMethodInvokeFn, ArtError> {
    if let Some(f) = ART_INVOKE.get() {
        return Ok(*f);
    }
    let sym = "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc";
    let addr = scan_libart_symbol(sym)
        .ok_or_else(|| ArtError::Msg("art::ArtMethod::Invoke not found".into()))?;
    let f: ArtMethodInvokeFn = unsafe { std::mem::transmute(addr) };
    let _ = ART_INVOKE.set(f);
    Ok(f)
}

fn resolve_thread_current() -> Result<ThreadCurrentFn, ArtError> {
    if let Some(f) = THREAD_CURRENT.get() {
        return Ok(*f);
    }
    for sym in [
        "_ZN3art6Thread7CurrentEv",
        "_ZN3art6Thread14CurrentFromGdbEv",
    ] {
        if let Some(addr) = scan_libart_symbol(sym) {
            let f: ThreadCurrentFn = unsafe { std::mem::transmute(addr) };
            let _ = THREAD_CURRENT.set(f);
            return Ok(f);
        }
        let c = CString::new(sym).unwrap();
        let p = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c.as_ptr()) };
        if !p.is_null() {
            let f: ThreadCurrentFn = unsafe { std::mem::transmute(p) };
            let _ = THREAD_CURRENT.set(f);
            return Ok(f);
        }
    }
    Err(ArtError::Msg("art::Thread::Current not found".into()))
}

fn resolve_decode_jobject() -> Result<DecodeJObjectFn, ArtError> {
    if let Some(f) = DECODE_JOBJECT.get() {
        return Ok(*f);
    }
    let sym = "_ZNK3art6Thread13DecodeJObjectEP8_jobject";
    let addr = scan_libart_symbol(sym)
        .ok_or_else(|| ArtError::Msg("Thread::DecodeJObject not found".into()))?;
    let f: DecodeJObjectFn = unsafe { std::mem::transmute(addr) };
    let _ = DECODE_JOBJECT.set(f);
    Ok(f)
}

/// Invoke a heap-cloned ArtMethod* via ART internals (receiver decoded from JNI handle).
unsafe fn invoke_backup_art_method(
    backup: usize,
    thiz: jobject,
    x: jint,
    is_static: bool,
) -> Result<jint, ArtError> {
    let invoke = resolve_art_invoke()?;
    let current = resolve_thread_current()?;
    let decode = resolve_decode_jobject()?;
    let thread = current();
    if thread.is_null() {
        return Err(ArtError::Msg("Thread::Current returned null".into()));
    }

    let shorty = CString::new("II").unwrap();
    let mut result: u64 = 0;

    // ArgArray stores compressed references as uint32_t (low 32 bits of Object* on
    // arm64 heaps that live in the low 4GB).
    if is_static {
        let mut args = [x as u32];
        invoke(
            backup as *mut c_void,
            thread,
            args.as_mut_ptr(),
            (args.len() * 4) as u32, // ArtMethod::Invoke wants byte count
            &mut result,
            shorty.as_ptr(),
        );
    } else {
        let obj = decode(thread, thiz);
        if obj.is_null() {
            return Err(ArtError::Msg("DecodeJObject(thiz) null".into()));
        }
        let mut args = [obj as u32, x as u32];
        invoke(
            backup as *mut c_void,
            thread,
            args.as_mut_ptr(),
            (args.len() * 4) as u32,
            &mut result,
            shorty.as_ptr(),
        );
    }
    Ok(result as i32)
}

fn with_vm<F, R>(f: F) -> Result<R, ArtError>
where
    F: FnOnce(JavaVM) -> Result<R, ArtError>,
{
    unsafe {
        let mut n: jni::sys::jsize = 0;
        let mut raw: *mut RawJavaVM = ptr::null_mut();
        let get_vms = resolve_get_created_javavms()
            .ok_or_else(|| ArtError::Jni("JNI_GetCreatedJavaVMs not found".into()))?;
        let rc = get_vms(&mut raw, 1, &mut n);
        if rc != JNI_OK || n < 1 || raw.is_null() {
            return Err(ArtError::Jni(
                "JNI_GetCreatedJavaVMs: no JavaVM (not an ART process?)".into(),
            ));
        }
        let vm = JavaVM::from_raw(raw).map_err(|e| ArtError::Jni(e.to_string()))?;
        f(vm)
    }
}

type GetCreatedJavaVMsFn =
    unsafe extern "C" fn(*mut *mut RawJavaVM, jni::sys::jsize, *mut jni::sys::jsize) -> jint;

unsafe fn resolve_get_created_javavms() -> Option<GetCreatedJavaVMsFn> {
    let name = CString::new("JNI_GetCreatedJavaVMs").unwrap();
    // 1) Default namespace
    let mut p = libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr());
    // 2) Explicit libart (often RTLD_LOCAL in the zygote)
    if p.is_null() {
        for lib in [
            "libart.so",
            "/apex/com.android.art/lib64/libart.so",
            "/apex/com.android.runtime/lib64/libart.so",
        ] {
            let c = CString::new(lib).unwrap();
            let h = libc::dlopen(c.as_ptr(), libc::RTLD_NOW);
            if h.is_null() {
                continue;
            }
            p = libc::dlsym(h, name.as_ptr());
            if !p.is_null() {
                break;
            }
        }
    }
    // 3) Absolute via maps + dynsym
    if p.is_null() {
        if let Some(addr) = scan_libart_symbol("JNI_GetCreatedJavaVMs") {
            p = addr as *mut c_void;
        }
    }
    if p.is_null() {
        return None;
    }
    Some(std::mem::transmute(p))
}
