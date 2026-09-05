//! Frida-shaped Java runtime helpers (enumerate / version / main-thread / methods).

use super::{find_app_class, with_attached_jni};
use crate::ArtError;
use jni::objects::{JObject, JString, JValue};
use jni::sys::{jclass, jlong, JNIEnv};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::OnceLock;

static MAIN_TOKEN_CB: RwLock<Option<fn(u64)>> = RwLock::new(None);
static MAIN_BRIDGE_READY: OnceLock<()> = OnceLock::new();
static MAIN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Called from `goauld.MainBridge.onMain` on the UI thread.
pub fn set_main_token_callback(cb: fn(u64)) {
    *MAIN_TOKEN_CB.write() = Some(cb);
}

pub fn android_version() -> Result<String, ArtError> {
    with_attached_jni(|env| {
        let cls = env
            .find_class("android/os/Build$VERSION")
            .map_err(|e| ArtError::Jni(format!("Build.VERSION: {e}")))?;
        let release = env
            .get_static_field(&cls, "RELEASE", "Ljava/lang/String;")
            .map_err(|e| ArtError::Jni(format!("RELEASE: {e}")))?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let s: String = env
            .get_string(&JString::from(release))
            .map_err(|e| ArtError::Jni(e.to_string()))?
            .into();
        Ok(s)
    })
}

/// `android.os.Build.VERSION.SDK_INT` (cached after first successful read).
pub fn android_sdk_int() -> Result<u32, ArtError> {
    let cached = SDK_INT.load(Ordering::Acquire);
    if cached != 0 {
        return Ok(cached);
    }
    let v = with_attached_jni(|env| {
        let cls = env
            .find_class("android/os/Build$VERSION")
            .map_err(|e| ArtError::Jni(format!("Build.VERSION: {e}")))?;
        let sdk = env
            .get_static_field(&cls, "SDK_INT", "I")
            .map_err(|e| ArtError::Jni(format!("SDK_INT: {e}")))?
            .i()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        Ok(sdk as u32)
    })?;
    if v != 0 {
        SDK_INT.store(v, Ordering::Release);
    }
    Ok(v)
}

/// Best-effort SDK_INT without error (0 if unknown / not Android).
pub fn android_sdk_int_or_0() -> u32 {
    android_sdk_int().unwrap_or(0)
}

static SDK_INT: AtomicU32 = AtomicU32::new(0);

pub fn is_main_thread() -> Result<bool, ArtError> {
    with_attached_jni(|env| {
        let looper = env
            .find_class("android/os/Looper")
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let mine = env
            .call_static_method(&looper, "myLooper", "()Landroid/os/Looper;", &[])
            .map_err(|e| ArtError::Jni(e.to_string()))?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let main = env
            .call_static_method(&looper, "getMainLooper", "()Landroid/os/Looper;", &[])
            .map_err(|e| ArtError::Jni(e.to_string()))?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        if mine.is_null() || main.is_null() {
            return Ok(false);
        }
        Ok(env.is_same_object(&mine, &main).unwrap_or(false))
    })
}

/// Enumerate class names visible via app + boot class loaders (DexFile.entries).
pub fn enumerate_loaded_classes() -> Result<Vec<String>, ArtError> {
    with_attached_jni(|env| {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for loader in collect_loaders(env)? {
            collect_classes_from_loader(env, &loader, &mut out, &mut seen)?;
        }
        out.sort();
        Ok(out)
    })
}

/// Class loader identity strings (`$className@ptr`).
pub fn enumerate_class_loaders() -> Result<Vec<String>, ArtError> {
    with_attached_jni(|env| {
        let loaders = collect_loaders(env)?;
        let mut out = Vec::new();
        for l in loaders {
            let name = class_name_of(env, &l).unwrap_or_else(|_| "java.lang.ClassLoader".into());
            let ptr = l.as_raw() as usize;
            out.push(format!("{name}@{:#x}", ptr));
        }
        Ok(out)
    })
}

/// Declared methods for `class_name`: `{name,sig,isStatic,flags}`.
pub fn enumerate_class_methods(class_name: &str) -> Result<Vec<MethodDesc>, ArtError> {
    with_attached_jni(|env| {
        let cls = find_app_class(env, class_name)?;
        let methods = env
            .call_method(
                &cls,
                "getDeclaredMethods",
                "()[Ljava/lang/reflect/Method;",
                &[],
            )
            .map_err(|e| ArtError::Jni(format!("getDeclaredMethods: {e}")))?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let arr = jni::objects::JObjectArray::from(methods);
        let n = env
            .get_array_length(&arr)
            .map_err(|e| ArtError::Jni(e.to_string()))? as usize;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let m = env
                .get_object_array_element(&arr, i as i32)
                .map_err(|e| ArtError::Jni(e.to_string()))?;
            if m.is_null() {
                continue;
            }
            let name = call_string_method(env, &m, "getName", "()Ljava/lang/String;")?;
            let sig = method_jni_signature(env, &m)?;
            let mods = env
                .call_method(&m, "getModifiers", "()I", &[])
                .map_err(|e| ArtError::Jni(e.to_string()))?
                .i()
                .unwrap_or(0) as u32;
            let is_static = mods & 0x0008 != 0;
            out.push(MethodDesc {
                name,
                sig,
                is_static,
                flags: mods,
            });
        }
        Ok(out)
    })
}

#[derive(Debug, Clone)]
pub struct MethodDesc {
    pub name: String,
    pub sig: String,
    pub is_static: bool,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct FieldDesc {
    pub name: String,
    pub type_name: String,
    pub is_static: bool,
    pub flags: u32,
}

/// Declared fields for `class_name`.
pub fn enumerate_class_fields(class_name: &str) -> Result<Vec<FieldDesc>, ArtError> {
    with_attached_jni(|env| {
        let cls = find_app_class(env, class_name)?;
        let fields = env
            .call_method(
                &cls,
                "getDeclaredFields",
                "()[Ljava/lang/reflect/Field;",
                &[],
            )
            .map_err(|e| ArtError::Jni(format!("getDeclaredFields: {e}")))?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let arr = jni::objects::JObjectArray::from(fields);
        let n = env
            .get_array_length(&arr)
            .map_err(|e| ArtError::Jni(e.to_string()))? as usize;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let f = env
                .get_object_array_element(&arr, i as i32)
                .map_err(|e| ArtError::Jni(e.to_string()))?;
            if f.is_null() {
                continue;
            }
            let _ = env.call_method(&f, "setAccessible", "(Z)V", &[JValue::Bool(1.into())]);
            let name = call_string_method(env, &f, "getName", "()Ljava/lang/String;")?;
            let ty = env
                .call_method(&f, "getType", "()Ljava/lang/Class;", &[])
                .map_err(|e| ArtError::Jni(e.to_string()))?
                .l()
                .map_err(|e| ArtError::Jni(e.to_string()))?;
            let type_name = call_string_method(env, &ty, "getName", "()Ljava/lang/String;")?;
            let mods = env
                .call_method(&f, "getModifiers", "()I", &[])
                .map_err(|e| ArtError::Jni(e.to_string()))?
                .i()
                .unwrap_or(0) as u32;
            out.push(FieldDesc {
                name,
                type_name,
                is_static: mods & 0x0008 != 0,
                flags: mods,
            });
        }
        Ok(out)
    })
}

/// Read a static field as a JSON string (primitives/strings/toString fallback).
pub fn read_static_field_json(class_name: &str, field_name: &str) -> Result<String, ArtError> {
    with_attached_jni(|env| {
        let cls = find_app_class(env, class_name)?;
        let fname = env
            .new_string(field_name)
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let field = env
            .call_method(
                &cls,
                "getDeclaredField",
                "(Ljava/lang/String;)Ljava/lang/reflect/Field;",
                &[JValue::Object(&fname)],
            )
            .map_err(|e| {
                let _ = env.exception_clear();
                ArtError::Jni(format!("getDeclaredField {field_name}: {e}"))
            })?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        let _ = env.call_method(&field, "setAccessible", "(Z)V", &[JValue::Bool(1.into())]);
        let null_obj = JObject::null();
        let val = env
            .call_method(
                &field,
                "get",
                "(Ljava/lang/Object;)Ljava/lang/Object;",
                &[JValue::Object(&null_obj)],
            )
            .map_err(|e| {
                let _ = env.exception_clear();
                ArtError::Jni(format!("Field.get: {e}"))
            })?
            .l()
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        Ok(java_value_to_json(env, &val))
    })
}

/// Dump SharedPreferences + dataDir file listing for the current application.
pub fn dump_app_storage_json() -> Result<String, ArtError> {
    with_attached_jni(|env| {
        let app = current_application(env)?;
        if app.is_null() {
            return Ok("{}".into());
        }
        let pkg = call_string_method(env, &app, "getPackageName", "()Ljava/lang/String;")
            .unwrap_or_else(|_| "unknown".into());
        let data_dir = match env
            .call_method(&app, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;", &[])
            .and_then(|v| v.l())
        {
            Ok(info) if !info.is_null() => env
                .get_field(&info, "dataDir", "Ljava/lang/String;")
                .ok()
                .and_then(|v| v.l().ok())
                .and_then(|s| {
                    env.get_string(&JString::from(s))
                        .ok()
                        .map(|x| x.into())
                })
                .unwrap_or_default(),
            _ => {
                let _ = env.exception_clear();
                String::new()
            }
        };

        let mut prefs = serde_json::Map::new();
        if !data_dir.is_empty() {
            let prefs_dir = format!("{data_dir}/shared_prefs");
            if let Ok(rd) = std::fs::read_dir(&prefs_dir) {
                for ent in rd.flatten() {
                    let name = ent.file_name().to_string_lossy().into_owned();
                    if !name.ends_with(".xml") {
                        continue;
                    }
                    let pref_name = name.trim_end_matches(".xml");
                    if let Ok(map) = read_shared_prefs(env, &app, pref_name) {
                        prefs.insert(pref_name.to_string(), map);
                    }
                }
            }
        }

        let files = list_dir_shallow(if data_dir.is_empty() {
            None
        } else {
            Some(data_dir.as_str())
        });
        let file_snippets = if data_dir.is_empty() {
            serde_json::json!({})
        } else {
            read_small_files_under(&format!("{data_dir}/files"))
        };

        Ok(serde_json::json!({
            "package": pkg,
            "dataDir": data_dir,
            "sharedPrefs": prefs,
            "dataDirListing": files,
            "filesSnippets": file_snippets,
        })
        .to_string())
    })
}

/// Read text-ish files under `dir` (≤4 KiB each, max 32 files).
fn read_small_files_under(dir: &str) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return serde_json::Value::Object(out);
    };
    for ent in rd.flatten().take(32) {
        let Ok(meta) = ent.metadata() else {
            continue;
        };
        if !meta.is_file() || meta.len() > 4096 {
            continue;
        }
        let path = ent.path();
        let name = ent.file_name().to_string_lossy().into_owned();
        if let Ok(bytes) = std::fs::read(&path) {
            match String::from_utf8(bytes) {
                Ok(s) => {
                    out.insert(name, serde_json::Value::String(s));
                }
                Err(e) => {
                    out.insert(
                        name,
                        serde_json::json!({
                            "encoding": "base64",
                            "data": base64_encode(e.as_bytes()),
                        }),
                    );
                }
            }
        }
    }
    serde_json::Value::Object(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn read_shared_prefs(
    env: &mut jni::JNIEnv,
    app: &JObject,
    name: &str,
) -> Result<serde_json::Value, ArtError> {
    let jname = env
        .new_string(name)
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let sp = env
        .call_method(
            app,
            "getSharedPreferences",
            "(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
            &[JValue::Object(&jname), JValue::Int(0)],
        )
        .map_err(|e| {
            let _ = env.exception_clear();
            ArtError::Jni(format!("getSharedPreferences: {e}"))
        })?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let all = env
        .call_method(&sp, "getAll", "()Ljava/util/Map;", &[])
        .map_err(|e| {
            let _ = env.exception_clear();
            ArtError::Jni(format!("getAll: {e}"))
        })?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    if all.is_null() {
        return Ok(serde_json::json!({}));
    }
    let entry_set = env
        .call_method(&all, "entrySet", "()Ljava/util/Set;", &[])
        .map_err(|e| ArtError::Jni(e.to_string()))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let iter = env
        .call_method(&entry_set, "iterator", "()Ljava/util/Iterator;", &[])
        .map_err(|e| ArtError::Jni(e.to_string()))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let mut map = serde_json::Map::new();
    loop {
        let has = env
            .call_method(&iter, "hasNext", "()Z", &[])
            .ok()
            .and_then(|v| v.z().ok())
            .unwrap_or(false);
        if !has {
            break;
        }
        let entry = match env
            .call_method(&iter, "next", "()Ljava/lang/Object;", &[])
            .and_then(|v| v.l())
        {
            Ok(o) => o,
            Err(_) => {
                let _ = env.exception_clear();
                break;
            }
        };
        let key = match env
            .call_method(&entry, "getKey", "()Ljava/lang/Object;", &[])
            .and_then(|v| v.l())
        {
            Ok(k) => java_value_to_json(env, &k),
            Err(_) => continue,
        };
        let val = match env
            .call_method(&entry, "getValue", "()Ljava/lang/Object;", &[])
            .and_then(|v| v.l())
        {
            Ok(v) => java_value_to_json(env, &v),
            Err(_) => "null".into(),
        };
        let key_s = serde_json::from_str::<serde_json::Value>(&key)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or(key);
        let val_v = serde_json::from_str(&val).unwrap_or(serde_json::Value::String(val));
        map.insert(key_s, val_v);
    }
    Ok(serde_json::Value::Object(map))
}

fn list_dir_shallow(root: Option<&str>) -> serde_json::Value {
    let Some(root) = root else {
        return serde_json::json!([]);
    };
    let mut out = Vec::new();
    for sub in ["", "shared_prefs", "files", "databases", "cache"] {
        let path = if sub.is_empty() {
            root.to_string()
        } else {
            format!("{root}/{sub}")
        };
        let Ok(rd) = std::fs::read_dir(&path) else {
            continue;
        };
        let mut entries = Vec::new();
        for ent in rd.flatten().take(200) {
            let meta = ent.metadata().ok();
            entries.push(serde_json::json!({
                "name": ent.file_name().to_string_lossy(),
                "isDir": meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                "size": meta.as_ref().map(|m| m.len()).unwrap_or(0),
            }));
        }
        out.push(serde_json::json!({
            "path": path,
            "entries": entries,
        }));
    }
    serde_json::Value::Array(out)
}

fn java_value_to_json(env: &mut jni::JNIEnv, obj: &JObject) -> String {
    if obj.is_null() {
        return "null".into();
    }
    let cls_name = env
        .get_object_class(obj)
        .ok()
        .and_then(|c| call_string_method(env, &c, "getName", "()Ljava/lang/String;").ok())
        .unwrap_or_default();
    match cls_name.as_str() {
        "java.lang.String" => {
            if let Ok(s) = call_string_method(env, obj, "toString", "()Ljava/lang/String;") {
                return serde_json::to_string(&s).unwrap_or_else(|_| "\"\"".into());
            }
        }
        "java.lang.Boolean" => {
            if let Ok(s) = call_string_method(env, obj, "toString", "()Ljava/lang/String;") {
                return if s == "true" { "true" } else { "false" }.into();
            }
        }
        "java.lang.Integer" | "java.lang.Long" | "java.lang.Short" | "java.lang.Byte"
        | "java.lang.Float" | "java.lang.Double" => {
            if let Ok(s) = call_string_method(env, obj, "toString", "()Ljava/lang/String;") {
                return s;
            }
        }
        _ => {}
    }
    if let Ok(s) = call_string_method(env, obj, "toString", "()Ljava/lang/String;") {
        return serde_json::json!({
            "class": cls_name,
            "toString": s,
        })
        .to_string();
    }
    serde_json::json!({ "class": cls_name }).to_string()
}

/// Post `token` to the main looper; `onMain` invokes the registered callback.
pub fn schedule_on_main(token: u64) -> Result<(), ArtError> {
    ensure_main_bridge()?;
    with_attached_jni(|env| {
        let cls = main_bridge_class(env)?;
        env.call_static_method(&cls, "post", "(J)V", &[JValue::Long(token as i64)])
            .map_err(|e| {
                let _ = env.exception_clear();
                ArtError::Jni(format!("MainBridge.post: {e}"))
            })?;
        Ok(())
    })
}

pub fn next_main_token() -> u64 {
    MAIN_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn ensure_main_bridge() -> Result<(), ArtError> {
    if MAIN_BRIDGE_READY.get().is_some() {
        return Ok(());
    }
    with_attached_jni(|env| {
        let cls = main_bridge_class(env)?;
        env.register_native_methods(
            &cls,
            &[jni::NativeMethod {
                name: "onMain".into(),
                sig: "(J)V".into(),
                fn_ptr: native_on_main as *mut c_void,
            }],
        )
        .map_err(|e| ArtError::Jni(format!("RegisterNatives MainBridge: {e}")))?;
        let _ = MAIN_BRIDGE_READY.set(());
        Ok(())
    })
}

extern "system" fn native_on_main(_env: *mut JNIEnv, _clazz: jclass, token: jlong) {
    if let Some(cb) = *MAIN_TOKEN_CB.read() {
        cb(token as u64);
    }
}

fn main_bridge_class<'a>(
    env: &mut jni::JNIEnv<'a>,
) -> Result<jni::objects::JClass<'a>, ArtError> {
    super::toast::load_goauld_helper_class(env, "goauld.MainBridge")
}

fn collect_loaders<'a>(
    env: &mut jni::JNIEnv<'a>,
) -> Result<Vec<JObject<'a>>, ArtError> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    // App class loader
    if let Ok(app) = current_application(env) {
        if let Ok(loader) = env
            .call_method(&app, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
            .and_then(|v| v.l())
        {
            push_loader_chain(env, loader, &mut out, &mut seen);
        } else {
            let _ = env.exception_clear();
        }
    }

    // Boot / Object class loader
    if let Ok(obj_cls) = env.find_class("java/lang/Object") {
        if let Ok(loader) = env
            .call_method(&obj_cls, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
            .and_then(|v| v.l())
        {
            if !loader.is_null() {
                push_loader_chain(env, loader, &mut out, &mut seen);
            }
        } else {
            let _ = env.exception_clear();
        }
    }

    Ok(out)
}

fn push_loader_chain<'a>(
    env: &mut jni::JNIEnv<'a>,
    mut loader: JObject<'a>,
    out: &mut Vec<JObject<'a>>,
    seen: &mut HashSet<usize>,
) {
    while !loader.is_null() {
        let ptr = loader.as_raw() as usize;
        if !seen.insert(ptr) {
            break;
        }
        // Get parent before moving loader into out
        let parent = env
            .call_method(&loader, "getParent", "()Ljava/lang/ClassLoader;", &[])
            .ok()
            .and_then(|v| v.l().ok());
        out.push(loader);
        match parent {
            Some(p) => loader = p,
            None => break,
        }
    }
}

fn collect_classes_from_loader(
    env: &mut jni::JNIEnv,
    loader: &JObject,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) -> Result<(), ArtError> {
    // BaseDexClassLoader.pathList.dexElements[].dexFile.entries()
    let cl_cls = match env.get_object_class(loader) {
        Ok(c) => c,
        Err(_) => {
            let _ = env.exception_clear();
            return Ok(());
        }
    };
    let path_list = match env.get_field(loader, "pathList", "Ldalvik/system/DexPathList;") {
        Ok(v) => match v.l() {
            Ok(o) if !o.is_null() => o,
            _ => {
                let _ = env.exception_clear();
                // Try superclass field walk via getDeclaredField reflection
                return collect_via_reflection_path_list(env, loader, out, seen);
            }
        },
        Err(_) => {
            let _ = env.exception_clear();
            return collect_via_reflection_path_list(env, loader, out, seen);
        }
    };
    let _ = cl_cls;
    let elements = match env.get_field(
        &path_list,
        "dexElements",
        "[Ldalvik/system/DexPathList$Element;",
    ) {
        Ok(v) => match v.l() {
            Ok(o) => jni::objects::JObjectArray::from(o),
            Err(_) => return Ok(()),
        },
        Err(_) => {
            let _ = env.exception_clear();
            return Ok(());
        }
    };
    let n = env.get_array_length(&elements).unwrap_or(0) as i32;
    for i in 0..n {
        let elem = match env.get_object_array_element(&elements, i) {
            Ok(e) if !e.is_null() => e,
            _ => continue,
        };
        let dex = match env.get_field(&elem, "dexFile", "Ldalvik/system/DexFile;") {
            Ok(v) => match v.l() {
                Ok(o) if !o.is_null() => o,
                _ => continue,
            },
            Err(_) => {
                let _ = env.exception_clear();
                continue;
            }
        };
        let entries = match env
            .call_method(&dex, "entries", "()Ljava/util/Enumeration;", &[])
            .and_then(|v| v.l())
        {
            Ok(e) if !e.is_null() => e,
            _ => {
                let _ = env.exception_clear();
                continue;
            }
        };
        loop {
            let has = env
                .call_method(&entries, "hasMoreElements", "()Z", &[])
                .ok()
                .and_then(|v| v.z().ok())
                .unwrap_or(false);
            if !has {
                break;
            }
            let next = match env
                .call_method(&entries, "nextElement", "()Ljava/lang/Object;", &[])
                .and_then(|v| v.l())
            {
                Ok(o) => o,
                Err(_) => {
                    let _ = env.exception_clear();
                    break;
                }
            };
            if let Ok(s) = env.get_string(&JString::from(next)) {
                let name: String = s.into();
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
    }
    Ok(())
}

fn collect_via_reflection_path_list(
    env: &mut jni::JNIEnv,
    loader: &JObject,
    out: &mut Vec<String>,
    seen: &mut HashSet<String>,
) -> Result<(), ArtError> {
    // Fallback: Class.getDeclaredField("pathList") on BaseDexClassLoader
    let bcl = match env.find_class("dalvik/system/BaseDexClassLoader") {
        Ok(c) => c,
        Err(_) => {
            let _ = env.exception_clear();
            return Ok(());
        }
    };
    let field = match env.call_method(
        &bcl,
        "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;",
        &[JValue::Object(
            &env.new_string("pathList")
                .map_err(|e| ArtError::Jni(e.to_string()))?
                .into(),
        )],
    ) {
        Ok(v) => match v.l() {
            Ok(f) => f,
            Err(_) => return Ok(()),
        },
        Err(_) => {
            let _ = env.exception_clear();
            return Ok(());
        }
    };
    let _ = env.call_method(&field, "setAccessible", "(Z)V", &[JValue::Bool(1.into())]);
    let path_list = match env
        .call_method(
            &field,
            "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            &[JValue::Object(loader)],
        )
        .and_then(|v| v.l())
    {
        Ok(o) if !o.is_null() => o,
        _ => {
            let _ = env.exception_clear();
            return Ok(());
        }
    };
    // Re-enter with a fake: set field via temporary — simplify by getting dexElements reflectively
    let pl_cls = env.get_object_class(&path_list).map_err(|e| ArtError::Jni(e.to_string()))?;
    let de_field = match env.call_method(
        &pl_cls,
        "getDeclaredField",
        "(Ljava/lang/String;)Ljava/lang/reflect/Field;",
        &[JValue::Object(
            &env.new_string("dexElements")
                .map_err(|e| ArtError::Jni(e.to_string()))?
                .into(),
        )],
    ) {
        Ok(v) => v.l().ok(),
        Err(_) => {
            let _ = env.exception_clear();
            None
        }
    };
    let Some(de_field) = de_field else {
        return Ok(());
    };
    let _ = env.call_method(&de_field, "setAccessible", "(Z)V", &[JValue::Bool(1.into())]);
    let elements_obj = match env
        .call_method(
            &de_field,
            "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            &[JValue::Object(&path_list)],
        )
        .and_then(|v| v.l())
    {
        Ok(o) => o,
        _ => return Ok(()),
    };
    let elements = jni::objects::JObjectArray::from(elements_obj);
    let n = env.get_array_length(&elements).unwrap_or(0) as i32;
    for i in 0..n {
        let elem = match env.get_object_array_element(&elements, i) {
            Ok(e) if !e.is_null() => e,
            _ => continue,
        };
        let dex = match env.get_field(&elem, "dexFile", "Ldalvik/system/DexFile;") {
            Ok(v) => match v.l() {
                Ok(o) if !o.is_null() => o,
                _ => continue,
            },
            Err(_) => {
                let _ = env.exception_clear();
                continue;
            }
        };
        let entries = match env
            .call_method(&dex, "entries", "()Ljava/util/Enumeration;", &[])
            .and_then(|v| v.l())
        {
            Ok(e) if !e.is_null() => e,
            _ => continue,
        };
        loop {
            let has = env
                .call_method(&entries, "hasMoreElements", "()Z", &[])
                .ok()
                .and_then(|v| v.z().ok())
                .unwrap_or(false);
            if !has {
                break;
            }
            let next = match env
                .call_method(&entries, "nextElement", "()Ljava/lang/Object;", &[])
                .and_then(|v| v.l())
            {
                Ok(o) => o,
                Err(_) => break,
            };
            if let Ok(s) = env.get_string(&JString::from(next)) {
                let name: String = s.into();
                if seen.insert(name.clone()) {
                    out.push(name);
                }
            }
        }
    }
    Ok(())
}

fn current_application<'a>(env: &mut jni::JNIEnv<'a>) -> Result<JObject<'a>, ArtError> {
    let at = env
        .find_class("android/app/ActivityThread")
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    env.call_static_method(
        &at,
        "currentApplication",
        "()Landroid/app/Application;",
        &[],
    )
    .map_err(|e| ArtError::Jni(e.to_string()))?
    .l()
    .map_err(|e| ArtError::Jni(e.to_string()))
}

fn class_name_of(env: &mut jni::JNIEnv, obj: &JObject) -> Result<String, ArtError> {
    let cls = env
        .get_object_class(obj)
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    call_string_method(env, &cls, "getName", "()Ljava/lang/String;")
}

fn call_string_method(
    env: &mut jni::JNIEnv,
    obj: &JObject,
    name: &str,
    sig: &str,
) -> Result<String, ArtError> {
    let v = env
        .call_method(obj, name, sig, &[])
        .map_err(|e| ArtError::Jni(format!("{name}: {e}")))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let js = JString::from(v);
    let s = env
        .get_string(&js)
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    Ok(s.into())
}

fn method_jni_signature(env: &mut jni::JNIEnv, method: &JObject) -> Result<String, ArtError> {
    // Build from getParameterTypes + getReturnType
    let params = env
        .call_method(method, "getParameterTypes", "()[Ljava/lang/Class;", &[])
        .map_err(|e| ArtError::Jni(e.to_string()))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    let arr = jni::objects::JObjectArray::from(params);
    let n = env.get_array_length(&arr).unwrap_or(0) as i32;
    let mut sig = String::from("(");
    for i in 0..n {
        let p = env
            .get_object_array_element(&arr, i)
            .map_err(|e| ArtError::Jni(e.to_string()))?;
        sig.push_str(&type_jni_name(env, &p)?);
    }
    sig.push(')');
    let ret = env
        .call_method(method, "getReturnType", "()Ljava/lang/Class;", &[])
        .map_err(|e| ArtError::Jni(e.to_string()))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    sig.push_str(&type_jni_name(env, &ret)?);
    Ok(sig)
}

fn type_jni_name(env: &mut jni::JNIEnv, cls: &JObject) -> Result<String, ArtError> {
    let is_prim = env
        .call_method(cls, "isPrimitive", "()Z", &[])
        .ok()
        .and_then(|v| v.z().ok())
        .unwrap_or(false);
    if is_prim {
        let name = call_string_method(env, cls, "getName", "()Ljava/lang/String;")?;
        return Ok(match name.as_str() {
            "void" => "V".into(),
            "boolean" => "Z".into(),
            "byte" => "B".into(),
            "char" => "C".into(),
            "short" => "S".into(),
            "int" => "I".into(),
            "long" => "J".into(),
            "float" => "F".into(),
            "double" => "D".into(),
            _ => "Ljava/lang/Object;".into(),
        });
    }
    let is_array = env
        .call_method(cls, "isArray", "()Z", &[])
        .ok()
        .and_then(|v| v.z().ok())
        .unwrap_or(false);
    if is_array {
        let name = call_string_method(env, cls, "getName", "()Ljava/lang/String;")?;
        // getName for arrays is already JNI-ish like "[I" or "[Ljava.lang.String;"
        return Ok(name.replace('.', "/"));
    }
    let name = call_string_method(env, cls, "getName", "()Ljava/lang/String;")?;
    Ok(format!("L{};", name.replace('.', "/")))
}
