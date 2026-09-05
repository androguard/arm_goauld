//! Show a framework `android.widget.Toast` from the agent (not the target APK).
//!
//! Loads a tiny embedded helper dex (`goauld.ToastBridge` / `goauld.MainBridge`) via
//! `InMemoryDexClassLoader`.

use super::with_attached_jni;
use crate::ArtError;
use jni::objects::{JObject, JValue};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Embedded `classes.dex` containing goauld helper classes.
const GOAULD_HELPER_DEX: &[u8] =
    include_bytes!("../../android-support/toast_bridge.dex");

static HELPER_LOADER: OnceLock<jni::objects::GlobalRef> = OnceLock::new();
static HELPER_CLASSES: Mutex<Option<HashMap<String, jni::objects::GlobalRef>>> =
    Mutex::new(None);

/// Show a long Toast using framework `android.widget.Toast` on the UI thread.
pub fn show_android_toast(message: &str) -> Result<(), ArtError> {
    with_attached_jni(|env| {
        let app_ctx = current_application_context(env)?;
        let bridge = load_goauld_helper_class(env, "goauld.ToastBridge")?;
        let jmsg = env
            .new_string(message)
            .map_err(|e| ArtError::Jni(format!("new_string: {e}")))?;
        env.call_static_method(
            &bridge,
            "show",
            "(Landroid/content/Context;Ljava/lang/String;)V",
            &[JValue::Object(&app_ctx), JValue::Object(&jmsg)],
        )
        .map_err(|e| {
            let _ = env.exception_clear();
            ArtError::Jni(format!("ToastBridge.show: {e}"))
        })?;
        Ok(())
    })
}

pub fn current_application_context<'a>(
    env: &mut jni::JNIEnv<'a>,
) -> Result<JObject<'a>, ArtError> {
    let at = env
        .find_class("android/app/ActivityThread")
        .map_err(|e| ArtError::Jni(format!("ActivityThread: {e}")))?;
    let app = env
        .call_static_method(
            &at,
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        )
        .map_err(|e| ArtError::Jni(format!("currentApplication: {e}")))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;
    if app.is_null() {
        return Err(ArtError::Jni(
            "ActivityThread.currentApplication() is null".into(),
        ));
    }
    Ok(app)
}

/// Load `goauld.*` helper class from the embedded dex (cached).
pub fn load_goauld_helper_class<'a>(
    env: &mut jni::JNIEnv<'a>,
    class_name: &str,
) -> Result<jni::objects::JClass<'a>, ArtError> {
    {
        let mut guard = HELPER_CLASSES.lock();
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        if let Some(g) = guard.as_ref().unwrap().get(class_name) {
            return Ok(unsafe { jni::objects::JClass::from_raw(g.as_raw()) });
        }
    }

    let loader = helper_loader(env)?;
    let name = env
        .new_string(class_name)
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
            ArtError::Jni(format!("loadClass {class_name}: {e}"))
        })?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;

    let global = env
        .new_global_ref(&cls_obj)
        .map_err(|e| ArtError::Jni(format!("global {class_name}: {e}")))?;
    HELPER_CLASSES
        .lock()
        .as_mut()
        .unwrap()
        .insert(class_name.to_string(), global);
    let g = HELPER_CLASSES.lock();
    let gref = g.as_ref().unwrap().get(class_name).unwrap();
    Ok(unsafe { jni::objects::JClass::from_raw(gref.as_raw()) })
}

fn helper_loader<'a>(env: &mut jni::JNIEnv<'a>) -> Result<JObject<'a>, ArtError> {
    if let Some(g) = HELPER_LOADER.get() {
        return Ok(unsafe { JObject::from_raw(g.as_raw()) });
    }

    let arr = env
        .byte_array_from_slice(GOAULD_HELPER_DEX)
        .map_err(|e| ArtError::Jni(format!("dex byte[]: {e}")))?;
    let bb_class = env
        .find_class("java/nio/ByteBuffer")
        .map_err(|e| ArtError::Jni(format!("ByteBuffer: {e}")))?;
    let buf = env
        .call_static_method(
            &bb_class,
            "wrap",
            "([B)Ljava/nio/ByteBuffer;",
            &[JValue::Object(&JObject::from(arr))],
        )
        .map_err(|e| ArtError::Jni(format!("ByteBuffer.wrap: {e}")))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;

    let app = current_application_context(env)?;
    let parent = env
        .call_method(&app, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
        .map_err(|e| ArtError::Jni(format!("getClassLoader: {e}")))?
        .l()
        .map_err(|e| ArtError::Jni(e.to_string()))?;

    let loader_class = env
        .find_class("dalvik/system/InMemoryDexClassLoader")
        .map_err(|e| ArtError::Jni(format!("InMemoryDexClassLoader: {e}")))?;
    let loader = env
        .new_object(
            &loader_class,
            "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
            &[JValue::Object(&buf), JValue::Object(&parent)],
        )
        .map_err(|e| ArtError::Jni(format!("InMemoryDexClassLoader.<init>: {e}")))?;

    let global = env
        .new_global_ref(&loader)
        .map_err(|e| ArtError::Jni(format!("global helper loader: {e}")))?;
    let _ = HELPER_LOADER.set(global);
    let g = HELPER_LOADER.get().unwrap();
    Ok(unsafe { JObject::from_raw(g.as_raw()) })
}
