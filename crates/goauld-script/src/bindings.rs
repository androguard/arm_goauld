//! QuickJS runtime + Frida-shaped globals (`send`, `Module`, `Interceptor`, `Java`, …).

#![cfg(feature = "quickjs")]

use crate::api::{self, NativePointer as Np};
use crate::engine::ScriptId;
use crate::js_lock::JsLock;
use crate::js_queue::{self, JavaInvokeJob, JavaInvokeResult};
use goauld_native_hook::patch::attach;
use goauld_native_hook::trampoline::{CpuContext, HookCallbacks};
use goauld_proto::Message;
use parking_lot::Mutex;
use rquickjs::prelude::{Func, Opt};
use rquickjs::{Class, Context, Function, Object, Runtime, Value};
use std::sync::mpsc::Sender;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

pub struct HostBridge {
    pub tx: Mutex<Option<Sender<Message>>>,
    pub current_script: Mutex<ScriptId>,
}

impl HostBridge {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tx: Mutex::new(None),
            current_script: Mutex::new(0),
        })
    }

    pub fn emit_send(&self, payload_json: String, data: Option<Vec<u8>>) {
        let script_id = *self.current_script.lock();
        if let Some(tx) = self.tx.lock().as_ref() {
            let _ = tx.send(Message::Send {
                script_id,
                payload_json,
                data,
            });
        }
    }
}

static ENGINE_SLOT: Mutex<Option<Arc<QuickJsEngine>>> = Mutex::new(None);
static JS_LOCK_SLOT: Mutex<Option<Arc<JsLock>>> = Mutex::new(None);
static SHARED_BRIDGE: OnceLock<Arc<HostBridge>> = OnceLock::new();

pub fn set_engine_slot(eng: Arc<QuickJsEngine>) {
    *ENGINE_SLOT.lock() = Some(eng);
}

pub fn set_js_lock(lock: Arc<JsLock>) {
    *JS_LOCK_SLOT.lock() = Some(lock);
}

/// Process-wide bridge so the JS worker and all `ScriptEngine` instances share `send` routing.
pub fn shared_bridge() -> Arc<HostBridge> {
    SHARED_BRIDGE
        .get_or_init(|| HostBridge::new())
        .clone()
}

pub struct QuickJsEngine {
    _runtime: Runtime,
    context: Context,
    bridge: Arc<HostBridge>,
}

unsafe impl Send for QuickJsEngine {}
unsafe impl Sync for QuickJsEngine {}

impl QuickJsEngine {
    pub fn new(bridge: Arc<HostBridge>) -> Result<Self, String> {
        let runtime = Runtime::new().map_err(|e| format!("Runtime::new: {e}"))?;
        let context = Context::full(&runtime).map_err(|e| format!("Context::full: {e}"))?;
        let eng = Self {
            _runtime: runtime,
            context,
            bridge,
        };
        eng.install_globals()?;
        Ok(eng)
    }

    pub fn bridge(&self) -> Arc<HostBridge> {
        self.bridge.clone()
    }

    pub fn set_current_script(&self, id: ScriptId) {
        *self.bridge.current_script.lock() = id;
    }

    pub fn eval(&self, source: &str) -> Result<(), String> {
        self.context.with(|ctx| {
            use rquickjs::CatchResultExt;
            ctx.eval::<(), _>(source)
                .catch(&ctx)
                .map_err(|e| format!("{e}"))
        })
    }

    fn install_globals(&self) -> Result<(), String> {
        let bridge = self.bridge.clone();
        self.context.with(|ctx| -> Result<(), String> {
            install_ptr_class(&ctx)?;

            let helpers = Object::new(ctx.clone()).map_err(|e| e.to_string())?;

            let b = bridge.clone();
            ctx.globals()
                .set(
                    "send",
                    Func::from(move |payload: String| {
                        // Coerce non-strings via JS prelude wrapper — this binding
                        // handles string; prelude overrides send for objects.
                        let json = serde_json::to_string(&payload).unwrap_or(payload);
                        b.emit_send(json, None);
                    }),
                )
                .map_err(|e| e.to_string())?;

            let b2 = bridge.clone();
            helpers
                .set(
                    "sendJson",
                    Func::from(move |json: String| {
                        b2.emit_send(json, None);
                    }),
                )
                .map_err(|e| e.to_string())?;

            let b3 = bridge.clone();
            helpers
                .set(
                    "sendJsonData",
                    Func::from(move |json: String, data: Vec<u8>| {
                        b3.emit_send(json, if data.is_empty() { None } else { Some(data) });
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "findExport",
                    Func::from(|module_name: Opt<String>, export_name: String| -> Option<f64> {
                        api::module::find_export_by_name(module_name.0.as_deref(), &export_name)
                            .map(|p| p.0 as f64)
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "findBase",
                    Func::from(|module_name: String| -> Option<f64> {
                        api::module::find_base_address(&module_name).map(|p| p.0 as f64)
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "readUtf8",
                    Func::from(|addr: f64| -> String {
                        api::memory::read_utf8_string(Np(addr as u64), None)
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "processInfoJson",
                    Func::from(|| -> String {
                        let i = api::process::info();
                        serde_json::json!({
                            "id": i.id,
                            "arch": i.arch,
                            "platform": i.platform,
                            "pageSize": i.page_size,
                            "pointerSize": i.pointer_size,
                            "codeSigningPolicy": i.code_signing_policy,
                            "cwd": api::process::get_current_dir(),
                            "home": api::process::get_home_dir(),
                            "tmp": api::process::get_tmp_dir(),
                            "tid": api::process::get_current_thread_id(),
                            "debugger": api::process::is_debugger_attached(),
                        })
                        .to_string()
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "enumerateModulesJson",
                    Func::from(|| -> String {
                        let mods: Vec<_> = api::process::enumerate_modules()
                            .into_iter()
                            .map(|m| {
                                serde_json::json!({
                                    "name": m.name,
                                    "base": m.base,
                                    "size": m.size,
                                    "path": m.path,
                                })
                            })
                            .collect();
                        serde_json::to_string(&mods).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "findModuleByNameJson",
                    Func::from(|name: String| -> Option<String> {
                        api::process::find_module_by_name(&name).map(|m| {
                            serde_json::json!({
                                "name": m.name,
                                "base": m.base,
                                "size": m.size,
                                "path": m.path,
                            })
                            .to_string()
                        })
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "findModuleByAddressJson",
                    Func::from(|addr: f64| -> Option<String> {
                        api::process::find_module_by_address(Np(addr as u64)).map(|m| {
                            serde_json::json!({
                                "name": m.name,
                                "base": m.base,
                                "size": m.size,
                                "path": m.path,
                            })
                            .to_string()
                        })
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "enumerateRangesJson",
                    Func::from(|protection: String, coalesce: Opt<bool>| -> String {
                        let coalesce = coalesce.0.unwrap_or(false);
                        let ranges: Vec<_> = api::process::enumerate_ranges(&protection, coalesce)
                            .into_iter()
                            .map(|r| {
                                let mut o = serde_json::json!({
                                    "base": r.base,
                                    "size": r.size,
                                    "protection": r.protection,
                                });
                                if let Some(path) = r.file_path {
                                    o.as_object_mut().unwrap().insert(
                                        "file".into(),
                                        serde_json::json!({
                                            "path": path,
                                            "offset": r.file_offset.unwrap_or(0),
                                            "size": r.size,
                                        }),
                                    );
                                }
                                o
                            })
                            .collect();
                        serde_json::to_string(&ranges).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "findRangeByAddressJson",
                    Func::from(|addr: f64| -> Option<String> {
                        api::process::find_range_by_address(Np(addr as u64)).map(|r| {
                            let mut o = serde_json::json!({
                                "base": r.base,
                                "size": r.size,
                                "protection": r.protection,
                            });
                            if let Some(path) = r.file_path {
                                o.as_object_mut().unwrap().insert(
                                    "file".into(),
                                    serde_json::json!({
                                        "path": path,
                                        "offset": r.file_offset.unwrap_or(0),
                                        "size": r.size,
                                    }),
                                );
                            }
                            o.to_string()
                        })
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "enumerateThreadsJson",
                    Func::from(|| -> String {
                        let threads: Vec<_> = api::thread::enumerate_threads()
                            .into_iter()
                            .map(|t| {
                                serde_json::json!({
                                    "id": t.id,
                                    "name": t.name,
                                    "state": t.state,
                                })
                            })
                            .collect();
                        serde_json::to_string(&threads).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "threadSleep",
                    Func::from(|secs: f64| {
                        api::thread::sleep(secs);
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "threadBacktraceJson",
                    Func::from(|accurate: Opt<bool>, max_frames: Opt<f64>| -> String {
                        let accurate = accurate.0.unwrap_or(true);
                        let max = max_frames.0.map(|n| n as usize).unwrap_or(16);
                        let frames: Vec<_> = api::thread::backtrace(accurate, max)
                            .into_iter()
                            .map(|p| p.0)
                            .collect();
                        serde_json::to_string(&frames).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryAlloc",
                    Func::from(|size: f64| -> f64 { api::memory::alloc(size as usize).0 as f64 }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryAllocUtf8",
                    Func::from(|s: String| -> f64 {
                        api::memory::alloc_utf8_string(&s).0 as f64
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryCopy",
                    Func::from(|dst: f64, src: f64, n: f64| {
                        api::memory::copy(Np(dst as u64), Np(src as u64), n as usize);
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryDup",
                    Func::from(|addr: f64, size: f64| -> f64 {
                        api::memory::dup(Np(addr as u64), size as usize).0 as f64
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryProtect",
                    Func::from(|addr: f64, size: f64, prot: String| -> bool {
                        api::memory::protect(Np(addr as u64), size as usize, &prot)
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryQueryProtection",
                    Func::from(|addr: f64| -> Option<String> {
                        api::memory::query_protection(Np(addr as u64))
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryWriteBytes",
                    Func::from(|addr: f64, bytes: Vec<u8>| {
                        api::memory::write_byte_array(Np(addr as u64), &bytes);
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryScanSyncJson",
                    Func::from(|addr: f64, size: f64, pattern: String| -> String {
                        let hits: Vec<_> = api::memory::scan_sync(
                            Np(addr as u64),
                            size as usize,
                            &pattern,
                        )
                        .into_iter()
                        .map(|(a, sz)| serde_json::json!({ "address": a, "size": sz }))
                        .collect();
                        serde_json::to_string(&hits).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "moduleLoadJson",
                    Func::from(|path: String| -> String {
                        match api::module::load(&path) {
                            Ok(m) => serde_json::json!({
                                "ok": true,
                                "name": m.name,
                                "base": m.base,
                                "size": m.size,
                                "path": m.path,
                            })
                            .to_string(),
                            Err(e) => serde_json::json!({ "ok": false, "error": e }).to_string(),
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "enumerateExportsJson",
                    Func::from(|name_or_path: String| -> String {
                        let Some(m) = api::module::find_module_by_name(&name_or_path) else {
                            return "[]".into();
                        };
                        let exports: Vec<_> = api::module::enumerate_exports(&m)
                            .into_iter()
                            .map(|e| {
                                serde_json::json!({
                                    "type": e.kind,
                                    "name": e.name,
                                    "address": e.address.0,
                                })
                            })
                            .collect();
                        serde_json::to_string(&exports).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "enumerateImportsJson",
                    Func::from(|name_or_path: String| -> String {
                        let Some(m) = api::module::find_module_by_name(&name_or_path) else {
                            return "[]".into();
                        };
                        let imports: Vec<_> = api::module::enumerate_imports(&m)
                            .into_iter()
                            .map(|e| {
                                serde_json::json!({
                                    "type": e.kind,
                                    "name": e.name,
                                    "address": e.address.map(|p| p.0),
                                    "slot": e.slot.map(|p| p.0),
                                    "module": e.module,
                                })
                            })
                            .collect();
                        serde_json::to_string(&imports).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "attach",
                    Func::from(|addr: f64| -> u32 {
                        let target = addr as u64;
                        let code =
                            unsafe { std::slice::from_raw_parts(target as *const u8, 16) }.to_vec();
                        let id_cell = Arc::new(Mutex::new(0u32));
                        let id_cell2 = id_cell.clone();
                        match attach(
                            target,
                            &code,
                            HookCallbacks {
                                on_enter: Some(Box::new(move |cpu: &mut CpuContext| {
                                    let id = *id_cell2.lock();
                                    dispatch_enter_to_js(id, cpu);
                                })),
                                on_leave: None,
                                save_simd: false,
                            },
                        ) {
                            Ok(h) => {
                                *id_cell.lock() = h.id;
                                h.id
                            }
                            Err(e) => {
                                log::error!("Interceptor.attach failed: {e}");
                                0
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaHook",
                    Func::from(|class_name: String, method: String, sig: Opt<String>| {
                        let sig = sig.0.unwrap_or_else(|| "(I)I".into());
                        log::info!("Java hook requested: {class_name}.{method}{sig}");
                        if let Err(e) =
                            goauld_art_bridge::hook_java_method(&class_name, &method, &sig)
                        {
                            log::error!("hook_java_method failed: {e}");
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaCallOriginal",
                    Func::from(|key: String, x: f64| -> f64 {
                        goauld_art_bridge::js_call_original(&key, x as i32)
                            .unwrap_or(x as i32) as f64
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaAndroidVersion",
                    Func::from(|| -> String {
                        goauld_art_bridge::android_version().unwrap_or_else(|_| "unknown".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaIsMainThread",
                    Func::from(|| -> bool {
                        goauld_art_bridge::is_main_thread().unwrap_or(false)
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaEnumerateClassesJson",
                    Func::from(|| -> String {
                        match goauld_art_bridge::enumerate_loaded_classes() {
                            Ok(v) => serde_json::to_string(&v).unwrap_or_else(|_| "[]".into()),
                            Err(e) => {
                                log::warn!("enumerateLoadedClasses: {e}");
                                "[]".into()
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaEnumerateLoadersJson",
                    Func::from(|| -> String {
                        match goauld_art_bridge::enumerate_class_loaders() {
                            Ok(v) => serde_json::to_string(&v).unwrap_or_else(|_| "[]".into()),
                            Err(e) => {
                                log::warn!("enumerateClassLoaders: {e}");
                                "[]".into()
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaClassMethodsJson",
                    Func::from(|class_name: String| -> String {
                        match goauld_art_bridge::enumerate_class_methods(&class_name) {
                            Ok(v) => {
                                let arr: Vec<_> = v
                                    .into_iter()
                                    .map(|m| {
                                        serde_json::json!({
                                            "name": m.name,
                                            "sig": m.sig,
                                            "isStatic": m.is_static,
                                            "flags": m.flags,
                                        })
                                    })
                                    .collect();
                                serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
                            }
                            Err(e) => {
                                log::warn!("class methods {class_name}: {e}");
                                "[]".into()
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaClassFieldsJson",
                    Func::from(|class_name: String| -> String {
                        match goauld_art_bridge::enumerate_class_fields(&class_name) {
                            Ok(v) => {
                                let arr: Vec<_> = v
                                    .into_iter()
                                    .map(|f| {
                                        serde_json::json!({
                                            "name": f.name,
                                            "type": f.type_name,
                                            "isStatic": f.is_static,
                                            "flags": f.flags,
                                        })
                                    })
                                    .collect();
                                serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
                            }
                            Err(e) => {
                                log::warn!("class fields {class_name}: {e}");
                                "[]".into()
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaReadStaticFieldJson",
                    Func::from(|class_name: String, field_name: String| -> String {
                        match goauld_art_bridge::read_static_field_json(&class_name, &field_name)
                        {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("read static {class_name}.{field_name}: {e}");
                                serde_json::json!({ "error": e.to_string() }).to_string()
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaDumpStorageJson",
                    Func::from(|| -> String {
                        match goauld_art_bridge::dump_app_storage_json() {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("dumpAppStorage: {e}");
                                serde_json::json!({ "error": e.to_string() }).to_string()
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaScheduleMain",
                    Func::from(|token: f64| -> bool {
                        goauld_art_bridge::schedule_on_main(token as u64).is_ok()
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaNextMainToken",
                    Func::from(|| -> f64 { goauld_art_bridge::next_main_token() as f64 }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "traceAndroidApi",
                    Func::from(
                        |filter: Opt<String>, max_events: Opt<f64>| -> f64 {
                            let raw = filter.0.unwrap_or_default();
                            let prefixes: Vec<String> = if raw.trim().is_empty() {
                                goauld_art_bridge::DEFAULT_API_PREFIXES
                                    .iter()
                                    .map(|s| (*s).to_string())
                                    .collect()
                            } else {
                                raw.split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect()
                            };
                            let max_events = max_events.0.map(|n| n as u64).unwrap_or(0);
                            match goauld_art_bridge::start_android_api_trace(
                                goauld_art_bridge::AndroidApiTraceConfig {
                                    prefixes,
                                    max_events,
                                    with_signature: true,
                                },
                            ) {
                                Ok(id) => id as f64,
                                Err(e) => {
                                    log::error!("traceAndroidApi failed: {e}");
                                    0.0
                                }
                            }
                        },
                    ),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "androidToast",
                    Func::from(|message: String| -> bool {
                        match goauld_art_bridge::show_android_toast(&message) {
                            Ok(()) => true,
                            Err(e) => {
                                log::error!("androidToast failed: {e}");
                                false
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            // Wire ART → send / JS invoke once (engine lives on this worker thread).
            {
                use std::sync::Once;
                static WIRE: Once = Once::new();
                WIRE.call_once(|| {
                    goauld_art_bridge::set_send_callback(art_send_cb);
                    goauld_art_bridge::set_js_invoke_callback(art_js_invoke_cb);
                    goauld_art_bridge::set_main_token_callback(art_main_token_cb);
                });
            }

            ctx.globals()
                .set("__goauld", helpers)
                .map_err(|e| e.to_string())?;

            ctx.eval::<(), _>(PRELUDE)
                .map_err(|e| format!("prelude: {e}"))?;
            Ok(())
        })
    }
}

fn art_send_cb(payload: &str) {
    if let Some(eng) = ENGINE_SLOT.lock().clone() {
        let json = serde_json::to_string(payload).unwrap_or_else(|_| format!("\"{payload}\""));
        eng.bridge().emit_send(json, None);
    }
}

/// Called on the ART hook thread — only posts to the JS worker (never enters QJS).
fn art_js_invoke_cb(key: &str, x: i32) -> Option<i32> {
    let (_env, thiz, art) = goauld_art_bridge::current_hook_context()?;
    js_queue::submit_java_invoke(key, x, thiz, art, Duration::from_secs(10))
}

/// Called on the Android main looper — never touches QuickJS directly.
fn art_main_token_cb(token: u64) {
    let src = format!("try{{__goauld_runMain({token});}}catch(e){{try{{send('main-err:'+e);}}catch(_){{}}}}");
    if let Err(e) = js_queue::submit_eval_async(src) {
        log::warn!("main token {token}: {e}");
    }
}

/// Create QuickJS on the worker thread (must be the only thread that touches it).
pub fn boot_worker(bridge: Arc<HostBridge>) {
    match QuickJsEngine::new(bridge) {
        Ok(eng) => {
            set_engine_slot(Arc::new(eng));
            log::info!("QuickJS engine ready on goauld-js-worker");
        }
        Err(e) => log::error!("QuickJS boot failed: {e}"),
    }
}

pub fn worker_eval(script_id: ScriptId, source: &str) -> Result<(), String> {
    let eng = ENGINE_SLOT
        .lock()
        .clone()
        .ok_or_else(|| "QuickJS engine not booted".to_string())?;
    eng.set_current_script(script_id);
    eng.eval(source)
}

pub fn worker_java_invoke(job: JavaInvokeJob) {
    let reply = |value: i32, error: Option<String>| {
        let _ = job.reply.send(JavaInvokeResult { value, error });
    };

    let eng = ENGINE_SLOT.lock().clone();
    let Some(eng) = eng else {
        reply(
            job.arg.saturating_add(1000),
            Some("no QuickJS engine".into()),
        );
        return;
    };

    let run_js = |env_ptr: usize| {
        goauld_art_bridge::set_hook_context(env_ptr, job.thiz, job.art_method);
        let out = eng.context.with(|ctx| -> Result<(bool, i32), String> {
            use rquickjs::CatchResultExt;
            let dispatch = ctx
                .globals()
                .get::<_, Function>("__goauld_java_invoke")
                .map_err(|e| e.to_string())?;
            let v: Value = dispatch
                .call((job.key.as_str(), job.arg as f64))
                .catch(&ctx)
                .map_err(|e| format!("{e}"))?;
            let obj = v
                .as_object()
                .ok_or_else(|| "java invoke returned non-object".to_string())?;
            let did: bool = obj.get("did").unwrap_or(false);
            let ret: f64 = obj.get("ret").unwrap_or(job.arg as f64);
            Ok((did, ret as i32))
        });
        goauld_art_bridge::clear_hook_context();
        out
    };

    #[cfg(target_os = "android")]
    let result = goauld_art_bridge::with_attached_jni(|env| {
        let env_ptr = env.get_raw() as usize;
        match run_js(env_ptr) {
            Ok((true, v)) => Ok(v),
            Ok((false, _)) => Ok(job.arg.saturating_add(1000)),
            Err(e) => Err(goauld_art_bridge::ArtError::Msg(e)),
        }
    });

    #[cfg(not(target_os = "android"))]
    let result: Result<i32, goauld_art_bridge::ArtError> = match run_js(0) {
        Ok((true, v)) => Ok(v),
        Ok((false, _)) => Ok(job.arg.saturating_add(1000)),
        Err(e) => Err(goauld_art_bridge::ArtError::Msg(e)),
    };

    match result {
        Ok(v) => reply(v, None),
        Err(e) => {
            log::error!("worker_java_invoke: {e}");
            reply(job.arg.saturating_add(1000), Some(e.to_string()));
        }
    }
}

/// Deliver host `post` into JS `recv` waiters.
pub fn worker_deliver_post(payload_json: &str, data: Option<&[u8]>) {
    let Some(eng) = ENGINE_SLOT.lock().clone() else {
        log::warn!("deliver_post: no QuickJS engine");
        return;
    };
    let data_json = match data {
        Some(d) => serde_json::to_string(d).unwrap_or_else(|_| "null".into()),
        None => "null".into(),
    };
    let src = format!(
        "(function(){{ try {{ var msg = JSON.parse({pj}); var data = {dj}; return !!__goauld_deliver_post(msg, data); }} catch (e) {{ try {{ send('recv-err:'+e); }} catch (_) {{}} return false; }} }})()",
        pj = serde_json::to_string(payload_json).unwrap_or_else(|_| "\"{}\"".into()),
        dj = data_json,
    );
    if let Err(e) = eng.eval(&src) {
        log::error!("deliver_post eval: {e}");
    }
}

/// Invoke `rpc.exports[fn_name](...JSON.parse(args_json))`.
pub fn worker_rpc_call(fn_name: &str, args_json: &str) -> crate::js_queue::RpcInvokeResult {
    use crate::js_queue::RpcInvokeResult;
    let Some(eng) = ENGINE_SLOT.lock().clone() else {
        return RpcInvokeResult {
            result_json: None,
            error: Some("no QuickJS engine".into()),
        };
    };
    let src = format!(
        "(function(){{ return __goauld_rpc_invoke({fn}, {args}); }})()",
        fn = serde_json::to_string(fn_name).unwrap_or_else(|_| "\"\"".into()),
        args = serde_json::to_string(args_json).unwrap_or_else(|_| "\"[]\"".into()),
    );
    match eng.context.with(|ctx| -> Result<String, String> {
        let v: Value = ctx.eval(src).map_err(|e| e.to_string())?;
        if let Ok(s) = v.get::<String>() {
            Ok(s)
        } else if v.is_null() || v.is_undefined() {
            Ok("null".into())
        } else {
            v.as_string()
                .and_then(|s| s.to_string().ok())
                .ok_or_else(|| "rpc returned non-string".into())
        }
    }) {
        Ok(s) => {
            if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&s) {
                if let Some(err) = wrapper.get("error").and_then(|e| e.as_str()) {
                    return RpcInvokeResult {
                        result_json: None,
                        error: Some(err.to_string()),
                    };
                }
                if wrapper.get("result").is_some() {
                    return RpcInvokeResult {
                        result_json: Some(
                            wrapper
                                .get("result")
                                .map(|r| r.to_string())
                                .unwrap_or_else(|| "null".into()),
                        ),
                        error: None,
                    };
                }
            }
            RpcInvokeResult {
                result_json: Some(s),
                error: None,
            }
        }
        Err(e) => RpcInvokeResult {
            result_json: None,
            error: Some(e),
        },
    }
}

fn dispatch_enter_to_js(hook_id: u32, cpu: &mut CpuContext) {
    let Some(eng) = ENGINE_SLOT.lock().clone() else {
        return;
    };
    let args = [
        cpu.x[0] as f64,
        cpu.x[1] as f64,
        cpu.x[2] as f64,
        cpu.x[3] as f64,
        cpu.x[4] as f64,
        cpu.x[5] as f64,
        cpu.x[6] as f64,
        cpu.x[7] as f64,
    ];
    let _ = eng.context.with(|ctx| {
        let Ok(dispatch) = ctx.globals().get::<_, Function>("__goauld_on_enter") else {
            return;
        };
        // Max IntoArgs arity is typically 8 — pack regs into a JS array.
        let arr = rquickjs::Array::new(ctx.clone()).unwrap();
        for (i, v) in args.iter().enumerate() {
            let _ = arr.set(i, *v);
        }
        let _: Result<Value, _> = dispatch.call((hook_id, arr));
        if let Ok(muts) = ctx.globals().get::<_, Object>("__goauld_mut_x") {
            for i in 0..8u32 {
                if let Ok(v) = muts.get::<_, f64>(i) {
                    cpu.x[i as usize] = v as u64;
                }
            }
        }
    });
}

fn install_ptr_class(ctx: &rquickjs::Ctx<'_>) -> Result<(), String> {
    Class::<JsNativePointer>::define(&ctx.globals()).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Clone, rquickjs::class::Trace, rquickjs::JsLifetime)]
#[rquickjs::class(rename = "NativePointer")]
pub struct JsNativePointer {
    pub addr: u64,
}

#[allow(non_snake_case)]
#[rquickjs::methods]
impl JsNativePointer {
    #[qjs(constructor)]
    pub fn new(addr: f64) -> Self {
        Self { addr: addr as u64 }
    }

    #[qjs(get)]
    pub fn address(&self) -> f64 {
        self.addr as f64
    }

    pub fn add(&self, n: f64) -> Self {
        Self {
            addr: (self.addr as i64).wrapping_add(n as i64) as u64,
        }
    }

    pub fn sub(&self, n: f64) -> Self {
        Self {
            addr: (self.addr as i64).wrapping_sub(n as i64) as u64,
        }
    }

    pub fn readU32(&self) -> u32 {
        api::memory::read_u32(Np(self.addr))
    }

    pub fn readU64(&self) -> f64 {
        api::memory::read_u64(Np(self.addr)) as f64
    }

    pub fn readU8(&self) -> u8 {
        api::memory::read_u8(Np(self.addr))
    }

    pub fn readU16(&self) -> u16 {
        api::memory::read_u16(Np(self.addr))
    }

    pub fn readPointer(&self) -> Self {
        let p = api::memory::read_pointer(Np(self.addr));
        Self { addr: p.0 }
    }

    pub fn readUtf8String(&self) -> String {
        api::memory::read_utf8_string(Np(self.addr), None)
    }

    pub fn readCString(&self) -> String {
        api::memory::read_c_string(Np(self.addr))
    }

    pub fn writeU8(&self, v: f64) {
        api::memory::write_u8(Np(self.addr), v as u8);
    }

    pub fn writeU16(&self, v: f64) {
        api::memory::write_u16(Np(self.addr), v as u16);
    }

    pub fn writeU32(&self, v: f64) {
        api::memory::write_u32(Np(self.addr), v as u32);
    }

    pub fn writeU64(&self, v: f64) {
        api::memory::write_u64(Np(self.addr), v as u64);
    }

    pub fn writePointer(&self, p: f64) {
        api::memory::write_pointer(Np(self.addr), Np(p as u64));
    }

    #[qjs(rename = "toString")]
    pub fn js_to_string(&self) -> String {
        format!("0x{:x}", self.addr)
    }
}

const PRELUDE: &str = r#"
(function() {
  var _send = send;
  send = function(payload, data) {
    var json = (typeof payload === 'string')
      ? JSON.stringify(payload)
      : JSON.stringify(payload);
    if (data == null || data === undefined) {
      __goauld.sendJson(json);
      return;
    }
    var bytes = [];
    if (typeof data.length === 'number') {
      for (var i = 0; i < data.length; i++) bytes.push(data[i] & 0xff);
    }
    __goauld.sendJsonData(json, bytes);
  };
})();

function ptr(v) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'object' && typeof v.address === 'number') return v;
  return new NativePointer(v);
}

var __recvWaiters = [];
function recv(typeOrCb, maybeCb) {
  var typ = null;
  var cb = typeOrCb;
  if (typeof typeOrCb === 'string') {
    typ = typeOrCb;
    cb = maybeCb;
  }
  if (typeof cb !== 'function') throw new Error('recv requires a callback');
  __recvWaiters.push({ type: typ, cb: cb });
  return { wait: function() {} };
}
function __goauld_deliver_post(msg, data) {
  for (var i = 0; i < __recvWaiters.length; i++) {
    var w = __recvWaiters[i];
    if (w.type == null || (msg && msg.type === w.type)) {
      __recvWaiters.splice(i, 1);
      try { w.cb(msg, data); } catch (e) { try { send('recv-cb-err:' + e); } catch (_) {} }
      return true;
    }
  }
  return false;
}
function __goauld_rpc_invoke(fnName, argsJsonStr) {
  try {
    var f = (rpc && rpc.exports) ? rpc.exports[fnName] : null;
    if (typeof f !== 'function') {
      return JSON.stringify({ error: 'missing rpc export: ' + fnName });
    }
    var args = JSON.parse(argsJsonStr);
    if (!Array.isArray(args)) args = [args];
    var ret = f.apply(null, args);
    return JSON.stringify({ result: (ret === undefined) ? null : ret });
  } catch (e) {
    return JSON.stringify({ error: String(e) });
  }
}

var rpc = { exports: {} };

function __goauld_wrap_module(m) {
  if (!m) return null;
  return {
    name: m.name,
    base: ptr(m.base),
    size: m.size,
    path: m.path,
    findExportByName: function(name) {
      return Module.findExportByName(this.name, name);
    },
    getExportByName: function(name) {
      var a = this.findExportByName(name);
      if (a === null) throw new Error('export not found: ' + name);
      return a;
    },
    enumerateExports: function() {
      return JSON.parse(__goauld.enumerateExportsJson(this.path || this.name)).map(function(e) {
        return { type: e.type, name: e.name, address: ptr(e.address) };
      });
    },
    enumerateImports: function() {
      return JSON.parse(__goauld.enumerateImportsJson(this.path || this.name)).map(function(e) {
        return {
          type: e.type,
          name: e.name,
          address: e.address != null ? ptr(e.address) : undefined,
          slot: e.slot != null ? ptr(e.slot) : undefined,
          module: e.module || undefined
        };
      });
    },
    enumerateSymbols: function() { return this.enumerateExports(); },
    enumerateRanges: function(protection) {
      var all = Process.enumerateRanges(protection || 'r--');
      var path = this.path;
      var base = this.base.address;
      var end = base + this.size;
      return all.filter(function(r) {
        if (r.file && r.file.path === path) return true;
        var b = r.base.address;
        return b >= base && b < end;
      });
    },
    ensureInitialized: function() {}
  };
}

function __goauld_wrap_range(r) {
  if (!r) return null;
  var o = {
    base: ptr(r.base),
    size: r.size,
    protection: r.protection
  };
  if (r.file) o.file = r.file;
  return o;
}

var Process = (function() {
  var info = JSON.parse(__goauld.processInfoJson());
  return {
    id: info.id,
    arch: info.arch,
    platform: info.platform,
    pageSize: info.pageSize,
    pointerSize: info.pointerSize,
    codeSigningPolicy: info.codeSigningPolicy,
    get mainModule() {
      var mods = Process.enumerateModules();
      return mods.length ? mods[0] : null;
    },
    getCurrentDir: function() { return JSON.parse(__goauld.processInfoJson()).cwd; },
    getHomeDir: function() { return JSON.parse(__goauld.processInfoJson()).home; },
    getTmpDir: function() { return JSON.parse(__goauld.processInfoJson()).tmp; },
    isDebuggerAttached: function() { return JSON.parse(__goauld.processInfoJson()).debugger; },
    getCurrentThreadId: function() { return JSON.parse(__goauld.processInfoJson()).tid; },
    enumerateThreads: function() {
      return JSON.parse(__goauld.enumerateThreadsJson()).map(function(t) {
        return { id: t.id, name: t.name, state: t.state };
      });
    },
    enumerateModules: function() {
      return JSON.parse(__goauld.enumerateModulesJson()).map(__goauld_wrap_module);
    },
    findModuleByName: function(name) {
      var j = __goauld.findModuleByNameJson(String(name));
      return j ? __goauld_wrap_module(JSON.parse(j)) : null;
    },
    getModuleByName: function(name) {
      var m = Process.findModuleByName(name);
      if (!m) throw new Error('module not found: ' + name);
      return m;
    },
    findModuleByAddress: function(address) {
      var a = (typeof address === 'object') ? address.address : address;
      var j = __goauld.findModuleByAddressJson(+a);
      return j ? __goauld_wrap_module(JSON.parse(j)) : null;
    },
    getModuleByAddress: function(address) {
      var m = Process.findModuleByAddress(address);
      if (!m) throw new Error('module not found for address');
      return m;
    },
    enumerateRanges: function(protectionOrSpec) {
      var prot = 'r--';
      var coalesce = false;
      if (typeof protectionOrSpec === 'string') prot = protectionOrSpec;
      else if (protectionOrSpec && typeof protectionOrSpec === 'object') {
        prot = protectionOrSpec.protection || 'r--';
        coalesce = !!protectionOrSpec.coalesce;
      }
      return JSON.parse(__goauld.enumerateRangesJson(prot, coalesce)).map(__goauld_wrap_range);
    },
    findRangeByAddress: function(address) {
      var a = (typeof address === 'object') ? address.address : address;
      var j = __goauld.findRangeByAddressJson(+a);
      return j ? __goauld_wrap_range(JSON.parse(j)) : null;
    },
    getRangeByAddress: function(address) {
      var r = Process.findRangeByAddress(address);
      if (!r) throw new Error('range not found');
      return r;
    }
  };
})();

var Module = {
  findExportByName: function(mod, name) {
    var a = __goauld.findExport(mod == null ? undefined : String(mod), name);
    return (a === null || a === undefined) ? null : ptr(a);
  },
  getExportByName: function(mod, name) {
    var a = Module.findExportByName(mod, name);
    if (a === null) throw new Error('export not found: ' + name);
    return a;
  },
  findBaseAddress: function(name) {
    var a = __goauld.findBase(String(name));
    return (a === null || a === undefined) ? null : ptr(a);
  },
  findGlobalExportByName: function(name) {
    return Module.findExportByName(null, name);
  },
  getGlobalExportByName: function(name) {
    return Module.getExportByName(null, name);
  },
  load: function(path) {
    var j = JSON.parse(__goauld.moduleLoadJson(String(path)));
    if (!j.ok) throw new Error(j.error || 'Module.load failed');
    return __goauld_wrap_module(j);
  }
};

function ModuleMap(filter) {
  this._filter = typeof filter === 'function' ? filter : null;
  this._mods = [];
  this.update();
}
ModuleMap.prototype.update = function() {
  var all = Process.enumerateModules();
  var f = this._filter;
  this._mods = f ? all.filter(f) : all.slice();
};
ModuleMap.prototype.values = function() { return this._mods.slice(); };
ModuleMap.prototype.has = function(address) { return !!this.find(address); };
ModuleMap.prototype.find = function(address) {
  var a = (typeof address === 'object') ? address.address : +address;
  for (var i = 0; i < this._mods.length; i++) {
    var m = this._mods[i];
    var b = m.base.address;
    if (a >= b && a < b + m.size) return m;
  }
  return null;
};
ModuleMap.prototype.get = function(address) {
  var m = this.find(address);
  if (!m) throw new Error('address not in ModuleMap');
  return m;
};
ModuleMap.prototype.findName = function(address) {
  var m = this.find(address);
  return m ? m.name : null;
};
ModuleMap.prototype.getName = function(address) {
  return this.get(address).name;
};
ModuleMap.prototype.findPath = function(address) {
  var m = this.find(address);
  return m ? m.path : null;
};
ModuleMap.prototype.getPath = function(address) {
  return this.get(address).path;
};

var Memory = {
  readUtf8String: function(p) { return ptr(p).readUtf8String(); },
  readByteArray: function(p, len) {
    var a = (typeof p === 'object') ? p.address : p;
    var out = [];
    for (var i = 0; i < len; i++) out.push(ptr(a).add(i).readU8());
    return out;
  },
  readU8: function(p) { return ptr(p).readU8(); },
  readU16: function(p) { return ptr(p).readU16(); },
  readU32: function(p) { return ptr(p).readU32(); },
  readU64: function(p) { return ptr(p).readU64(); },
  readPointer: function(p) { return ptr(p).readPointer(); },
  writeU8: function(p, v) { ptr(p).writeU8(v); },
  writeU16: function(p, v) { ptr(p).writeU16(v); },
  writeU32: function(p, v) { ptr(p).writeU32(v); },
  writeU64: function(p, v) { ptr(p).writeU64(v); },
  writePointer: function(p, v) {
    var a = (typeof v === 'object') ? v.address : v;
    ptr(p).writePointer(a);
  },
  writeByteArray: function(p, bytes) {
    var a = (typeof p === 'object') ? p.address : p;
    var arr = [];
    if (typeof bytes.length === 'number') {
      for (var i = 0; i < bytes.length; i++) arr.push(bytes[i] & 0xff);
    }
    __goauld.memoryWriteBytes(+a, arr);
  },
  alloc: function(size) { return ptr(__goauld.memoryAlloc(+size)); },
  allocUtf8String: function(s) {
    s = String(s);
    var bytes = [];
    for (var i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i) & 0xff);
    bytes.push(0);
    var p = Memory.alloc(bytes.length);
    Memory.writeByteArray(p, bytes);
    return p;
  },
  copy: function(dst, src, n) {
    var d = (typeof dst === 'object') ? dst.address : dst;
    var s = (typeof src === 'object') ? src.address : src;
    __goauld.memoryCopy(+d, +s, +n);
  },
  dup: function(address, size) {
    var a = (typeof address === 'object') ? address.address : address;
    return ptr(__goauld.memoryDup(+a, +size));
  },
  protect: function(address, size, protection) {
    var a = (typeof address === 'object') ? address.address : address;
    return !!__goauld.memoryProtect(+a, +size, String(protection));
  },
  queryProtection: function(address) {
    var a = (typeof address === 'object') ? address.address : address;
    return __goauld.memoryQueryProtection(+a);
  },
  scanSync: function(address, size, pattern) {
    var a = (typeof address === 'object') ? address.address : address;
    return JSON.parse(__goauld.memoryScanSyncJson(+a, +size, String(pattern))).map(function(h) {
      return { address: ptr(h.address), size: h.size };
    });
  },
  scan: function(address, size, pattern, callbacks) {
    var hits = Memory.scanSync(address, size, pattern);
    for (var i = 0; i < hits.length; i++) {
      if (callbacks && callbacks.onMatch) {
        var r = callbacks.onMatch(hits[i].address, hits[i].size);
        if (r === 'stop') break;
      }
    }
    if (callbacks && callbacks.onComplete) callbacks.onComplete();
  },
  patchCode: function(address, size, apply) {
    var a = (typeof address === 'object') ? address.address : address;
    // Default rw- (not r-x): a failed query must not leave the page non-writable
    // after we temporarily elevate permissions — that SEGV's the JS heap.
    var prev = Memory.queryProtection(a) || 'rw-';
    var elevated = Memory.protect(a, size, 'rwx') || Memory.protect(a, size, 'rw-');
    if (!elevated) {
      throw new Error('Memory.patchCode: protect failed');
    }
    try {
      apply(ptr(a));
    } finally {
      // Prefer restoring prior prot; fall back to writable if restore fails.
      if (!Memory.protect(a, size, prev)) {
        Memory.protect(a, size, 'rw-');
      }
    }
  }
};

var Backtracer = { ACCURATE: 'accurate', FUZZY: 'fuzzy' };
var Thread = {
  sleep: function(delay) { __goauld.threadSleep(+delay); },
  backtrace: function(context, backtracer) {
    // context (Interceptor CPU state) not wired yet — walk current JS worker thread.
    var accurate = true;
    if (backtracer === Backtracer.FUZZY || backtracer === 'fuzzy') accurate = false;
    if (typeof context === 'string' && (context === 'fuzzy' || context === Backtracer.FUZZY)) {
      accurate = false;
    }
    return JSON.parse(__goauld.threadBacktraceJson(accurate, 16)).map(function(a) {
      return ptr(a);
    });
  }
};

var __hookCallbacks = {};
function __goauld_on_enter(hookId, regs) {
  var cb = __hookCallbacks[hookId];
  if (!cb || !cb.onEnter) return;
  var args = [];
  for (var i = 0; i < 8; i++) args.push(ptr(regs[i]));
  var invocation = {
    context: {
      x0: regs[0], x1: regs[1], x2: regs[2], x3: regs[3],
      x4: regs[4], x5: regs[5], x6: regs[6], x7: regs[7]
    }
  };
  cb.onEnter.call(invocation, args);
  var mut = {};
  mut[0]=invocation.context.x0; mut[1]=invocation.context.x1;
  mut[2]=invocation.context.x2; mut[3]=invocation.context.x3;
  mut[4]=invocation.context.x4; mut[5]=invocation.context.x5;
  mut[6]=invocation.context.x6; mut[7]=invocation.context.x7;
  globalThis.__goauld_mut_x = mut;
}

var Interceptor = {
  attach: function(target, callbacks) {
    var addr = (typeof target === 'object') ? target.address : target;
    var id = __goauld.attach(+addr);
    if (id) __hookCallbacks[id] = callbacks || {};
    return { detach: function() {} };
  },
  detachAll: function() { __hookCallbacks = {}; },
  replace: function() {},
  revert: function() {}
};

var __javaImpls = {};
var __javaMainFns = {};
function __goauld_runMain(token) {
  var fn = __javaMainFns[token];
  delete __javaMainFns[token];
  if (typeof fn === 'function') fn();
}
function __goauld_javaTypeToSig(t) {
  if (t === 'void') return 'V';
  if (t === 'boolean') return 'Z';
  if (t === 'byte') return 'B';
  if (t === 'char') return 'C';
  if (t === 'short') return 'S';
  if (t === 'int') return 'I';
  if (t === 'long') return 'J';
  if (t === 'float') return 'F';
  if (t === 'double') return 'D';
  if (typeof t === 'string' && t.length === 1) return t;
  if (typeof t === 'string' && t.indexOf('.') >= 0) return 'L' + t.replace(/\\./g, '/') + ';';
  if (typeof t === 'string' && t.charAt(0) === '[') return t.replace(/\\./g, '/');
  return 'Ljava/lang/Object;';
}
function __goauld_buildSig(ret, args) {
  var s = '(';
  for (var i = 0; i < args.length; i++) s += __goauld_javaTypeToSig(args[i]);
  s += ')';
  s += __goauld_javaTypeToSig(ret || 'void');
  return s;
}
function __goauld_wrapJavaClass(className) {
  if (className === 'android.app.ActivityThread') {
    return {
      className: className,
      currentApplication: function() {
        return { getApplicationContext: function() { return { __goauldCtx: true }; } };
      }
    };
  }
  if (className === 'android.widget.Toast') {
    return {
      className: className,
      LENGTH_SHORT: { value: 0 },
      LENGTH_LONG: { value: 1 },
      makeText: function(_ctx, text, _duration) {
        var msg = (text && typeof text === 'object' && text.__goauldStr) ? text.__goauldStr : String(text);
        return {
          show: function() {
            if (!__goauld.androidToast(msg)) throw new Error('androidToast failed');
          }
        };
      }
    };
  }
  if (className === 'java.lang.String') {
    return {
      className: className,
      $new: function(s) { return { __goauldStr: String(s), $className: className }; }
    };
  }
  var methods = [];
  try { methods = JSON.parse(__goauld.javaClassMethodsJson(className)); } catch (_) {}
  var byName = {};
  for (var i = 0; i < methods.length; i++) {
    var m = methods[i];
    if (!byName[m.name]) byName[m.name] = [];
    byName[m.name].push(m);
  }
  return new Proxy({ className: className, $className: className }, {
    get: function(target, prop) {
      if (prop in target) return target[prop];
      if (prop === '$new') {
        return function() {
          throw new Error('Java.use(\"' + className + '\").$new is not fully implemented yet');
        };
      }
      if (prop === '$dispose') return function() {};
      var name = String(prop);
      var overloads = byName[name] || [];
      var def = overloads[0] || { name: name, sig: '(I)I', isStatic: false, flags: 0 };
      var method = {
        _key: className + '.' + name,
        _sig: def.sig,
        _overloads: overloads,
        overload: function() {
          var args = Array.prototype.slice.call(arguments);
          var want;
          if (args.length === 1 && typeof args[0] === 'string' && args[0].charAt(0) === '(') {
            want = args[0];
          } else {
            want = __goauld_buildSig('int', args.length ? args : ['int']);
            for (var oj = 0; oj < overloads.length; oj++) {
              if (overloads[oj].sig.indexOf('(') === 0) {
                var pcount = 0;
                var body = overloads[oj].sig.slice(1, overloads[oj].sig.indexOf(')'));
                for (var k = 0; k < body.length; k++) {
                  var ch = body.charAt(k);
                  if (ch === 'L') { pcount++; while (k < body.length && body.charAt(k) !== ';') k++; }
                  else if (ch === '[') { /* next primitive/object counts */ }
                  else if ('ZBCSIJFD'.indexOf(ch) >= 0) pcount++;
                }
                if (pcount === args.length) { want = overloads[oj].sig; break; }
              }
            }
            if (args.length === 1 && args[0] === 'int') want = '(I)I';
            if (args.length === 0 && overloads[0]) want = overloads[0].sig;
          }
          method._sig = want;
          return method;
        }
      };
      Object.defineProperty(method, 'implementation', {
        get: function() { return __javaImpls[method._key]; },
        set: function(fn) {
          __javaImpls[method._key] = fn;
          __goauld.javaHook(className, name, method._sig);
        }
      });
      Object.defineProperty(method, 'overloads', {
        get: function() {
          return (overloads.length ? overloads : [def]).map(function(o) {
            var mm = {
              _key: className + '.' + name,
              _sig: o.sig,
              overload: method.overload
            };
            Object.defineProperty(mm, 'implementation', {
              get: function() { return __javaImpls[mm._key]; },
              set: function(fn) {
                __javaImpls[mm._key] = fn;
                __goauld.javaHook(className, name, mm._sig);
              }
            });
            return mm;
          });
        }
      });
      return method;
    }
  });
}

var Java = {
  available: !!(Module.findBaseAddress('libart.so') || Module.findBaseAddress('libart.so.0')),
  get androidVersion() {
    try { return __goauld.javaAndroidVersion(); } catch (_) { return 'unknown'; }
  },
  ACC_PUBLIC: 0x0001,
  ACC_PRIVATE: 0x0002,
  ACC_PROTECTED: 0x0004,
  ACC_STATIC: 0x0008,
  ACC_FINAL: 0x0010,
  ACC_SYNCHRONIZED: 0x0020,
  ACC_BRIDGE: 0x0040,
  ACC_VARARGS: 0x0080,
  ACC_NATIVE: 0x0100,
  ACC_ABSTRACT: 0x0400,
  ACC_STRICT: 0x0800,
  ACC_SYNTHETIC: 0x1000,
  perform: function(fn) { return fn(); },
  performNow: function(fn) { return fn(); },
  scheduleOnMainThread: function(fn) {
    var token = __goauld.javaNextMainToken();
    __javaMainFns[token] = fn;
    if (!__goauld.javaScheduleMain(token)) {
      delete __javaMainFns[token];
      return fn();
    }
  },
  isMainThread: function() {
    try { return !!__goauld.javaIsMainThread(); } catch (_) { return false; }
  },
  use: function(className) { return __goauld_wrapJavaClass(String(className)); },
  choose: function(_c, cbs) { if (cbs && cbs.onComplete) cbs.onComplete(); },
  retain: function(obj) { return obj; },
  cast: function(handle, _klass) {
    if (handle && typeof handle === 'object') {
      handle.$className = handle.$className || (_klass && _klass.className) || 'java.lang.Object';
    }
    return handle;
  },
  array: function(type, elements) {
    var a = Array.prototype.slice.call(elements || []);
    a.$type = type;
    return a;
  },
  enumerateLoadedClasses: function(cbs) {
    var names = [];
    try { names = JSON.parse(__goauld.javaEnumerateClassesJson()); } catch (_) {}
    for (var i = 0; i < names.length; i++) {
      if (cbs && cbs.onMatch) cbs.onMatch(names[i], null);
    }
    if (cbs && cbs.onComplete) cbs.onComplete();
  },
  enumerateLoadedClassesSync: function() {
    try { return JSON.parse(__goauld.javaEnumerateClassesJson()); } catch (_) { return []; }
  },
  enumerateClassLoaders: function(cbs) {
    var loaders = [];
    try { loaders = JSON.parse(__goauld.javaEnumerateLoadersJson()); } catch (_) {}
    for (var i = 0; i < loaders.length; i++) {
      if (cbs && cbs.onMatch) cbs.onMatch({ $className: loaders[i], toString: function(){ return this.$className; } });
    }
    if (cbs && cbs.onComplete) cbs.onComplete();
  },
  enumerateClassLoadersSync: function() {
    var loaders = [];
    try { loaders = JSON.parse(__goauld.javaEnumerateLoadersJson()); } catch (_) {}
    return loaders.map(function(s){ return { $className: s }; });
  },
  enumerateMethods: function(query) {
    query = String(query || '*!*');
    var insensitive = query.indexOf('/i') >= 0;
    var withSig = query.indexOf('/s') >= 0;
    var userOnly = query.indexOf('/u') >= 0;
    var q = query.split('/')[0];
    var parts = q.split('!');
    var classPat = parts[0] || '*';
    var methodPat = parts[1] || '*';
    function globRe(g) {
      var s = String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\\*/g, '.*').replace(/\\?/g, '.');
      return new RegExp('^' + s + '$', insensitive ? 'i' : '');
    }
    var cre = globRe(classPat);
    var mre = globRe(methodPat);
    var classes = Java.enumerateLoadedClassesSync();
    var grouped = { loader: '<default>', classes: [] };
    for (var i = 0; i < classes.length; i++) {
      var cn = classes[i];
      if (userOnly && (cn.indexOf('android.') === 0 || cn.indexOf('java.') === 0 || cn.indexOf('dalvik.') === 0)) continue;
      if (!cre.test(cn)) continue;
      var meths = [];
      try {
        var ms = JSON.parse(__goauld.javaClassMethodsJson(cn));
        for (var j = 0; j < ms.length; j++) {
          if (!mre.test(ms[j].name)) continue;
          meths.push(withSig ? (ms[j].name + ms[j].sig) : ms[j].name);
        }
      } catch (_) {}
      if (meths.length) grouped.classes.push({ name: cn, methods: meths });
    }
    return grouped.classes.length ? [grouped] : [];
  },
  /** Declared fields for a class (name/type/isStatic). */
  enumerateFieldsSync: function(className) {
    try { return JSON.parse(__goauld.javaClassFieldsJson(String(className))); } catch (_) { return []; }
  },
  /** Read a static field value (JSON-decoded primitive / string / {class,toString}). */
  readStaticField: function(className, fieldName) {
    try {
      return JSON.parse(__goauld.javaReadStaticFieldJson(String(className), String(fieldName)));
    } catch (e) {
      return { error: String(e) };
    }
  },
  /** SharedPreferences + dataDir listing + small files under files/. */
  dumpAppStorageSync: function() {
    try { return JSON.parse(__goauld.javaDumpStorageJson()); } catch (_) { return {}; }
  },
  backtrace: function(_opts) {
    return Thread.backtrace(null, Backtracer.FUZZY).map(function(p) {
      return { native: true, address: p, methodName: null, className: null, fileName: null, lineNumber: null, methodFlags: 0 };
    });
  },
  openClassFile: function(path) {
    return {
      load: function() { throw new Error('Java.openClassFile.load not yet implemented: ' + path); },
      getClassNames: function() { return []; }
    };
  },
  registerClass: function(_spec) {
    throw new Error('Java.registerClass not yet implemented');
  },
  deoptimizeEverything: function() {},
  deoptimizeBootImage: function() {},
  vm: {
    perform: function(fn) { return fn(); },
    getEnv: function() { return null; }
  },
  classFactory: {
    loader: null,
    cacheDir: '/data/local/tmp',
    use: function(n) { return Java.use(n); },
    choose: function(c, cbs) { return Java.choose(c, cbs); },
    cast: function(h, k) { return Java.cast(h, k); },
    array: function(t, e) { return Java.array(t, e); },
    retain: function(o) { return Java.retain(o); },
    registerClass: function(s) { return Java.registerClass(s); },
    openClassFile: function(p) { return Java.openClassFile(p); }
  },
  ClassFactory: {
    get: function(_loader) { return Java.classFactory; }
  }
};

function __goauld_java_invoke(key, x) {
  if (globalThis.__goauldJavaInvoking) return { did: false };
  globalThis.__goauldJavaInvoking = true;
  try {
    var fn = __javaImpls[key];
    if (!fn) return { did: false };
    var methodName = key.split('.').pop();
    var self = {};
    self[methodName] = function (v) {
      if (typeof globalThis.__goauldCallOriginalOverride === 'function') {
        return globalThis.__goauldCallOriginalOverride(key, +v);
      }
      return __goauld.javaCallOriginal(key, +v);
    };
    var ret = fn.call(self, x);
    return { did: true, ret: +ret };
  } catch (e) {
    send('java-invoke-err:' + e);
    return { did: false };
  } finally {
    globalThis.__goauldJavaInvoking = false;
  }
}


var console = {
  log: function() {
    try { send({type:'log', args: Array.prototype.slice.call(arguments)}); } catch (e) {}
  }
};
"#;
