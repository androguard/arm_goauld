//! QuickJS runtime + Frida-shaped globals (`send`, `Module`, `Interceptor`, `Java`, …).

#![cfg(feature = "quickjs")]

use crate::api::{self, NativePointer as Np};
use crate::engine::ScriptId;
use crate::js_lock::JsLock;
use crate::js_queue::{self, JavaInvokeJob, JavaInvokeResult};
use goauld_native_hook::patch::{attach, detach, detach_all, flush, replace_ptr};
use goauld_native_hook::trampoline::{CpuContext, HookCallbacks};
use parking_lot::Mutex;
use rquickjs::prelude::{Func, Opt};
use rquickjs::{Class, Context, Ctx, Function, Object, Runtime, Value};
use std::cell::Cell;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

pub use crate::bridge::{shared_bridge, HostBridge};

static ENGINE_SLOT: Mutex<Option<Arc<QuickJsEngine>>> = Mutex::new(None);
static JS_LOCK_SLOT: Mutex<Option<Arc<JsLock>>> = Mutex::new(None);
// Active QuickJS context while inside `Context::with` on the JS worker.
// Nested Interceptor callbacks must not re-enter JS (rquickjs Runtime lock /
// Ctx::from_raw is unsafe mid-call) — skip until the outer with() returns.
thread_local! {
    static RAW_CTX: Cell<Option<NonNull<rquickjs::qjs::JSContext>>> = const { Cell::new(None) };
    // Prevent recursive Interceptor JS while a callback is already running
    // (e.g. hooked strlen used by send/JSON inside onEnter).
    static IN_INTERCEPTOR_JS: Cell<bool> = const { Cell::new(false) };
}

struct RawCtxGuard {
    prev: Option<NonNull<rquickjs::qjs::JSContext>>,
}
impl RawCtxGuard {
    fn push(ctx: &Ctx<'_>) -> Self {
        let prev = RAW_CTX.with(|c| c.replace(Some(ctx.as_raw())));
        Self { prev }
    }
}
impl Drop for RawCtxGuard {
    fn drop(&mut self) {
        RAW_CTX.with(|c| c.set(self.prev));
    }
}

fn qjs_in_context() -> bool {
    RAW_CTX.with(|c| c.get().is_some())
}

/// Run `f` with a fresh `Ctx`. Returns `None` if already inside `Context::with`
/// (nested Interceptor during eval / native Func — skip JS safely).
fn with_active_ctx<R>(eng: &QuickJsEngine, f: impl FnOnce(Ctx<'_>) -> R) -> Option<R> {
    if qjs_in_context() {
        return None;
    }
    Some(eng.context.with(|ctx| {
        let _guard = RawCtxGuard::push(&ctx);
        f(ctx)
    }))
}

pub fn set_engine_slot(eng: Arc<QuickJsEngine>) {
    *ENGINE_SLOT.lock() = Some(eng);
}

pub fn set_js_lock(lock: Arc<JsLock>) {
    *JS_LOCK_SLOT.lock() = Some(lock);
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
        // Frida's QuickJS agent tends to win on bursty alloc/string workloads when GC
        // kicks in mid-loop. Raise the threshold so short scripts aren't taxed by
        // cyclic GC; memory_limit 0 = unlimited (QuickJS still refcounts).
        runtime.set_memory_limit(0);
        runtime.set_gc_threshold(64 * 1024 * 1024);
        runtime.set_max_stack_size(1024 * 1024);
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
            let _guard = RawCtxGuard::push(&ctx);
            use rquickjs::CatchResultExt;
            ctx.eval::<(), _>(source)
                .catch(&ctx)
                .map_err(|e| format!("{e}"))
        })
    }

    fn install_globals(&self) -> Result<(), String> {
        let bridge = self.bridge.clone();
        self.context.with(|ctx| -> Result<(), String> {
            let _guard = RawCtxGuard::push(&ctx);
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
                            .map(|p| p.0 & 0x00FF_FFFF_FFFF_FFFF)
                            .collect();
                        serde_json::to_string(&frames).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "startThreadObserver",
                    Func::from(|| {
                        api::thread::start_thread_observer(|json| {
                            let src = format!(
                                "try{{__goauld_threadObserverEvent({json});}}catch(e){{try{{send('thread-obs-err:'+e);}}catch(_){{}}}}"
                            );
                            let _ = js_queue::submit_eval_async(src);
                        });
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "stopThreadObserver",
                    Func::from(|| {
                        api::thread::stop_thread_observer();
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "setExceptionHandler",
                    Func::from(|on: bool| {
                        api::thread::set_exception_handler_enabled(on);
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "exceptionProbeJson",
                    Func::from(|| -> Option<String> {
                        api::thread::exception_probe_details().map(|d| {
                            serde_json::json!({
                                "type": d.type_name,
                                "address": d.address,
                                "memory": {
                                    "operation": d.memory_operation,
                                    "address": d.memory_address,
                                }
                            })
                            .to_string()
                        })
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "scheduleOnThread",
                    Func::from(|_tid: f64, token: f64| {
                        let token = token as u64;
                        std::thread::spawn(move || {
                            // Brief yield so the calling script can finish its turn.
                            std::thread::sleep(std::time::Duration::from_millis(20));
                            let src = format!(
                                "try{{__goauld_dispatchRunOnThread({token});}}catch(e){{try{{send('runOnThread-err:'+e);}}catch(_){{}}}}"
                            );
                            let _ = js_queue::submit_eval_async(src);
                        });
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "spawnSleepThread",
                    Func::from(|name: String, ms: f64| {
                        let ms = ms.max(1.0) as u64;
                        let _ = std::thread::Builder::new()
                            .name(name.chars().take(15).collect::<String>())
                            .spawn(move || {
                                std::thread::sleep(std::time::Duration::from_millis(ms));
                            });
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryAlloc",
                    Func::from(|size: f64| -> f64 {
                        (api::memory::alloc(size as usize).0 & 0x00FF_FFFF_FFFF_FFFF) as f64
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "memoryAllocAnon",
                    Func::from(|size: f64| -> f64 {
                        (api::memory::alloc_anonymous(size as usize).0 & 0x00FF_FFFF_FFFF_FFFF) as f64
                    }),
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
                    "enumerateSymbolsJson",
                    Func::from(|name_or_path: String| -> String {
                        let Some(m) = api::module::find_module_by_name(&name_or_path) else {
                            return "[]".into();
                        };
                        let symbols: Vec<_> = api::module::enumerate_symbols(&m)
                            .into_iter()
                            .map(|e| {
                                serde_json::json!({
                                    "type": e.kind,
                                    "name": e.name,
                                    "address": e.address.0,
                                    "size": e.size,
                                    "isGlobal": e.is_global,
                                    "isWeak": e.is_weak,
                                })
                            })
                            .collect();
                        serde_json::to_string(&symbols).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "enumerateSectionsJson",
                    Func::from(|name_or_path: String| -> String {
                        let Some(m) = api::module::find_module_by_name(&name_or_path) else {
                            return "[]".into();
                        };
                        let sections: Vec<_> = api::module::enumerate_sections(&m)
                            .into_iter()
                            .map(|e| {
                                serde_json::json!({
                                    "id": e.id,
                                    "name": e.name,
                                    "address": e.address.0,
                                    "size": e.size,
                                })
                            })
                            .collect();
                        serde_json::to_string(&sections).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "enumerateDependenciesJson",
                    Func::from(|name_or_path: String| -> String {
                        let Some(m) = api::module::find_module_by_name(&name_or_path) else {
                            return "[]".into();
                        };
                        let deps = api::module::enumerate_dependencies(&m);
                        serde_json::to_string(&deps).unwrap_or_else(|_| "[]".into())
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "attach",
                    Func::from(|addr: f64, want_leave: Opt<bool>, replace_mode: Opt<bool>| -> u32 {
                        let target = addr as u64;
                        let want_leave = want_leave.0.unwrap_or(false);
                        let replace_mode = replace_mode.0.unwrap_or(false);
                        let code =
                            unsafe { std::slice::from_raw_parts(target as *const u8, 16) }.to_vec();
                        let id_cell = Arc::new(Mutex::new(0u32));
                        let id_enter = id_cell.clone();
                        let id_leave = id_cell.clone();
                        let on_leave = if want_leave || replace_mode {
                            Some(Box::new(move |cpu: &mut CpuContext, retval: u64| {
                                let id = *id_leave.lock();
                                dispatch_leave_to_js(id, cpu, retval);
                            }) as _)
                        } else {
                            None
                        };
                        match attach(
                            target,
                            &code,
                            HookCallbacks {
                                on_enter: Some(Box::new(move |cpu: &mut CpuContext| {
                                    let id = *id_enter.lock();
                                    dispatch_enter_to_js(id, cpu);
                                })),
                                on_leave,
                                save_simd: false,
                                replace_mode,
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
                    "detach",
                    Func::from(|id: u32| -> bool {
                        match detach(id) {
                            Ok(()) => true,
                            Err(e) => {
                                log::warn!("Interceptor.detach({id}): {e}");
                                false
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "detachAll",
                    Func::from(|| {
                        let _ = detach_all();
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "flush",
                    Func::from(|| {
                        flush();
                    }),
                )
                .map_err(|e| e.to_string())?;

            // Minimal FFI for fixtures: call a pointer-sized native fn with 0/1 args.
            helpers
                .set(
                    "call0",
                    Func::from(|addr: f64| -> f64 {
                        let f: extern "C" fn() -> u64 =
                            unsafe { std::mem::transmute(addr as u64) };
                        f() as f64
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "call1",
                    Func::from(|addr: f64, a0: f64| -> f64 {
                        let f: extern "C" fn(u64) -> u64 =
                            unsafe { std::mem::transmute(addr as u64) };
                        f(a0 as u64) as f64
                    }),
                )
                .map_err(|e| e.to_string())?;

            // Fire libc call on a side thread so Interceptor JS can run after
            // the current eval releases the QuickJS context (no nested re-entry).
            helpers
                .set(
                    "call1Detached",
                    Func::from(|addr: f64, a0: f64| {
                        let addr = addr as u64;
                        let a0 = a0 as u64;
                        std::thread::spawn(move || {
                            let f: extern "C" fn(u64) -> u64 =
                                unsafe { std::mem::transmute(addr) };
                            let _ = f(a0);
                        });
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "evalAsync",
                    Func::from(|source: String| -> bool {
                        js_queue::submit_eval_async(source).is_ok()
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "mamEnableJson",
                    Func::from(|ranges_json: String| -> String {
                        let parsed: Result<Vec<serde_json::Value>, _> =
                            serde_json::from_str(&ranges_json);
                        let Ok(arr) = parsed else {
                            return r#"{"ok":false,"error":"bad ranges json"}"#.into();
                        };
                        let mut ranges = Vec::new();
                        for v in arr {
                            let base = v
                                .get("base")
                                .and_then(|x| x.as_u64().or_else(|| x.as_f64().map(|f| f as u64)))
                                .unwrap_or(0);
                            let size = v
                                .get("size")
                                .and_then(|x| x.as_u64().or_else(|| x.as_f64().map(|f| f as u64)))
                                .unwrap_or(0);
                            if base != 0 && size != 0 {
                                ranges.push((base, size));
                            }
                        }
                        match crate::memory_access::enable(&ranges) {
                            Ok(n) => format!(r#"{{"ok":true,"pagesTotal":{n}}}"#),
                            Err(e) => format!(
                                r#"{{"ok":false,"error":{}}}"#,
                                serde_json::to_string(&e).unwrap_or_else(|_| "\"err\"".into())
                            ),
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "mamDisable",
                    Func::from(|| {
                        crate::memory_access::disable();
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "clearIcache",
                    Func::from(|addr: f64, len: f64| {
                        let a = (addr as u64) & 0x00FF_FFFF_FFFF_FFFF;
                        unsafe {
                            goauld_native_hook::icache::clear_icache(a as *const u8, len as usize);
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "arm64WriterNew",
                    Func::from(|code_address: f64, pc: Opt<f64>| -> f64 {
                        let pc = pc.0.and_then(|p| {
                            if p.is_nan() || p < 0.0 {
                                None
                            } else {
                                Some(p as u64)
                            }
                        });
                        crate::arm64_code::writer_new(code_address as u64, pc) as f64
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "arm64WriterOp",
                    Func::from(|id: f64, op: String, args: Opt<String>| -> String {
                        crate::arm64_code::writer_op(
                            id as u32,
                            &op,
                            args.0.as_deref().unwrap_or("{}"),
                        )
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "arm64RelocatorNew",
                    Func::from(|input: f64, writer_id: f64| -> f64 {
                        match crate::arm64_code::relocator_new(input as u64, writer_id as u32) {
                            Ok(id) => id as f64,
                            Err(e) => {
                                log::error!("Arm64Relocator.new: {e}");
                                0.0
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "arm64RelocatorOp",
                    Func::from(
                        |id: f64, writer_id: f64, op: String, args: Opt<String>| -> String {
                            crate::arm64_code::relocator_op(
                                id as u32,
                                writer_id as u32,
                                &op,
                                args.0.as_deref().unwrap_or("{}"),
                            )
                        },
                    ),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "arm64RelocatorSetSource",
                    Func::from(|id: f64, base: f64, bytes: Vec<u8>| -> bool {
                        crate::arm64_code::relocator_set_source(id as u32, base as u64, bytes)
                            .is_ok()
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "replacePtr",
                    Func::from(|addr: f64, replacement: f64| -> u32 {
                        let target = addr as u64;
                        let repl = replacement as u64;
                        let code =
                            unsafe { std::slice::from_raw_parts(target as *const u8, 16) }.to_vec();
                        match replace_ptr(target, &code, repl) {
                            Ok(h) => h.id,
                            Err(e) => {
                                log::error!("Interceptor.replace failed: {e}");
                                0
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "javaEnsureVm",
                    Func::from(|| -> bool {
                        // Touch JNI so perform()/performNow() run with a live VM attachment.
                        goauld_art_bridge::android_sdk_int_or_0() != 0
                            || goauld_art_bridge::android_version().is_ok()
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
                    "stopAndroidApiTrace",
                    Func::from(|| -> bool {
                        goauld_art_bridge::stop_android_api_trace();
                        true
                    }),
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

            let blog = bridge.clone();
            helpers
                .set(
                    "consoleLog",
                    Func::from(move |level: String, message: String| {
                        blog.emit_log(&level, message);
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "scheduleTimer",
                    Func::from(|delay_ms: f64, repeating: bool| -> f64 {
                        crate::timers::schedule(delay_ms.max(0.0) as u64, repeating) as f64
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "cancelTimer",
                    Func::from(|id: f64| {
                        crate::timers::cancel(id as u64);
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "runGc",
                    Func::from(|ctx: Ctx<'_>| {
                        ctx.run_gc();
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "engineName",
                    Func::from(|| -> String { "quickjs".into() }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "cloakAddThread",
                    Func::from(|id: f64| {
                        crate::cloak::add_thread(id as u64);
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakRemoveThread",
                    Func::from(|id: f64| {
                        crate::cloak::remove_thread(id as u64);
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakHasThread",
                    Func::from(|id: f64| -> bool { crate::cloak::has_thread(id as u64) }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakHasCurrentThread",
                    Func::from(|| -> bool { crate::cloak::has_current_thread() }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakAddRange",
                    Func::from(|base: f64, size: f64| {
                        crate::cloak::add_range(base as u64, size as u64);
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakRemoveRange",
                    Func::from(|base: f64, size: f64| {
                        crate::cloak::remove_range(base as u64, size as u64);
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakHasRangeContaining",
                    Func::from(|addr: f64| -> bool {
                        crate::cloak::has_range_containing(addr as u64)
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakClipRangeJson",
                    Func::from(|base: f64, size: f64| -> String {
                        match crate::cloak::clip_range(base as u64, size as u64) {
                            None => "null".into(),
                            Some(vis) => {
                                let arr: Vec<_> = vis
                                    .into_iter()
                                    .map(|r| {
                                        serde_json::json!({ "base": r.base, "size": r.size })
                                    })
                                    .collect();
                                serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
                            }
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakAddFd",
                    Func::from(|fd: f64| {
                        crate::cloak::add_fd(fd as i32);
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakRemoveFd",
                    Func::from(|fd: f64| {
                        crate::cloak::remove_fd(fd as i32);
                    }),
                )
                .map_err(|e| e.to_string())?;
            helpers
                .set(
                    "cloakHasFd",
                    Func::from(|fd: f64| -> bool { crate::cloak::has_fd(fd as i32) }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "wallClockSample",
                    Func::from(|| -> String {
                        use std::time::{SystemTime, UNIX_EPOCH};
                        let ns = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_nanos() as u64)
                            .unwrap_or(0);
                        ns.to_string()
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "cycleSample",
                    Func::from(|| -> String {
                        #[cfg(target_arch = "aarch64")]
                        {
                            let v: u64;
                            unsafe {
                                core::arch::asm!("mrs {0}, cntvct_el0", out(reg) v);
                            }
                            return v.to_string();
                        }
                        #[cfg(not(target_arch = "aarch64"))]
                        {
                            use std::time::{SystemTime, UNIX_EPOCH};
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_nanos() as u64)
                                .unwrap_or(0)
                                .to_string()
                        }
                    }),
                )
                .map_err(|e| e.to_string())?;

            helpers
                .set(
                    "userTimeSample",
                    Func::from(|tid: Opt<f64>| -> String {
                        let _ = tid;
                        #[cfg(target_os = "linux")]
                        {
                            let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
                            let rc = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) };
                            if rc == 0 {
                                let us = (ru.ru_utime.tv_sec as u128) * 1_000_000
                                    + (ru.ru_utime.tv_usec as u128);
                                return us.to_string();
                            }
                        }
                        "0".into()
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

            // Explicit GC for bursty alloc/string scripts (Frida often starts those
            // microbenches on a cleaner heap; without this, prior ScriptLoad residue
            // and cyclic prelude graphs tax QuickJS mid-loop).
            ctx.globals()
                .set(
                    "gc",
                    Func::from(|ctx: Ctx<'_>| {
                        ctx.run_gc();
                    }),
                )
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
    // Hide the JS worker from Process.enumerateThreads by default (Frida-like).
    crate::cloak::add_thread(crate::cloak::current_tid());
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
            let _guard = RawCtxGuard::push(&ctx);
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
    let result = eng.context.with(|ctx| -> Result<String, String> {
        let _guard = RawCtxGuard::push(&ctx);
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
    });
    match result {
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
    let regs = [
        cpu.x[0], cpu.x[1], cpu.x[2], cpu.x[3], cpu.x[4], cpu.x[5], cpu.x[6], cpu.x[7],
    ];
    let out = js_queue::submit_interceptor_enter(hook_id, regs, Duration::from_secs(5));
    for i in 0..8 {
        cpu.x[i] = out[i];
    }
}

fn dispatch_leave_to_js(hook_id: u32, cpu: &mut CpuContext, retval: u64) {
    let out = js_queue::submit_interceptor_leave(hook_id, retval, Duration::from_secs(5));
    cpu.x[0] = out;
}

/// Called on the JS worker: run `__goauld_on_enter` and return mutated regs.
pub fn worker_interceptor_enter(hook_id: u32, regs: [u64; 8]) -> [u64; 8] {
    if IN_INTERCEPTOR_JS.with(|c| c.get()) || qjs_in_context() {
        return regs;
    }
    let Some(eng) = ENGINE_SLOT.lock().clone() else {
        return regs;
    };
    let mut out = regs;
    IN_INTERCEPTOR_JS.with(|c| c.set(true));
    struct ClearInterceptor;
    impl Drop for ClearInterceptor {
        fn drop(&mut self) {
            IN_INTERCEPTOR_JS.with(|c| c.set(false));
        }
    }
    let _clear = ClearInterceptor;
    let _ = with_active_ctx(&eng, |ctx| {
        let Ok(dispatch) = ctx.globals().get::<_, Function>("__goauld_on_enter") else {
            return;
        };
        let arr = rquickjs::Array::new(ctx.clone()).unwrap();
        for (i, v) in regs.iter().enumerate() {
            let _ = arr.set(i, *v as f64);
        }
        let _: Result<Value, _> = dispatch.call((hook_id, arr));
        if let Ok(muts) = ctx.globals().get::<_, Object>("__goauld_mut_x") {
            for i in 0..8u32 {
                if let Ok(v) = muts.get::<_, f64>(i) {
                    out[i as usize] = v as u64;
                }
            }
        }
    });
    out
}

/// Called on the JS worker: run `__goauld_on_leave` and return mutated retval.
pub fn worker_interceptor_leave(hook_id: u32, retval: u64) -> u64 {
    if IN_INTERCEPTOR_JS.with(|c| c.get()) || qjs_in_context() {
        return retval;
    }
    let Some(eng) = ENGINE_SLOT.lock().clone() else {
        return retval;
    };
    let mut out = retval;
    IN_INTERCEPTOR_JS.with(|c| c.set(true));
    struct ClearInterceptor;
    impl Drop for ClearInterceptor {
        fn drop(&mut self) {
            IN_INTERCEPTOR_JS.with(|c| c.set(false));
        }
    }
    let _clear = ClearInterceptor;
    let _ = with_active_ctx(&eng, |ctx| {
        let Ok(dispatch) = ctx.globals().get::<_, Function>("__goauld_on_leave") else {
            return;
        };
        let _: Result<Value, _> = dispatch.call((hook_id, retval as f64));
        if let Ok(v) = ctx.globals().get::<_, f64>("__goauld_mut_retval") {
            out = v as u64;
            let _ = ctx.globals().set("__goauld_mut_retval", rquickjs::Undefined);
        }
    });
    out
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
        // Strip ARM TBI/MTE top byte so the VA fits in f64's 53-bit mantissa.
        (self.addr & 0x00FF_FFFF_FFFF_FFFF) as f64
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
        // JS bitwise ops yield signed Int32; recover low bits via i64.
        api::memory::write_u8(Np(self.addr), (v as i64) as u8);
    }

    pub fn writeU16(&self, v: f64) {
        api::memory::write_u16(Np(self.addr), (v as i64) as u16);
    }

    pub fn writeU32(&self, v: f64) {
        api::memory::write_u32(Np(self.addr), (v as i64) as u32);
    }

    pub fn writeU64(&self, v: f64) {
        api::memory::write_u64(Np(self.addr), (v as i64) as u64);
    }

    pub fn writePointer(&self, p: f64) {
        api::memory::write_pointer(Np(self.addr), Np(p as u64));
    }

    #[qjs(rename = "toString")]
    pub fn js_to_string(&self) -> String {
        format!("0x{:x}", self.addr)
    }
}

const PRELUDE: &str = crate::frida_prelude::FRIDA_PRELUDE;
