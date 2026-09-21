//! Shared host operations for QuickJS and Symbiote Frida-shaped `__goauld` bindings.
//!
//! Symbiote calls these through a JSON dispatcher so both engines expose the same surface.

use crate::api::{self, NativePointer as Np};
use crate::js_queue;
use goauld_native_hook::patch::{attach, detach, detach_all, flush, replace_ptr};
use goauld_native_hook::trampoline::{CpuContext, HookCallbacks};
use serde_json::{Value, json};
use std::time::Duration;

fn ok_n(n: f64) -> String {
    json!({"ok": true, "t": "n", "v": n}).to_string()
}
fn ok_s(s: impl Into<String>) -> String {
    json!({"ok": true, "t": "s", "v": s.into()}).to_string()
}
fn ok_b(b: bool) -> String {
    json!({"ok": true, "t": "b", "v": b}).to_string()
}
fn ok_u() -> String {
    json!({"ok": true, "t": "u"}).to_string()
}
fn err(msg: impl Into<String>) -> String {
    json!({"ok": false, "error": msg.into()}).to_string()
}

fn arg_f(args: &[Value], i: usize) -> f64 {
    args.get(i)
        .and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_i64().map(|n| n as f64))
                .or_else(|| v.as_u64().map(|n| n as f64))
        })
        .unwrap_or(0.0)
}
fn arg_u(args: &[Value], i: usize) -> u64 {
    arg_f(args, i) as u64
}
fn arg_s(args: &[Value], i: usize) -> String {
    args.get(i)
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}
fn arg_b(args: &[Value], i: usize) -> bool {
    args.get(i).and_then(|v| v.as_bool()).unwrap_or(false)
}
fn arg_bytes(args: &[Value], i: usize) -> Vec<u8> {
    args.get(i)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|x| {
                    x.as_u64()
                        .or_else(|| x.as_f64().map(|f| f as u64))
                        .unwrap_or(0) as u8
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Dispatch a host op. `args_json` is a JSON array of positional arguments.
pub fn dispatch(op: &str, args_json: &str) -> String {
    let args: Vec<Value> = serde_json::from_str(args_json).unwrap_or_default();
    match op {
        "engineName" => ok_s("symbiote"),
        "findExport" => {
            let (mod_name, export) = if args.len() >= 2 {
                let m = args[0].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string());
                (m, arg_s(&args, 1))
            } else {
                (None, arg_s(&args, 0))
            };
            match api::module::find_export_by_name(mod_name.as_deref(), &export) {
                Some(p) => ok_n(p.0 as f64),
                None => ok_u(),
            }
        }
        "findBase" => match api::module::find_base_address(&arg_s(&args, 0)) {
            Some(p) => ok_n(p.0 as f64),
            None => ok_u(),
        }
        "readUtf8" => ok_s(api::memory::read_utf8_string(Np(arg_u(&args, 0)), None)),
        "processInfoJson" => {
            let i = api::process::info();
            ok_s(
                json!({
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
                .to_string(),
            )
        }
        "enumerateModulesJson" => {
            let mods: Vec<_> = api::process::enumerate_modules()
                .into_iter()
                .map(|m| json!({"name": m.name, "base": m.base, "size": m.size, "path": m.path}))
                .collect();
            ok_s(serde_json::to_string(&mods).unwrap_or_else(|_| "[]".into()))
        }
        "findModuleByNameJson" => match api::process::find_module_by_name(&arg_s(&args, 0)) {
            Some(m) => ok_s(
                json!({"name": m.name, "base": m.base, "size": m.size, "path": m.path}).to_string(),
            ),
            None => ok_u(),
        },
        "findModuleByAddressJson" => {
            match api::process::find_module_by_address(Np(arg_u(&args, 0))) {
                Some(m) => ok_s(
                    json!({"name": m.name, "base": m.base, "size": m.size, "path": m.path})
                        .to_string(),
                ),
                None => ok_u(),
            }
        }
        "enumerateRangesJson" => {
            let prot = arg_s(&args, 0);
            let coalesce = arg_b(&args, 1);
            let ranges: Vec<_> = api::process::enumerate_ranges(&prot, coalesce)
                .into_iter()
                .map(|r| json!({"base": r.base, "size": r.size, "protection": r.protection}))
                .collect();
            ok_s(serde_json::to_string(&ranges).unwrap_or_else(|_| "[]".into()))
        }
        "findRangeByAddressJson" => match api::process::find_range_by_address(Np(arg_u(&args, 0))) {
            Some(r) => ok_s(
                json!({"base": r.base, "size": r.size, "protection": r.protection}).to_string(),
            ),
            None => ok_u(),
        },
        "enumerateThreadsJson" => {
            let threads: Vec<_> = api::thread::enumerate_threads()
                .into_iter()
                .map(|t| json!({"id": t.id, "name": t.name, "state": t.state}))
                .collect();
            ok_s(serde_json::to_string(&threads).unwrap_or_else(|_| "[]".into()))
        }
        "threadSleep" => {
            api::thread::sleep(arg_f(&args, 0));
            ok_u()
        }
        "threadBacktraceJson" => {
            let accurate = arg_b(&args, 0);
            let max = arg_f(&args, 1) as usize;
            let frames: Vec<_> = api::thread::backtrace(accurate, max)
                .into_iter()
                .map(|a| a.0)
                .collect();
            ok_s(serde_json::to_string(&frames).unwrap_or_else(|_| "[]".into()))
        }
        "memoryAlloc" => ok_n(
            (api::memory::alloc(arg_f(&args, 0) as usize).0 & 0x00FF_FFFF_FFFF_FFFF) as f64,
        ),
        "memoryAllocAnon" => ok_n(
            (api::memory::alloc_anonymous(arg_f(&args, 0) as usize).0 & 0x00FF_FFFF_FFFF_FFFF)
                as f64,
        ),
        "memoryAllocUtf8" => ok_n(api::memory::alloc_utf8_string(&arg_s(&args, 0)).0 as f64),
        "memoryCopy" => {
            api::memory::copy(Np(arg_u(&args, 0)), Np(arg_u(&args, 1)), arg_f(&args, 2) as usize);
            ok_u()
        }
        "memoryDup" => ok_n(api::memory::dup(Np(arg_u(&args, 0)), arg_f(&args, 1) as usize).0 as f64),
        "memoryProtect" => ok_b(api::memory::protect(
            Np(arg_u(&args, 0)),
            arg_f(&args, 1) as usize,
            &arg_s(&args, 2),
        )),
        "memoryQueryProtection" => match api::memory::query_protection(Np(arg_u(&args, 0))) {
            Some(s) => ok_s(s),
            None => ok_u(),
        },
        "memoryWriteBytes" => {
            api::memory::write_byte_array(Np(arg_u(&args, 0)), &arg_bytes(&args, 1));
            ok_u()
        }
        "memoryScanSyncJson" => {
            let hits: Vec<_> = api::memory::scan_sync(
                Np(arg_u(&args, 0)),
                arg_f(&args, 1) as usize,
                &arg_s(&args, 2),
            )
            .into_iter()
            .map(|(a, sz)| json!({"address": a, "size": sz}))
            .collect();
            ok_s(serde_json::to_string(&hits).unwrap_or_else(|_| "[]".into()))
        }
        "clearIcache" => {
            let a = arg_u(&args, 0) & 0x00FF_FFFF_FFFF_FFFF;
            let len = arg_f(&args, 1) as usize;
            unsafe {
                goauld_native_hook::icache::clear_icache(a as *const u8, len);
            }
            ok_u()
        }
        "moduleLoadJson" => match api::module::load(&arg_s(&args, 0)) {
            Ok(m) => ok_s(
                json!({"ok": true, "name": m.name, "base": m.base, "size": m.size, "path": m.path})
                    .to_string(),
            ),
            Err(e) => ok_s(json!({"ok": false, "error": e}).to_string()),
        },
        "enumerateExportsJson" => {
            let name = arg_s(&args, 0);
            let Some(m) = api::module::find_module_by_name(&name) else {
                return ok_s("[]");
            };
            let exports: Vec<_> = api::module::enumerate_exports(&m)
                .into_iter()
                .map(|e| json!({"type": e.kind, "name": e.name, "address": e.address.0}))
                .collect();
            ok_s(serde_json::to_string(&exports).unwrap_or_else(|_| "[]".into()))
        }
        "enumerateImportsJson" => {
            let name = arg_s(&args, 0);
            let Some(m) = api::module::find_module_by_name(&name) else {
                return ok_s("[]");
            };
            let imports: Vec<_> = api::module::enumerate_imports(&m)
                .into_iter()
                .map(|e| {
                    json!({
                        "type": e.kind,
                        "name": e.name,
                        "module": e.module,
                        "address": e.address.map(|a| a.0),
                        "slot": e.slot.map(|a| a.0),
                    })
                })
                .collect();
            ok_s(serde_json::to_string(&imports).unwrap_or_else(|_| "[]".into()))
        }
        "enumerateSymbolsJson" => {
            let name = arg_s(&args, 0);
            let Some(m) = api::module::find_module_by_name(&name) else {
                return ok_s("[]");
            };
            let syms: Vec<_> = api::module::enumerate_symbols(&m)
                .into_iter()
                .map(|e| {
                    json!({
                        "isGlobal": e.is_global,
                        "type": e.kind,
                        "name": e.name,
                        "address": e.address.0,
                        "size": e.size,
                    })
                })
                .collect();
            ok_s(serde_json::to_string(&syms).unwrap_or_else(|_| "[]".into()))
        }
        "enumerateSectionsJson" => {
            let name = arg_s(&args, 0);
            let Some(m) = api::module::find_module_by_name(&name) else {
                return ok_s("[]");
            };
            let secs: Vec<_> = api::module::enumerate_sections(&m)
                .into_iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "name": e.name,
                        "address": e.address.0,
                        "size": e.size,
                    })
                })
                .collect();
            ok_s(serde_json::to_string(&secs).unwrap_or_else(|_| "[]".into()))
        }
        "enumerateDependenciesJson" => {
            let name = arg_s(&args, 0);
            let Some(m) = api::module::find_module_by_name(&name) else {
                return ok_s("[]");
            };
            ok_s(
                serde_json::to_string(&api::module::enumerate_dependencies(&m))
                    .unwrap_or_else(|_| "[]".into()),
            )
        }
        "attach" => {
            let addr = arg_u(&args, 0);
            let want_leave = arg_b(&args, 1);
            let replace_mode = arg_b(&args, 2);
            let code = unsafe { std::slice::from_raw_parts(addr as *const u8, 16) }.to_vec();
            let id_cell = std::sync::Arc::new(std::sync::Mutex::new(0u32));
            let id_enter = id_cell.clone();
            let id_leave = id_cell.clone();
            let on_leave = if want_leave || replace_mode {
                Some(Box::new(move |cpu: &mut CpuContext, retval: u64| {
                    let id = *id_leave.lock().unwrap_or_else(|e| e.into_inner());
                    let out = crate::js_queue::submit_interceptor_leave(
                        id,
                        retval,
                        Duration::from_secs(5),
                    );
                    cpu.x[0] = out;
                }) as _)
            } else {
                None
            };
            let cbs = HookCallbacks {
                on_enter: Some(Box::new(move |cpu: &mut CpuContext| {
                    let id = *id_enter.lock().unwrap_or_else(|e| e.into_inner());
                    let regs = [
                        cpu.x[0], cpu.x[1], cpu.x[2], cpu.x[3], cpu.x[4], cpu.x[5], cpu.x[6],
                        cpu.x[7],
                    ];
                    let out = crate::js_queue::submit_interceptor_enter(
                        id,
                        regs,
                        Duration::from_secs(5),
                    );
                    for i in 0..8 {
                        cpu.x[i] = out[i];
                    }
                })),
                on_leave,
                save_simd: false,
                replace_mode,
            };
            match attach(addr, &code, cbs) {
                Ok(h) => {
                    if let Ok(mut g) = id_cell.lock() {
                        *g = h.id;
                    }
                    ok_n(h.id as f64)
                }
                Err(e) => {
                    log::error!("Interceptor.attach failed: {e}");
                    ok_n(0.0)
                }
            }
        }
        "detach" => ok_b(detach(arg_f(&args, 0) as u32).is_ok()),
        "detachAll" => {
            let _ = detach_all();
            ok_u()
        }
        "flush" => {
            flush();
            ok_u()
        }
        "replacePtr" => {
            let target = arg_u(&args, 0);
            let repl = arg_u(&args, 1);
            let code = unsafe { std::slice::from_raw_parts(target as *const u8, 16) }.to_vec();
            match replace_ptr(target, &code, repl) {
                Ok(h) => ok_n(h.id as f64),
                Err(e) => {
                    log::error!("Interceptor.replace failed: {e}");
                    ok_n(0.0)
                }
            }
        }
        "call0" => {
            let f: extern "C" fn() -> u64 = unsafe { std::mem::transmute(arg_u(&args, 0)) };
            ok_n(f() as f64)
        }
        "call1" => {
            let f: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(arg_u(&args, 0)) };
            ok_n(f(arg_u(&args, 1)) as f64)
        }
        "call1Detached" => {
            let addr = arg_u(&args, 0);
            let a0 = arg_u(&args, 1);
            std::thread::spawn(move || {
                let f: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(addr) };
                let _ = f(a0);
            });
            ok_u()
        }
        "evalAsync" => ok_b(js_queue::submit_eval_async(arg_s(&args, 0)).is_ok()),
        "scheduleTimer" => ok_n(
            crate::timers::schedule(arg_f(&args, 0).max(0.0) as u64, arg_b(&args, 1)) as f64,
        ),
        "cancelTimer" => {
            crate::timers::cancel(arg_f(&args, 0) as u64);
            ok_u()
        }
        "runGc" => {
            // Symbiote GC is engine-managed; no-op host side.
            ok_u()
        }
        "consoleLog" => {
            let level = arg_s(&args, 0);
            let line = arg_s(&args, 1);
            log::info!("js[{level}]: {line}");
            ok_u()
        }
        "arm64WriterNew" => {
            let pc = if args.len() > 1 {
                let p = arg_f(&args, 1);
                if p < 0.0 || p.is_nan() {
                    None
                } else {
                    Some(p as u64)
                }
            } else {
                None
            };
            ok_n(crate::arm64_code::writer_new(arg_u(&args, 0), pc) as f64)
        }
        "arm64WriterOp" => {
            let id = arg_f(&args, 0) as u32;
            let op_name = arg_s(&args, 1);
            let args_s = if args.len() > 2 {
                arg_s(&args, 2)
            } else {
                "{}".into()
            };
            ok_s(crate::arm64_code::writer_op(id, &op_name, &args_s))
        }
        "arm64RelocatorNew" => match crate::arm64_code::relocator_new(arg_u(&args, 0), arg_f(&args, 1) as u32)
        {
            Ok(id) => ok_n(id as f64),
            Err(e) => {
                log::error!("Arm64Relocator.new: {e}");
                ok_n(0.0)
            }
        },
        "arm64RelocatorOp" => {
            let id = arg_f(&args, 0) as u32;
            let wid = arg_f(&args, 1) as u32;
            let op_name = arg_s(&args, 2);
            let args_s = if args.len() > 3 {
                arg_s(&args, 3)
            } else {
                "{}".into()
            };
            ok_s(crate::arm64_code::relocator_op(id, wid, &op_name, &args_s))
        }
        "arm64RelocatorSetSource" => ok_b(
            crate::arm64_code::relocator_set_source(
                arg_f(&args, 0) as u32,
                arg_u(&args, 1),
                arg_bytes(&args, 2),
            )
            .is_ok(),
        ),
        "cloakAddThread" => {
            crate::cloak::add_thread(arg_u(&args, 0));
            ok_u()
        }
        "cloakRemoveThread" => {
            crate::cloak::remove_thread(arg_u(&args, 0));
            ok_u()
        }
        "cloakHasCurrentThread" => ok_b(crate::cloak::has_current_thread()),
        "cloakHasThread" => ok_b(crate::cloak::has_thread(arg_u(&args, 0))),
        "cloakAddRange" => {
            crate::cloak::add_range(arg_u(&args, 0), arg_u(&args, 1));
            ok_u()
        }
        "cloakRemoveRange" => {
            crate::cloak::remove_range(arg_u(&args, 0), arg_u(&args, 1));
            ok_u()
        }
        "cloakHasRangeContaining" => ok_b(crate::cloak::has_range_containing(arg_u(&args, 0))),
        "cloakClipRangeJson" => {
            let clipped = crate::cloak::clip_range(arg_u(&args, 0), arg_u(&args, 1));
            match clipped {
                None => ok_s("null"),
                Some(ranges) => {
                    let v: Vec<_> = ranges
                        .into_iter()
                        .map(|r| json!({"base": r.base, "size": r.size}))
                        .collect();
                    ok_s(serde_json::to_string(&v).unwrap_or_else(|_| "[]".into()))
                }
            }
        }
        "cloakAddFd" => {
            crate::cloak::add_fd(arg_f(&args, 0) as i32);
            ok_u()
        }
        "cloakRemoveFd" => {
            crate::cloak::remove_fd(arg_f(&args, 0) as i32);
            ok_u()
        }
        "cloakHasFd" => ok_b(crate::cloak::has_fd(arg_f(&args, 0) as i32)),
        "wallClockSample" => {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            ok_s(ns.to_string())
        }
        "cycleSample" => {
            #[cfg(target_arch = "aarch64")]
            {
                let v: u64;
                unsafe {
                    core::arch::asm!("mrs {0}, cntvct_el0", out(reg) v);
                }
                return ok_s(v.to_string());
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                ok_s("0")
            }
        }
        "userTimeSample" => {
            let _ = arg_f(&args, 0);
            #[cfg(target_os = "linux")]
            {
                let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
                let rc = unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) };
                if rc == 0 {
                    let us = (ru.ru_utime.tv_sec as u128) * 1_000_000
                        + (ru.ru_utime.tv_usec as u128);
                    return ok_s((us * 1000).to_string());
                }
            }
            ok_s("0")
        }
        "mamEnableJson" => {
            let ranges_json = arg_s(&args, 0);
            let parsed: Result<Vec<Value>, _> = serde_json::from_str(&ranges_json);
            let Ok(arr) = parsed else {
                return ok_s(r#"{"ok":false,"error":"bad ranges json"}"#);
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
                Ok(n) => ok_s(format!(r#"{{"ok":true,"pagesTotal":{n}}}"#)),
                Err(e) => ok_s(format!(
                    r#"{{"ok":false,"error":{}}}"#,
                    serde_json::to_string(&e).unwrap_or_else(|_| "\"err\"".into())
                )),
            }
        }
        "mamDisable" => {
            crate::memory_access::disable();
            ok_u()
        }
        "startThreadObserver" => {
            // Best-effort; full observer is QuickJS-wired.
            ok_u()
        }
        "stopThreadObserver" => ok_u(),
        "setExceptionHandler" => ok_u(),
        "exceptionProbeJson" => ok_u(),
        "scheduleOnThread" => ok_b(false),
        "spawnSleepThread" => ok_u(),
        "javaEnsureVm" => ok_b(
            goauld_art_bridge::android_sdk_int_or_0() != 0
                || goauld_art_bridge::android_version().is_ok(),
        ),
        "javaIsMainThread" => ok_b(goauld_art_bridge::is_main_thread().unwrap_or(false)),
        "javaAndroidVersion" => ok_s(
            goauld_art_bridge::android_version().unwrap_or_else(|_| "unknown".into()),
        ),
        "javaNextMainToken" => ok_n(goauld_art_bridge::next_main_token() as f64),
        "javaScheduleMain" => {
            let token = arg_u(&args, 0);
            match goauld_art_bridge::schedule_on_main(token) {
                Ok(()) => ok_b(true),
                Err(e) => {
                    log::debug!("javaScheduleMain({token}): {e}");
                    ok_b(false)
                }
            }
        }
        "javaEnumerateClassesJson" => ok_s(match goauld_art_bridge::enumerate_loaded_classes() {
            Ok(v) => serde_json::to_string(&v).unwrap_or_else(|_| "[]".into()),
            Err(e) => {
                log::warn!("enumerateLoadedClasses: {e}");
                "[]".into()
            }
        }),
        "javaEnumerateLoadersJson" => ok_s(match goauld_art_bridge::enumerate_class_loaders() {
            Ok(v) => serde_json::to_string(&v).unwrap_or_else(|_| "[]".into()),
            Err(e) => {
                log::warn!("enumerateClassLoaders: {e}");
                "[]".into()
            }
        }),
        "javaClassMethodsJson" => ok_s(class_methods_json(&arg_s(&args, 0))),
        "javaClassFieldsJson" => ok_s(class_fields_json(&arg_s(&args, 0))),
        "javaReadStaticFieldJson" => {
            let class_name = arg_s(&args, 0);
            let field = arg_s(&args, 1);
            ok_s(
                match goauld_art_bridge::read_static_field_json(&class_name, &field) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("read static {class_name}.{field}: {e}");
                        serde_json::json!({ "error": e.to_string() }).to_string()
                    }
                },
            )
        }
        "javaDumpStorageJson" => ok_s(match goauld_art_bridge::dump_app_storage_json() {
            Ok(v) => v,
            Err(e) => {
                log::warn!("dumpAppStorage: {e}");
                serde_json::json!({ "error": e.to_string() }).to_string()
            }
        }),
        "javaHook" => {
            let class_name = arg_s(&args, 0);
            let method = arg_s(&args, 1);
            let sig = args
                .get(2)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("(I)I");
            log::info!("Java hook requested: {class_name}.{method}{sig}");
            match goauld_art_bridge::hook_java_method(&class_name, &method, sig) {
                Ok(()) => ok_b(true),
                Err(e) => {
                    log::error!("hook_java_method failed: {e}");
                    ok_b(false)
                }
            }
        }
        "javaCallOriginal" => {
            let key = arg_s(&args, 0);
            let x = arg_f(&args, 1);
            ok_n(
                goauld_art_bridge::js_call_original(&key, x as i32).unwrap_or(x as i32) as f64,
            )
        }
        "androidToast" => {
            let message = arg_s(&args, 0);
            match goauld_art_bridge::show_android_toast(&message) {
                Ok(()) => ok_b(true),
                Err(e) => {
                    log::error!("androidToast failed: {e}");
                    ok_b(false)
                }
            }
        }
        "stopAndroidApiTrace" => {
            goauld_art_bridge::stop_android_api_trace();
            ok_b(true)
        }
        "traceAndroidApi" => {
            let raw = arg_s(&args, 0);
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
            let max_events = arg_f(&args, 1) as u64;
            match goauld_art_bridge::start_android_api_trace(
                goauld_art_bridge::AndroidApiTraceConfig {
                    prefixes,
                    max_events,
                    with_signature: true,
                },
            ) {
                Ok(id) => ok_n(id as f64),
                Err(e) => {
                    log::error!("traceAndroidApi failed: {e}");
                    ok_n(0.0)
                }
            }
        }
        "sendJson" | "sendJsonData" => {
            // Handled specially by Symbiote install (needs bridge).
            err("sendJson must be bound by engine")
        }
        other => err(format!("unknown host op: {other}")),
    }
}

fn class_methods_json(class_name: &str) -> String {
    match goauld_art_bridge::enumerate_class_methods(class_name) {
        Ok(v) => {
            let arr: Vec<_> = v
                .into_iter()
                .map(|m| {
                    json!({
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
}

fn class_fields_json(class_name: &str) -> String {
    match goauld_art_bridge::enumerate_class_fields(class_name) {
        Ok(v) => {
            let arr: Vec<_> = v
                .into_iter()
                .map(|f| {
                    json!({
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
}

/// Apply a dispatch result in JS terms — used by docs/tests.
#[allow(dead_code)]
pub fn dispatch_timeout_hint() -> Duration {
    Duration::from_secs(5)
}
