//! Symbiote (pure-Rust JS) runtime + Frida-shaped globals.
//!
//! Selected with `--features symbiote --no-default-features` on `goauld-script`
//! / `goauld-agent`. Host helpers share [`crate::host_ops`] with the same
//! `__goauld` surface as QuickJS; the Frida API prelude is shared via
//! [`crate::frida_prelude`].

#![cfg(feature = "symbiote")]

use crate::api::{self, NativePointer as Np};
use crate::engine::ScriptId;
use crate::frida_prelude::FRIDA_PRELUDE;
use crate::js_lock::JsLock;
use crate::js_queue::{JavaInvokeJob, JavaInvokeResult};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use symbiote_core::host::{ContextConfig, RuntimeConfig};
use symbiote_core::runtime::{Context, Runtime};
use symbiote_core::value::{from_f64, from_i32, undefined, Value};
use symbiote_core::JsError;

pub use crate::bridge::{shared_bridge, HostBridge};

struct SymEngine {
    _runtime: Runtime,
    context: Context,
    bridge: Arc<HostBridge>,
}

unsafe impl Send for SymEngine {}
unsafe impl Sync for SymEngine {}

static ENGINE_SLOT: Mutex<Option<Arc<Mutex<SymEngine>>>> = Mutex::new(None);
static JS_LOCK_SLOT: Mutex<Option<Arc<JsLock>>> = Mutex::new(None);

pub fn set_js_lock(lock: Arc<JsLock>) {
    *JS_LOCK_SLOT.lock() = Some(lock);
}

fn arg_num(args: &[Value], i: usize) -> f64 {
    args.get(i)
        .and_then(|v| v.as_int32().map(|n| n as f64).or_else(|| v.as_f64()))
        .unwrap_or(0.0)
}

fn arg_str(ctx: &mut Context, args: &[Value], i: usize) -> String {
    args.get(i)
        .map(|v| ctx.value_to_string(*v).unwrap_or_default())
        .unwrap_or_default()
}

fn ok_str(ctx: &mut Context, s: String) -> Result<Value, JsError> {
    Ok(ctx.new_string(&s))
}

fn ok_num(n: f64) -> Result<Value, JsError> {
    if n.fract() == 0.0 && n >= i32::MIN as f64 && n <= i32::MAX as f64 {
        Ok(from_i32(n as i32))
    } else {
        Ok(from_f64(n))
    }
}

const SYMBIOTE_BOOT: &str = r#"
function NativePointer(addr) {
  this.address = (+addr) || 0;
}
NativePointer.prototype.add = function(n) { return new NativePointer(this.address + (+n)); };
NativePointer.prototype.sub = function(n) { return new NativePointer(this.address - (+n)); };
NativePointer.prototype.toString = function() {
  return '0x' + __goauld_hex_u32(this.address);
};
"#;

const SYMBIOTE_SHIM: &str = include_str!("symbiote_goauld_shim.inc.js");

fn install_host(ctx: &mut Context, bridge: Arc<HostBridge>) -> Result<(), String> {
    let b = bridge.clone();
    ctx.register_function("send", move |_c, _t, args| {
        let payload = args
            .first()
            .map(|v| _c.value_to_string(*v).unwrap_or_else(|_| "null".into()))
            .unwrap_or_else(|| "null".into());
        let json = if payload.starts_with('{')
            || payload.starts_with('[')
            || payload.starts_with('"')
            || payload == "null"
            || payload == "true"
            || payload == "false"
            || payload.parse::<f64>().is_ok()
        {
            payload
        } else {
            serde_json::to_string(&payload).unwrap_or(payload)
        };
        b.emit_send(json, None);
        Ok(undefined())
    });

    let b2 = bridge.clone();
    ctx.register_leaf_function("__g_sendJson", move |_c, _t, args| {
        let json = arg_str(_c, args, 0);
        b2.emit_send(json, None);
        Ok(undefined())
    });

    let b3 = bridge.clone();
    ctx.register_leaf_function("__g_sendJsonData", move |_c, _t, args| {
        let json = arg_str(_c, args, 0);
        let mut data = Vec::new();
        if let Some(arr) = args.get(1) {
            if let Ok(len_v) = _c.get_property(*arr, "length") {
                let len = len_v.as_int32().unwrap_or(0).max(0) as usize;
                for i in 0..len.min(1 << 20) {
                    if let Ok(el) = _c.get_property(*arr, &i.to_string()) {
                        data.push(arg_num(&[el], 0) as u8);
                    }
                }
            }
        }
        b3.emit_send(json, if data.is_empty() { None } else { Some(data) });
        Ok(undefined())
    });

    ctx.register_leaf_function("__g_hostOp", |_c, _t, args| {
        let op = arg_str(_c, args, 0);
        let args_json = if args.len() > 1 {
            arg_str(_c, args, 1)
        } else {
            "[]".into()
        };
        let out = crate::host_ops::dispatch(&op, &args_json);
        ok_str(_c, out)
    });

    // Fast-path memory ops used by NativePointer (avoid JSON for every byte).
    ctx.register_leaf_function("__g_readU8", |_c, _t, args| {
        ok_num(api::memory::read_u8(Np(arg_num(args, 0) as u64)) as f64)
    });
    ctx.register_leaf_function("__g_readU16", |_c, _t, args| {
        ok_num(api::memory::read_u16(Np(arg_num(args, 0) as u64)) as f64)
    });
    ctx.register_leaf_function("__g_readU32", |_c, _t, args| {
        ok_num(api::memory::read_u32(Np(arg_num(args, 0) as u64)) as f64)
    });
    ctx.register_leaf_function("__g_readU64", |_c, _t, args| {
        ok_num(api::memory::read_u64(Np(arg_num(args, 0) as u64)) as f64)
    });
    ctx.register_leaf_function("__g_writeU8", |_c, _t, args| {
        api::memory::write_u8(Np(arg_num(args, 0) as u64), arg_num(args, 1) as u8);
        Ok(undefined())
    });
    ctx.register_leaf_function("__g_writeU16", |_c, _t, args| {
        api::memory::write_u16(Np(arg_num(args, 0) as u64), arg_num(args, 1) as u16);
        Ok(undefined())
    });
    ctx.register_leaf_function("__g_writeU32", |_c, _t, args| {
        api::memory::write_u32(Np(arg_num(args, 0) as u64), arg_num(args, 1) as u32);
        Ok(undefined())
    });
    ctx.register_leaf_function("__g_writeU64", |_c, _t, args| {
        api::memory::write_u64(Np(arg_num(args, 0) as u64), arg_num(args, 1) as u64);
        Ok(undefined())
    });

    Ok(())
}

/// Patch NativePointer in boot to use fast leafs; host_ops also exposes memoryRead*.
const SYMBIOTE_NP_FIXUP: &str = r#"
NativePointer.prototype.readU8 = function() { return __g_readU8(this.address); };
NativePointer.prototype.readU16 = function() { return __g_readU16(this.address); };
NativePointer.prototype.readU32 = function() { return __g_readU32(this.address); };
NativePointer.prototype.readU64 = function() { return __g_readU64(this.address); };
NativePointer.prototype.writeU8 = function(v) { __g_writeU8(this.address, +v); return this; };
NativePointer.prototype.writeU16 = function(v) { __g_writeU16(this.address, +v); return this; };
NativePointer.prototype.writeU32 = function(v) { __g_writeU32(this.address, +v); return this; };
NativePointer.prototype.writeU64 = function(v) { __g_writeU64(this.address, +v); return this; };
NativePointer.prototype.readUtf8String = function() { return __host('readUtf8', [this.address]); };
NativePointer.prototype.readPointer = function() { return ptr(__g_readU64(this.address)); };
NativePointer.prototype.writePointer = function(v) {
  var a = (typeof v === 'object') ? v.address : +v;
  __g_writeU64(this.address, a);
  return this;
};
"#;

impl SymEngine {
    fn new(bridge: Arc<HostBridge>) -> Result<Self, String> {
        let mut runtime = Runtime::new(RuntimeConfig {
            memory_limit_bytes: 128 * 1024 * 1024,
        })
        .map_err(|e| format!("symbiote Runtime::new: {e}"))?;
        symbiote_jit::attach(&mut runtime);
        let mut context = runtime
            .new_context(ContextConfig {
                step_budget: u64::MAX / 4,
                max_call_depth: 4096,
                allow_jit: true,
                trusted_leaf_hosts: true,
                allow_nondeterministic: true,
                ..Default::default()
            })
            .map_err(|e| format!("symbiote Context: {e}"))?;
        install_host(&mut context, bridge.clone())?;

        // Order: __host/__goauld shim → NativePointer → Frida prelude → NP fixup
        let boot = format!(
            "{SYMBIOTE_SHIM}\n{SYMBIOTE_BOOT}\n{FRIDA_PRELUDE}\n{SYMBIOTE_NP_FIXUP}\n"
        );
        context
            .eval(&boot)
            .map_err(|e| format!("symbiote prelude: {e}"))?;
        Ok(Self {
            _runtime: runtime,
            context,
            bridge,
        })
    }

    fn set_current_script(&self, id: ScriptId) {
        *self.bridge.current_script.lock() = id;
    }

    fn eval(&mut self, source: &str) -> Result<(), String> {
        self.context
            .eval(source)
            .map(|_| ())
            .map_err(|e| format!("{e}"))
    }
}

pub fn boot_worker(bridge: Arc<HostBridge>) {
    crate::cloak::add_thread(crate::cloak::current_tid());
    match SymEngine::new(bridge) {
        Ok(eng) => {
            *ENGINE_SLOT.lock() = Some(Arc::new(Mutex::new(eng)));
            log::info!("Symbiote engine ready on goauld-js-worker (full Frida prelude)");
        }
        Err(e) => {
            eprintln!("goauld: Symbiote boot failed: {e}");
            log::error!("Symbiote boot failed: {e}");
        }
    }
}

pub fn worker_eval(script_id: ScriptId, source: &str) -> Result<(), String> {
    let slot = ENGINE_SLOT
        .lock()
        .clone()
        .ok_or_else(|| "Symbiote engine not booted".to_string())?;
    let mut eng = slot.lock();
    eng.set_current_script(script_id);
    eng.eval(source)
}

pub fn worker_java_invoke(job: JavaInvokeJob) {
    let _ = job.reply.send(JavaInvokeResult {
        value: job.arg.saturating_add(1000),
        error: Some("Java invoke on Symbiote uses host stubs; prefer quickjs for Technique-A".into()),
    });
}

pub fn worker_deliver_post(payload_json: &str, data: Option<&[u8]>) {
    let Some(slot) = ENGINE_SLOT.lock().clone() else {
        return;
    };
    let data_json = match data {
        Some(d) => serde_json::to_string(d).unwrap_or_else(|_| "null".into()),
        None => "null".into(),
    };
    let src = format!(
        "(function(){{ try {{ var msg = JSON.parse({pj}); var data = {dj}; if (typeof __goauld_deliver_post === 'function') return !!__goauld_deliver_post(msg, data); return false; }} catch (e) {{ return false; }} }})()",
        pj = serde_json::to_string(payload_json).unwrap_or_else(|_| "\"{}\"".into()),
        dj = data_json,
    );
    let _ = slot.lock().eval(&src);
}

pub fn worker_rpc_call(fn_name: &str, args_json: &str) -> crate::js_queue::RpcInvokeResult {
    use crate::js_queue::RpcInvokeResult;
    let Some(slot) = ENGINE_SLOT.lock().clone() else {
        return RpcInvokeResult {
            result_json: None,
            error: Some("no Symbiote engine".into()),
        };
    };
    let src = format!(
        "(function(){{ try {{ var f = (rpc && rpc.exports) ? rpc.exports[{fn}] : null; if (typeof f !== 'function') return JSON.stringify({{error:'missing'}}); var args = JSON.parse({args}); if (!Array.isArray(args)) args = [args]; var ret = f.apply(null, args); return JSON.stringify({{result: (ret === undefined) ? null : ret}}); }} catch (e) {{ return JSON.stringify({{error: String(e)}}); }} }})()",
        fn = serde_json::to_string(fn_name).unwrap_or_else(|_| "\"\"".into()),
        args = serde_json::to_string(args_json).unwrap_or_else(|_| "\"[]\"".into()),
    );
    let result = {
        let mut eng = slot.lock();
        eng.eval_string_result(&src)
    };
    match result {
        Ok(s) => {
            if let Ok(wrapper) = serde_json::from_str::<serde_json::Value>(&s) {
                if let Some(err) = wrapper.get("error").and_then(|e| e.as_str()) {
                    return RpcInvokeResult {
                        result_json: None,
                        error: Some(err.to_string()),
                    };
                }
                if let Some(r) = wrapper.get("result") {
                    return RpcInvokeResult {
                        result_json: Some(r.to_string()),
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

impl SymEngine {
    fn eval_string_result(&mut self, source: &str) -> Result<String, String> {
        match self.context.eval(source) {
            Ok(v) => self
                .context
                .value_to_string(v)
                .map_err(|e| format!("{e}")),
            Err(e) => Err(format!("{e}")),
        }
    }
}

/// Keep signature parity with QuickJS for js_queue drain.
pub fn worker_tick(_timeout: Duration) {}

pub fn worker_interceptor_enter(hook_id: u32, regs: [u64; 8]) -> [u64; 8] {
    let _ = hook_id;
    regs
}

pub fn worker_interceptor_leave(hook_id: u32, retval: u64) -> u64 {
    let _ = hook_id;
    retval
}