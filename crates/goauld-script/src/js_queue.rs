//! Marshal all QuickJS work onto a dedicated worker thread.
//!
//! The Runtime/Context are created on that thread and never touched elsewhere.
//! ART hook threads and the agent I/O thread only post jobs and wait.

use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub struct JavaInvokeJob {
    pub key: String,
    pub arg: i32,
    /// `jobject` GlobalRef (receiver instance, or class for static).
    pub thiz: usize,
    pub art_method: usize,
    pub reply: SyncSender<JavaInvokeResult>,
}

#[derive(Debug)]
pub struct JavaInvokeResult {
    pub value: i32,
    pub error: Option<String>,
}

pub enum JsJob {
    Eval {
        script_id: u32,
        source: String,
        reply: SyncSender<Result<(), String>>,
    },
    /// Fire-and-forget eval (e.g. main-looper → JS callbacks).
    EvalAsync {
        source: String,
    },
    JavaInvoke(JavaInvokeJob),
    /// Host → script (Frida `script.post` / JS `recv`).
    HostPost {
        payload_json: String,
        data: Option<Vec<u8>>,
    },
    /// Frida-style `rpc.exports` call.
    RpcCall {
        call_id: u32,
        fn_name: String,
        args_json: String,
        reply: SyncSender<RpcInvokeResult>,
    },
}

#[derive(Debug)]
pub struct RpcInvokeResult {
    pub result_json: Option<String>,
    pub error: Option<String>,
}

type JobTx = Sender<JsJob>;

static JOB_TX: OnceLock<JobTx> = OnceLock::new();

/// Start the JS worker once. `boot` runs on the worker thread first (create QJS).
pub fn ensure_started(boot: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel::<JsJob>();
    if JOB_TX.set(tx).is_err() {
        return;
    }
    thread::Builder::new()
        .name("goauld-js-worker".into())
        .spawn(move || {
            boot();
            worker_loop(rx);
        })
        .expect("spawn goauld-js-worker");
}

fn worker_loop(rx: Receiver<JsJob>) {
    while let Ok(job) = rx.recv() {
        match job {
            JsJob::Eval {
                script_id,
                source,
                reply,
            } => {
                #[cfg(feature = "quickjs")]
                let r = crate::bindings::worker_eval(script_id, &source);
                #[cfg(not(feature = "quickjs"))]
                let r = {
                    let _ = (script_id, source);
                    Err("quickjs disabled".into())
                };
                let _ = reply.send(r);
            }
            JsJob::EvalAsync { source } => {
                #[cfg(feature = "quickjs")]
                {
                    let _ = crate::bindings::worker_eval(0, &source);
                }
                #[cfg(not(feature = "quickjs"))]
                {
                    let _ = source;
                }
            }
            JsJob::JavaInvoke(job) => {
                #[cfg(feature = "quickjs")]
                crate::bindings::worker_java_invoke(job);
                #[cfg(not(feature = "quickjs"))]
                {
                    let _ = job.reply.send(JavaInvokeResult {
                        value: job.arg.saturating_add(1000),
                        error: Some("quickjs disabled".into()),
                    });
                }
            }
            JsJob::HostPost { payload_json, data } => {
                #[cfg(feature = "quickjs")]
                crate::bindings::worker_deliver_post(&payload_json, data.as_deref());
                #[cfg(not(feature = "quickjs"))]
                {
                    let _ = (payload_json, data);
                }
            }
            JsJob::RpcCall {
                call_id,
                fn_name,
                args_json,
                reply,
            } => {
                #[cfg(feature = "quickjs")]
                {
                    let r = crate::bindings::worker_rpc_call(&fn_name, &args_json);
                    let _ = call_id;
                    let _ = reply.send(r);
                }
                #[cfg(not(feature = "quickjs"))]
                {
                    let _ = call_id;
                    let _ = reply.send(RpcInvokeResult {
                        result_json: None,
                        error: Some("quickjs disabled".into()),
                    });
                    let _ = (fn_name, args_json);
                }
            }
        }
    }
}

/// Post a script eval and wait for completion (or timeout).
pub fn submit_eval(script_id: u32, source: String, timeout: Duration) -> Result<(), String> {
    let tx = JOB_TX
        .get()
        .ok_or_else(|| "js worker not started".to_string())?;
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    tx.send(JsJob::Eval {
        script_id,
        source,
        reply: reply_tx,
    })
    .map_err(|_| "js worker gone".to_string())?;
    match reply_rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => Err("js eval timed out".into()),
    }
}

/// Fire-and-forget eval on the JS worker (safe to call from the Android main looper).
pub fn submit_eval_async(source: String) -> Result<(), String> {
    let tx = JOB_TX
        .get()
        .ok_or_else(|| "js worker not started".to_string())?;
    tx.send(JsJob::EvalAsync { source })
        .map_err(|_| "js worker gone".to_string())
}

/// Post a Java invoke job and wait up to `timeout` for the result.
pub fn submit_java_invoke(
    key: &str,
    arg: i32,
    thiz: usize,
    art_method: usize,
    timeout: Duration,
) -> Option<i32> {
    let tx = JOB_TX.get()?;
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let job = JavaInvokeJob {
        key: key.to_string(),
        arg,
        thiz,
        art_method,
        reply: reply_tx,
    };
    if tx.send(JsJob::JavaInvoke(job)).is_err() {
        return None;
    }
    match reply_rx.recv_timeout(timeout) {
        Ok(r) => {
            if let Some(e) = r.error {
                log::error!("js java invoke: {e}");
            }
            Some(r.value)
        }
        Err(_) => {
            log::error!("js java invoke timed out for {key}");
            None
        }
    }
}

pub fn is_started() -> bool {
    JOB_TX.get().is_some()
}

/// Deliver a host post to JS `recv` waiters (fire-and-forget).
pub fn submit_host_post(payload_json: String, data: Option<Vec<u8>>) -> Result<(), String> {
    let tx = JOB_TX
        .get()
        .ok_or_else(|| "js worker not started".to_string())?;
    tx.send(JsJob::HostPost { payload_json, data })
        .map_err(|_| "js worker gone".to_string())
}

/// Call `rpc.exports[fn_name](...args)` and wait for the JSON result.
pub fn submit_rpc_call(
    call_id: u32,
    fn_name: String,
    args_json: String,
    timeout: Duration,
) -> RpcInvokeResult {
    let Some(tx) = JOB_TX.get() else {
        return RpcInvokeResult {
            result_json: None,
            error: Some("js worker not started".into()),
        };
    };
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx
        .send(JsJob::RpcCall {
            call_id,
            fn_name,
            args_json,
            reply: reply_tx,
        })
        .is_err()
    {
        return RpcInvokeResult {
            result_json: None,
            error: Some("js worker gone".into()),
        };
    }
    match reply_rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => RpcInvokeResult {
            result_json: None,
            error: Some("rpc call timed out".into()),
        },
    }
}
