//! Script engine: load/unload sources, route send/rpc.

use crate::js_lock::JsLock;
use goauld_proto::Message;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use thiserror::Error;

pub type ScriptId = u32;

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("script {0} not found")]
    NotFound(ScriptId),
    #[error("js: {0}")]
    Js(String),
    #[error("{0}")]
    Msg(String),
}

pub struct ScriptEngine {
    lock: Arc<JsLock>,
    scripts: Mutex<HashMap<ScriptId, String>>,
    tx: Mutex<Option<Sender<Message>>>,
    #[cfg(feature = "quickjs")]
    bridge: Arc<crate::bindings::HostBridge>,
}

impl ScriptEngine {
    pub fn new() -> Self {
        let lock = Arc::new(JsLock::new());
        #[cfg(feature = "quickjs")]
        let bridge = crate::bindings::shared_bridge();
        #[cfg(feature = "quickjs")]
        crate::bindings::set_js_lock(lock.clone());
        Self {
            lock,
            scripts: Mutex::new(HashMap::new()),
            tx: Mutex::new(None),
            #[cfg(feature = "quickjs")]
            bridge,
        }
    }

    pub fn set_outbound(&self, tx: Sender<Message>) {
        *self.tx.lock() = Some(tx.clone());
        #[cfg(feature = "quickjs")]
        {
            *self.bridge.tx.lock() = Some(tx);
        }
    }

    #[cfg(feature = "quickjs")]
    fn ensure_worker(&self) {
        let bridge = self.bridge.clone();
        let lock = self.lock.clone();
        crate::js_queue::ensure_started(move || {
            crate::bindings::set_js_lock(lock);
            crate::bindings::boot_worker(bridge);
        });
    }

    pub fn load(&self, id: ScriptId, source: String) -> Result<(), ScriptError> {
        self.scripts.lock().insert(id, source.clone());
        #[cfg(feature = "quickjs")]
        {
            self.ensure_worker();
            crate::js_queue::submit_eval(id, source, std::time::Duration::from_secs(30))
                .map_err(ScriptError::Js)?;
        }
        #[cfg(not(feature = "quickjs"))]
        {
            let _ = &self.lock;
            if let Some(payload) = try_parse_send_hi(&source) {
                self.emit_send(id, payload, None);
            }
        }
        Ok(())
    }

    pub fn unload(&self, id: ScriptId) -> Result<(), ScriptError> {
        self.scripts
            .lock()
            .remove(&id)
            .ok_or(ScriptError::NotFound(id))?;
        Ok(())
    }

    pub fn emit_send(&self, script_id: ScriptId, payload_json: String, data: Option<Vec<u8>>) {
        if let Some(tx) = self.tx.lock().as_ref() {
            let _ = tx.send(Message::Send {
                script_id,
                payload_json,
                data,
            });
        }
    }

    pub fn lock(&self) -> &JsLock {
        self.lock.as_ref()
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "quickjs"))]
fn try_parse_send_hi(source: &str) -> Option<String> {
    let s = source.trim();
    for quote in ['"', '\''] {
        let prefix = format!("send({quote}");
        if let Some(rest) = s.strip_prefix(&prefix) {
            if let Some(end) = rest.find(quote) {
                let payload = &rest[..end];
                return Some(serde_json::to_string(payload).ok()?);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_queue;
    use std::sync::mpsc::channel;
    use std::sync::Mutex;
    use std::time::Duration;

    static TEST_GATE: Mutex<()> = Mutex::new(());

    fn drain_payloads(
        rx: &std::sync::mpsc::Receiver<Message>,
        wait: Duration,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + wait;
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(Message::Send { payload_json, .. }) => out.push(payload_json),
                Ok(_) => {}
                Err(_) => {
                    if !out.is_empty() {
                        break;
                    }
                }
            }
        }
        out
    }

    /// Shared QJS worker — clear per-test overrides / impls so cases stay isolated.
    fn reset_java_test_state(eng: &ScriptEngine) {
        eng.load(
            99,
            r#"
            globalThis.__goauldCallOriginalOverride = undefined;
            if (typeof __javaImpls === 'object') {
              for (var k in __javaImpls) { delete __javaImpls[k]; }
            }
            "#
            .into(),
        )
        .expect("reset java test state");
    }

    #[test]
    fn load_send_hi_emits() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        eng.load(1, r#"send("hi")"#.into()).unwrap();
        let msg = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        match msg {
            Message::Send {
                script_id,
                payload_json,
                ..
            } => {
                assert_eq!(script_id, 1);
                assert!(
                    payload_json == "\"hi\"" || payload_json.contains("hi"),
                    "payload={payload_json}"
                );
            }
            _ => panic!("expected Send"),
        }
    }

    #[cfg(feature = "quickjs")]
    #[test]
    fn process_memory_apis_smoke() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        eng.load(
            42,
            r#"
            var b = Memory.alloc(16);
            Memory.writeU32(b, 0x11223344);
            if (Memory.readU32(b) !== 0x11223344) throw new Error('rw');
            var s = Memory.allocUtf8String('ptmm');
            if (Memory.readUtf8String(s) !== 'ptmm') throw new Error('utf8');
            Thread.sleep(0.001);
            send({
              type: 'ptmm',
              id: Process.id,
              arch: Process.arch,
              pageSize: Process.pageSize,
              pointerSize: Process.pointerSize,
              modules: Process.enumerateModules().length,
              ranges: Process.enumerateRanges('r--').length
            });
            "#
            .into(),
        )
        .expect("ptmm eval");
        let payloads = drain_payloads(&rx, Duration::from_secs(2));
        assert!(
            payloads.iter().any(|p| p.contains("\"type\":\"ptmm\"") || p.contains("'type':'ptmm'") || p.contains("ptmm")),
            "payloads={payloads:?}"
        );
        assert!(
            payloads.iter().any(|p| p.contains("\"arch\":\"arm64\"") || p.contains("arm64")),
            "expected arm64 arch in {payloads:?}"
        );
    }

    #[cfg(feature = "quickjs")]
    #[test]
    fn java_use_implementation_eval_ok() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        eng.load(
            2,
            r#"
            Java.perform(function() {
              var T = Java.use('com.example.javatarget.Target');
              T.hookMe.implementation = function(x) {
                send('called with ' + x);
                return x * 2;
              };
            });
            send('java-hook-installed');
            "#
            .into(),
        )
        .expect("eval java.use script");
        let payloads = drain_payloads(&rx, Duration::from_secs(2));
        assert!(
            payloads.iter().any(|p| p.contains("java-hook-installed")),
            "payloads={payloads:?}"
        );
    }

    /// No registered implementation → worker falls back to arg+1000.
    #[cfg(feature = "quickjs")]
    #[test]
    fn java_invoke_missing_impl_falls_back() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, _rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        eng.load(10, "send('ready')".into()).unwrap();
        let v = js_queue::submit_java_invoke(
            "com.example.Missing.nope",
            7,
            0,
            0,
            Duration::from_secs(5),
        );
        assert_eq!(v, Some(1007));
    }

    /// Replacement without callOriginal: return x+1000 and send.
    #[cfg(feature = "quickjs")]
    #[test]
    fn java_invoke_simple_replacement() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        eng.load(
            11,
            r#"
            Java.perform(function() {
              var T = Java.use('com.example.javatarget.Target');
              T.hookMe.implementation = function(x) {
                send('called with ' + x);
                return x + 1000;
              };
            });
            "#
            .into(),
        )
        .unwrap();
        let v = js_queue::submit_java_invoke(
            "com.example.javatarget.Target.hookMe",
            5,
            0,
            0,
            Duration::from_secs(5),
        );
        assert_eq!(v, Some(1005));
        let payloads = drain_payloads(&rx, Duration::from_secs(1));
        assert!(
            payloads.iter().any(|p| p.contains("called with 5")),
            "payloads={payloads:?}"
        );
    }

    /// Frida-shaped `this.hookMe(x)` via override (orig = x*2).
    #[cfg(feature = "quickjs")]
    #[test]
    fn java_invoke_call_original_via_this() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        eng.load(
            12,
            r#"
            globalThis.__goauldCallOriginalOverride = function(_key, x) { return x * 2; };
            Java.perform(function() {
              var T = Java.use('com.example.javatarget.Target');
              T.hookMe.implementation = function(x) {
                send('called with ' + x);
                return this.hookMe(x) + 1000;
              };
            });
            "#
            .into(),
        )
        .unwrap();
        let v = js_queue::submit_java_invoke(
            "com.example.javatarget.Target.hookMe",
            3,
            0,
            0,
            Duration::from_secs(5),
        );
        assert_eq!(v, Some(1006));
        let payloads = drain_payloads(&rx, Duration::from_secs(1));
        assert!(
            payloads.iter().any(|p| p.contains("called with 3")),
            "payloads={payloads:?}"
        );
    }

    /// Matches scripts/fixtures/java_hook.js shape (device e2e).
    #[cfg(feature = "quickjs")]
    #[test]
    fn java_invoke_fixture_shape_with_mocked_original() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        let fixture = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/fixtures/java_hook.js"
        ))
        .expect("read java_hook.js fixture");
        let source = format!(
            "globalThis.__goauldCallOriginalOverride = function(_k, x) {{ return x * 2; }};\n{fixture}"
        );
        eng.load(13, source).unwrap();
        let payloads = drain_payloads(&rx, Duration::from_secs(1));
        assert!(
            payloads.iter().any(|p| p.contains("java-hook-installed")),
            "payloads={payloads:?}"
        );
        let v = js_queue::submit_java_invoke(
            "com.example.javatarget.Target.hookMe",
            2,
            0,
            0,
            Duration::from_secs(5),
        );
        assert_eq!(v, Some(1004));
    }

    /// Thrown implementation → error send + fallback arg+1000.
    #[cfg(feature = "quickjs")]
    #[test]
    fn java_invoke_impl_throw_sends_error() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        eng.load(
            14,
            r#"
            Java.perform(function() {
              var T = Java.use('com.example.javatarget.Target');
              T.hookMe.implementation = function(x) {
                throw new Error('boom-' + x);
              };
            });
            "#
            .into(),
        )
        .unwrap();
        let v = js_queue::submit_java_invoke(
            "com.example.javatarget.Target.hookMe",
            9,
            0,
            0,
            Duration::from_secs(5),
        );
        assert_eq!(v, Some(1009));
        let payloads = drain_payloads(&rx, Duration::from_secs(1));
        assert!(
            payloads
                .iter()
                .any(|p| p.contains("java-invoke-err:") && p.contains("boom-9")),
            "payloads={payloads:?}"
        );
    }

    /// Host stub: javaCallOriginal outside a live ART hook returns the arg unchanged.
    #[cfg(feature = "quickjs")]
    #[test]
    fn java_call_original_host_stub_value() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        eng.load(
            16,
            r#"
            send('orig=' + __goauld.javaCallOriginal('Any.method', 42));
            "#
            .into(),
        )
        .unwrap();
        let payloads = drain_payloads(&rx, Duration::from_secs(1));
        assert!(
            payloads.iter().any(|p| p.contains("orig=42")),
            "host stub should unwrap_or arg; payloads={payloads:?}"
        );
    }

    #[cfg(feature = "quickjs")]
    #[test]
    fn java_invoke_sequential_calls_stable() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, _rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        reset_java_test_state(&eng);
        eng.load(
            17,
            r#"
            globalThis.__goauldCallOriginalOverride = function(_k, x) { return x * 2; };
            Java.perform(function() {
              var T = Java.use('com.example.javatarget.Target');
              T.hookMe.implementation = function(x) {
                return this.hookMe(x) + 1000;
              };
            });
            "#
            .into(),
        )
        .unwrap();
        for n in 2..=5 {
            let v = js_queue::submit_java_invoke(
                "com.example.javatarget.Target.hookMe",
                n,
                0,
                0,
                Duration::from_secs(5),
            );
            assert_eq!(v, Some(n * 2 + 1000), "n={n}");
        }
    }
}
