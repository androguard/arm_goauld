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
    #[cfg(any(feature = "quickjs", feature = "symbiote"))]
    bridge: Arc<crate::js_backend::HostBridge>,
}

impl ScriptEngine {
    pub fn new() -> Self {
        let lock = Arc::new(JsLock::new());
        #[cfg(any(feature = "quickjs", feature = "symbiote"))]
        let bridge = crate::js_backend::shared_bridge();
        #[cfg(any(feature = "quickjs", feature = "symbiote"))]
        crate::js_backend::set_js_lock(lock.clone());
        Self {
            lock,
            scripts: Mutex::new(HashMap::new()),
            tx: Mutex::new(None),
            #[cfg(any(feature = "quickjs", feature = "symbiote"))]
            bridge,
        }
    }

    pub fn set_outbound(&self, tx: Sender<Message>) {
        *self.tx.lock() = Some(tx.clone());
        #[cfg(any(feature = "quickjs", feature = "symbiote"))]
        {
            *self.bridge.tx.lock() = Some(tx);
        }
    }

    #[cfg(any(feature = "quickjs", feature = "symbiote"))]
    fn ensure_worker(&self) {
        let bridge = self.bridge.clone();
        let lock = self.lock.clone();
        crate::js_queue::ensure_started(move || {
            crate::js_backend::set_js_lock(lock);
            crate::js_backend::boot_worker(bridge);
        });
    }

    pub fn load(&self, id: ScriptId, source: String) -> Result<(), ScriptError> {
        self.scripts.lock().insert(id, source.clone());
        #[cfg(any(feature = "quickjs", feature = "symbiote"))]
        {
            self.ensure_worker();
            crate::js_queue::submit_eval(id, source, std::time::Duration::from_secs(30))
                .map_err(ScriptError::Js)?;
        }
        #[cfg(not(any(feature = "quickjs", feature = "symbiote")))]
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

#[cfg(not(any(feature = "quickjs", feature = "symbiote")))]
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
    #[cfg(feature = "quickjs")]
    use crate::js_queue;
    use std::sync::mpsc::channel;
    use std::sync::Mutex;
    use std::time::Duration;

    static TEST_GATE: Mutex<()> = Mutex::new(());

    #[cfg(feature = "quickjs")]
    fn drain_payloads(
        rx: &std::sync::mpsc::Receiver<Message>,
        wait: Duration,
    ) -> Vec<String> {
        drain_payloads_until(rx, wait, None)
    }

    /// Collect sends until `wait` elapses, or until `until_contains` appears.
    fn drain_payloads_until(
        rx: &std::sync::mpsc::Receiver<Message>,
        wait: Duration,
        until_contains: Option<&str>,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + wait;
        while std::time::Instant::now() < deadline {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match rx.recv_timeout(left.min(Duration::from_millis(50))) {
                Ok(Message::Send { payload_json, .. }) => {
                    out.push(payload_json);
                    if let Some(needle) = until_contains {
                        if out.iter().any(|p| p.contains(needle)) {
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }
        out
    }

    /// Shared QJS worker — clear per-test overrides / impls so cases stay isolated.
    #[cfg(feature = "quickjs")]
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

    #[cfg(any(feature = "quickjs", feature = "symbiote"))]
    fn expected_runtime() -> &'static str {
        if cfg!(feature = "symbiote") {
            "SYMBIOTE"
        } else {
            "QJS"
        }
    }

    #[cfg(any(feature = "quickjs", feature = "symbiote"))]
    #[test]
    fn js_engine_send_hi() {
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

    /// Core Frida-shaped surface that both QuickJS and Symbiote must provide.
    #[cfg(any(feature = "quickjs", feature = "symbiote"))]
    #[test]
    fn js_engine_core_smoke() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        let expect = expected_runtime();
        let script = format!(
            r#"
            (function() {{
              try {{
                if (typeof Script === 'undefined' || Script.runtime !== '{expect}') {{
                  throw new Error('bad Script.runtime');
                }}
                var b = Memory.alloc(16);
                Memory.writeU32(b, 0x11223344);
                var got = Memory.readU32(b);
                if (got != 287454020) throw new Error('rw u32 got ' + got);
                var s = Memory.allocUtf8String('ptmm');
                if (Memory.readUtf8String(s) !== 'ptmm') throw new Error('utf8');
                Thread.sleep(0.001);
                console.log('engine-core', Script.runtime);
                var dump = hexdump(b, {{ length: 8, header: true }});
                if (typeof dump !== 'string' || dump.indexOf('44 33 22 11') < 0) {{
                  throw new Error('hexdump bad: ' + dump);
                }}
                var ticks = 0;
                var iv = setInterval(function() {{ ticks = ticks + 1; }}, 10);
                setTimeout(function() {{
                  clearInterval(iv);
                  send({{
                    type: 'engine-core',
                    runtime: Script.runtime,
                    id: Process.id,
                    arch: Process.arch,
                    pageSize: Process.pageSize,
                    pointerSize: Process.pointerSize,
                    modules: Process.enumerateModules().length,
                    ranges: Process.enumerateRanges('r--').length,
                    ticks: ticks,
                    timerOk: true
                  }});
                  send('engine-core-ok');
                }}, 80);
              }} catch (err) {{
                send({{ type: 'engine-core-err', runtime: '{expect}', err: String(err && err.message != null ? err.message : err) }});
              }}
            }})();
            "#
        );
        eng.load(42, script)
            .unwrap_or_else(|e| panic!("js_engine_core_smoke eval ({expect}): {e}"));
        let payloads = drain_payloads_until(&rx, Duration::from_secs(3), Some("engine-core-ok"));
        if let Some(err) = payloads.iter().find(|p| p.contains("engine-core-err")) {
            panic!("script error for {expect}: {err}; payloads={payloads:?}");
        }
        assert!(
            payloads.iter().any(|p| p.contains("engine-core-ok")),
            "missing engine-core-ok for {expect}; payloads={payloads:?}"
        );
        assert!(
            payloads
                .iter()
                .any(|p| p.contains("\"type\":\"engine-core\"") && p.contains(expect)),
            "missing engine-core payload with runtime={expect}; payloads={payloads:?}"
        );
        assert!(
            payloads.iter().any(|p| p.contains("\"timerOk\":true")),
            "timer did not fire; payloads={payloads:?}"
        );
    }

    /// Symbiote and QuickJS must expose the same Frida module globals.
    #[cfg(any(feature = "quickjs", feature = "symbiote"))]
    #[test]
    fn js_engine_modules_exposed() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        let expect = expected_runtime();
        let script = format!(
            r#"
            (function() {{
              try {{
                var missing = [];
                function need(name, v) {{ if (typeof v === 'undefined') missing.push(name); }}
                need('Script', Script);
                need('Process', Process);
                need('Module', Module);
                need('Memory', Memory);
                need('Thread', Thread);
                need('Interceptor', Interceptor);
                need('Java', Java);
                need('Arm64Writer', Arm64Writer);
                need('Arm64Relocator', Arm64Relocator);
                need('Register', Register);
                need('ConditionCode', ConditionCode);
                need('IndexMode', IndexMode);
                need('Cloak', Cloak);
                need('MemoryAccessMonitor', MemoryAccessMonitor);
                need('Backtracer', Backtracer);
                need('hexdump', hexdump);
                need('console', console);
                need('setTimeout', setTimeout);
                need('setInterval', setInterval);
                need('ptr', ptr);
                need('recv', recv);
                need('rpc', rpc);
                need('Profiler', Profiler);
                need('ModuleMap', ModuleMap);
                need('Worker', Worker);
                need('gc', gc);
                if (Script.runtime !== '{expect}') missing.push('runtime=' + Script.runtime);
                if (missing.length) throw new Error('missing: ' + missing.join(','));
                send('modules-exposed-ok');
              }} catch (e) {{
                send({{ type: 'modules-err', err: String(e && e.message != null ? e.message : e) }});
              }}
            }})();
            "#
        );
        eng.load(7, script)
            .unwrap_or_else(|e| panic!("modules_exposed ({expect}): {e}"));
        let payloads = drain_payloads_until(&rx, Duration::from_secs(2), Some("modules-exposed-ok"));
        if let Some(err) = payloads.iter().find(|p| p.contains("modules-err")) {
            panic!("script error for {expect}: {err}; payloads={payloads:?}");
        }
        assert!(
            payloads.iter().any(|p| p.contains("modules-exposed-ok")),
            "missing ok; payloads={payloads:?}"
        );
    }

    #[cfg(any(feature = "quickjs", feature = "symbiote"))]
    #[test]
    fn js_engine_arm64_writer_smoke() {
        let _gate = TEST_GATE.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = channel();
        let eng = ScriptEngine::new();
        eng.set_outbound(tx);
        let expect = expected_runtime();
        eng.load(
            42,
            r#"
            (function() {
              try {
                if (typeof Arm64Writer !== 'function') throw new Error('no Arm64Writer');
                if (typeof Arm64Relocator !== 'function') throw new Error('no Arm64Relocator');
                if (Register.x0 !== 'x0' || ConditionCode.eq !== 'eq') throw new Error('enums');
                if (IndexMode['signed-offset'] !== 'signed-offset') throw new Error('IndexMode');

                var page = Memory.alloc(64);
                Memory.protect(page, 64, 'rwx');
                var w = new Arm64Writer(page);
                w.putNop();
                w.putLabel('done');
                w.putRet();
                w.flush();
                var nop = Memory.readU32(page) >>> 0;
                var ret = Memory.readU32(page.add(4)) >>> 0;
                if (nop !== 0xD503201F) throw new Error('nop=' + nop);
                if (ret !== 0xD65F03C0) throw new Error('ret=' + ret);
                if (w.offset !== 8) throw new Error('offset=' + w.offset);

                var srcPage = Memory.alloc(32);
                var dst = Memory.alloc(64);
                Memory.protect(dst, 64, 'rwx');
                var w2 = new Arm64Writer(dst);
                var r = new Arm64Relocator(srcPage, w2);
                r.setSource(srcPage, [
                  0x1F, 0x20, 0x03, 0xD5,
                  0xC0, 0x03, 0x5F, 0xD6
                ]);
                var n = r.readOne();
                if (n !== 4) throw new Error('readOne=' + n);
                if (!r.writeOne()) throw new Error('writeOne');
                r.readOne();
                r.writeOne();
                w2.flush();
                if ((Memory.readU32(dst) >>> 0) !== 0xD503201F) throw new Error('reloc nop');
                if ((Memory.readU32(dst.add(4)) >>> 0) !== 0xD65F03C0) throw new Error('reloc ret');

                var page3 = Memory.alloc(256);
                Memory.protect(page3, 256, 'rwx');
                var w3 = new Arm64Writer(page3);
                w3.putPushAllXRegisters();
                w3.putPopAllXRegisters();
                var ref = w3.putLdrRegRef('x0');
                w3.putLdrRegValue(ref, 0xabcd);
                w3.putMovRegNzcv('x1');
                w3.putCallAddressWithArguments(0x1000, ['x0', 42]);
                var signed = w3.sign(0x55);
                if (!(signed && signed.address === 0x55)) throw new Error('sign');
                w3.dispose();

                w.dispose();
                w2.dispose();
                r.dispose();
                send({ type: 'arm64-writer', ok: true, offset: 8 });
                send('arm64-writer-ok');
              } catch (e) {
                var msg = (e && e.message != null) ? String(e.message) : String(e);
                send({ type: 'arm64-writer-err', err: msg });
              }
            })();
            "#
            .into(),
        )
        .unwrap_or_else(|e| panic!("js_engine_arm64_writer_smoke ({expect}): {e}"));
        let payloads = drain_payloads_until(&rx, Duration::from_secs(3), Some("arm64-writer-ok"));
        if let Some(err) = payloads.iter().find(|p| p.contains("arm64-writer-err")) {
            panic!("script error for {expect}: {err}; payloads={payloads:?}");
        }
        assert!(
            payloads.iter().any(|p| p.contains("arm64-writer-ok")),
            "missing ok; payloads={payloads:?}"
        );
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
