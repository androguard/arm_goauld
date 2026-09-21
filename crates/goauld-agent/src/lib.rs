//! Agent cdylib entry — ELF constructor starts the socket listener (§7).

use goauld_proto::{Hello, Message};
use goauld_script::ScriptEngine;
use std::io::{Read, Write};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
#[cfg(target_os = "android")]
use std::time::Duration;

/// Abstract Unix socket name: `goauld-agent-<pid>`.
pub fn socket_name(pid: u32) -> String {
    format!("goauld-agent-{pid}")
}

/// Compile-time JS engine baked into this agent (`quickjs` or `symbiote`).
pub fn js_engine_name() -> &'static str {
    if cfg!(feature = "symbiote") {
        "symbiote"
    } else if cfg!(feature = "quickjs") {
        "quickjs"
    } else {
        "none"
    }
}

/// Hello `version` string, including the JS engine so a host can tell which agent it attached to.
pub fn hello_version() -> String {
    format!("{} js={}", goauld_proto::version_info(), js_engine_name())
}

/// Start the agent listener once. The ELF constructor calls this; tests call it too
/// so a host-style attach does not depend on the ctor surviving the test linker.
pub fn start_agent_listener() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        init_logger();
        log::info!(
            "goauld agent constructor {} js={}",
            goauld_proto::version_info(),
            js_engine_name()
        );
        #[cfg(target_os = "android")]
        {
            // Best-effort early SDK probe (may be too early for JNI; Hello retries later).
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(200));
                let sdk = goauld_art_bridge::android_sdk_int_or_0();
                let rel = goauld_art_bridge::android_version().unwrap_or_else(|_| "?".into());
                if sdk != 0 {
                    log::info!("goauld runtime Android API {sdk} (release={rel})");
                }
            });
        }
        thread::spawn(|| {
            if let Err(e) = run_agent() {
                log::error!("goauld agent exited: {e}");
            }
        });
    });
}

#[ctor::ctor]
fn agent_init() {
    start_agent_listener();
}

/// Bionic does not export `__clear_cache`. Symbiote's JIT calls it after every
/// code emission; without a definition `dlopen` of this agent fails on Android.
#[cfg(all(target_os = "android", target_arch = "aarch64"))]
#[no_mangle]
pub unsafe extern "C" fn __clear_cache(start: *mut std::ffi::c_void, end: *mut std::ffi::c_void) {
    let start = start as usize;
    let end = end as usize;
    if start == 0 || end <= start {
        return;
    }
    let ctr: u64;
    core::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nomem, nostack));
    let dline = 4usize << ((ctr >> 16) & 15);
    let iline = 4usize << (ctr & 15);
    // CTR_EL0.IDC (bit 28): data-cache clean is not required for I-cache coherence.
    if (ctr & (1 << 28)) == 0 {
        let mut addr = start & !(dline - 1);
        while addr < end {
            core::arch::asm!("dc cvau, {addr}", addr = in(reg) addr, options(nostack));
            addr = addr.wrapping_add(dline);
        }
    }
    core::arch::asm!("dsb ish", options(nostack));
    // CTR_EL0.DIC (bit 29): instruction-cache invalidate is not required.
    if (ctr & (1 << 29)) == 0 {
        let mut addr = start & !(iline - 1);
        while addr < end {
            core::arch::asm!("ic ivau, {addr}", addr = in(reg) addr, options(nostack));
            addr = addr.wrapping_add(iline);
        }
        core::arch::asm!("dsb ish", options(nostack));
    }
    core::arch::asm!("isb", options(nostack));
}

fn init_logger() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("goauld"),
        );
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = env_logger_init();
    }
}

#[cfg(not(target_os = "android"))]
fn env_logger_init() {
    // Host test builds: silent unless RUST_LOG set by the test harness.
}

fn run_agent() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pid = std::process::id();
    let name = socket_name(pid);
    let engine = Arc::new(ScriptEngine::new());

    #[cfg(target_os = "android")]
    {
        listen_abstract_loop(&name, engine)?;
    }
    #[cfg(not(target_os = "android"))]
    {
        // Host: listen on a filesystem socket under /tmp for unit tests.
        let path = std::env::temp_dir().join(&name);
        let _ = std::fs::remove_file(&path);
        listen_path_loop(&path, engine)?;
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn listen_path_loop(
    path: &std::path::Path,
    engine: Arc<ScriptEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::net::UnixListener;
    let listener = UnixListener::bind(path)?;
    log::info!("goauld listening on {} {}", path.display(), goauld_proto::version_info());
    loop {
        let (mut stream, _) = listener.accept()?;
        log::info!("goauld host connected");
        let (tx, rx) = mpsc::channel::<Message>();
        engine.set_outbound(tx.clone());
        if let Err(e) = on_connected(&mut stream, engine.clone(), rx, tx) {
            log::warn!("goauld session ended: {e}");
        }
    }
}

#[cfg(target_os = "android")]
fn listen_abstract_loop(
    name: &str,
    engine: Arc<ScriptEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Android abstract namespace: sun_path[0] == '\0'.
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let bytes = name.as_bytes();
    addr.sun_path[0] = 0;
    for (i, b) in bytes.iter().enumerate() {
        addr.sun_path[i + 1] = *b as _;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len()) as u32;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    unsafe { libc::listen(fd, 4) };
    log::info!("goauld listening on abstract @{name} {}", goauld_proto::version_info());

    loop {
        let client_fd =
            unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            let err = std::io::Error::last_os_error();
            log::warn!("goauld accept failed: {err}");
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        let mut stream = unsafe { UnixStream::from_raw_fd(client_fd) };
        log::info!("goauld host connected");
        let (tx, rx) = mpsc::channel::<Message>();
        engine.set_outbound(tx.clone());
        if let Err(e) = on_connected(&mut stream, engine.clone(), rx, tx) {
            // Normal when the host disconnects after max-wait / Ctrl-C.
            log::warn!("goauld session ended: {e}");
        }
    }
}

fn on_connected(
    stream: &mut impl ReadWrite,
    engine: Arc<ScriptEngine>,
    rx: mpsc::Receiver<Message>,
    tx: mpsc::Sender<Message>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Hello
    #[cfg(target_os = "android")]
    let sdk = goauld_art_bridge::android_sdk_int_or_0();
    #[cfg(not(target_os = "android"))]
    let sdk = 0u32;
    #[cfg(target_os = "android")]
    let release = goauld_art_bridge::android_version().unwrap_or_else(|_| "?".into());
    #[cfg(not(target_os = "android"))]
    let release = "host".to_string();
    let ver = hello_version();
    log::info!("goauld hello version={ver} sdk_int={sdk} release={release}");
    let hello = Message::Hello(Hello {
        pid: std::process::id(),
        package: std::env::var("ANDROID_APP_PACKAGE").unwrap_or_else(|_| "unknown".into()),
        sdk_int: if sdk != 0 {
            sdk
        } else {
            std::env::var("SDK_INT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        },
        abi: "arm64-v8a".into(),
        version: ver,
    });
    write_msg(stream, &hello)?;

    // Outbound pump for this session only (Send + RpcReply share one writer).
    let mut stream_out = stream.try_clone_box()?;
    let pump = thread::spawn(move || {
        while let Ok(msg) = rx.recv() {
            if write_msg(&mut *stream_out, &msg).is_err() {
                break;
            }
        }
    });

    // Inbound loop until host disconnects.
    let result = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let msg = read_msg(stream)?;
            match msg {
                Message::ScriptLoad(s) => {
                    if let Err(e) = engine.load(s.script_id, s.source) {
                        log::error!("ScriptLoad: {e}");
                        let _ = tx.send(Message::Log(goauld_proto::LogMsg {
                            level: "error".into(),
                            message: format!("ScriptLoad: {e}"),
                        }));
                    }
                }
                Message::ScriptUnload(s) => {
                    let _ = engine.unload(s.script_id);
                }
                Message::Post {
                    script_id: _,
                    payload_json,
                    data,
                } => {
                    if let Err(e) = goauld_script::js_queue::submit_host_post(payload_json, data) {
                        log::error!("host post: {e}");
                    }
                }
                Message::RpcCall(c) => {
                    let r = goauld_script::js_queue::submit_rpc_call(
                        c.call_id,
                        c.fn_name,
                        c.args_json,
                        std::time::Duration::from_secs(30),
                    );
                    let reply = Message::RpcReply(goauld_proto::RpcReply {
                        call_id: c.call_id,
                        result_json: r.result_json,
                        error: r.error,
                    });
                    if tx.send(reply).is_err() {
                        break;
                    }
                }
                other => log::debug!("ignored inbound: {other:?}"),
            }
        }
        Ok(())
    })();

    drop(tx);
    drop(pump);
    result
}

trait ReadWrite: Read + Write + Send {
    fn try_clone_box(&self) -> std::io::Result<Box<dyn ReadWrite>>;
}

#[cfg(unix)]
impl ReadWrite for std::os::unix::net::UnixStream {
    fn try_clone_box(&self) -> std::io::Result<Box<dyn ReadWrite>> {
        Ok(Box::new(self.try_clone()?))
    }
}

fn write_msg(w: &mut dyn Write, msg: &Message) -> std::io::Result<()> {
    let bytes = msg.encode().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    w.write_all(&bytes)?;
    w.flush()
}

fn read_msg(r: &mut dyn Read) -> std::io::Result<Message> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let total = u32::from_le_bytes(len_buf) as usize;
    let mut rest = vec![0u8; total];
    r.read_exact(&mut rest)?;
    let mut frame = Vec::with_capacity(4 + total);
    frame.extend_from_slice(&len_buf);
    frame.extend_from_slice(&rest);
    Message::decode(&frame).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(all(test, unix, not(target_os = "android")))]
mod attach_tests {
    use super::{read_msg, socket_name, start_agent_listener, write_msg, Message};
    use std::io::ErrorKind;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::{Duration, Instant};

    fn expect_engine() -> &'static str {
        if cfg!(feature = "symbiote") {
            "symbiote"
        } else {
            "quickjs"
        }
    }

    fn expect_runtime() -> &'static str {
        if cfg!(feature = "symbiote") {
            "SYMBIOTE"
        } else {
            "QJS"
        }
    }

    #[test]
    fn agent_host_attach_roundtrip() {
        start_agent_listener();
        let path = std::env::temp_dir().join(socket_name(std::process::id()));
        let mut stream = None;
        let mut last = None;
        for _ in 0..50 {
            match UnixStream::connect(&path) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
        let mut stream = stream.unwrap_or_else(|| {
            panic!(
                "could not attach to agent socket {} ({})",
                path.display(),
                last.map(|e| e.to_string()).unwrap_or_else(|| "no error".into())
            )
        });
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();

        let hello = read_hello(&mut stream);
        match hello {
            Message::Hello(h) => {
                assert_eq!(h.pid, std::process::id());
                assert!(
                    h.version.contains(&format!("js={}", expect_engine())),
                    "hello version {:?} missing js={}",
                    h.version,
                    expect_engine()
                );
            }
            other => panic!("expected Hello, got {other:?}"),
        }

        let runtime = expect_runtime();
        let source = r#"
            (function() {
              try {
                var page = Memory.alloc(32);
                for (var i = 0; i < 8; i++) Memory.writeU32(page.add(i * 4), 0xD503201F);
                var listener = Interceptor.attach(page, { onEnter: function() {} });
                if (!listener || typeof listener.detach !== 'function') throw new Error('no listener');
                listener.detach();
                send({ type: 'agent-attach', runtime: Script.runtime, ok: true });
              } catch (e) {
                var msg = (e && e.message != null) ? String(e.message) : String(e);
                send({ type: 'agent-attach-err', err: msg, runtime: (typeof Script !== 'undefined' ? Script.runtime : 'none') });
              }
            })();
        "#;
        write_msg(
            &mut stream,
            &Message::ScriptLoad(goauld_proto::ScriptLoad {
                script_id: 1,
                source: source.into(),
            }),
        )
        .expect("ScriptLoad");

        let deadline = Instant::now() + Duration::from_secs(8);
        let mut payloads = Vec::new();
        while Instant::now() < deadline {
            match read_msg(&mut stream) {
                Ok(Message::Send { payload_json, .. }) => {
                    let done = payload_json.contains("agent-attach");
                    payloads.push(payload_json);
                    if done {
                        break;
                    }
                }
                Ok(Message::Log(l)) => payloads.push(format!("log:{}:{}", l.level, l.message)),
                Ok(other) => payloads.push(format!("msg:{other:?}")),
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    continue;
                }
                Err(e) => panic!("attach read failed: {e}; payloads={payloads:?}"),
            }
        }
        if let Some(err) = payloads.iter().find(|p| p.contains("agent-attach-err") || p.contains("ScriptLoad:")) {
            panic!("agent attach script failed ({runtime}): {err}; payloads={payloads:?}");
        }
        assert!(
            payloads.iter().any(|p| p.contains("agent-attach") && p.contains(runtime)),
            "missing agent-attach for {runtime}; payloads={payloads:?}"
        );
    }

    fn read_hello(stream: &mut UnixStream) -> Message {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match read_msg(stream) {
                Ok(msg) => return msg,
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    if Instant::now() > deadline {
                        panic!("timed out waiting for Hello: {e}");
                    }
                }
                Err(e) => panic!("hello read failed: {e}"),
            }
        }
    }
}
