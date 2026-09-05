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

#[ctor::ctor]
fn agent_init() {
    // Avoid double-init if the loader invokes constructors more than once.
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        init_logger();
        log::info!("goauld agent constructor {}", goauld_proto::version_info());
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
    let ver = goauld_proto::version_info();
    #[cfg(target_os = "android")]
    let sdk = goauld_art_bridge::android_sdk_int_or_0();
    #[cfg(not(target_os = "android"))]
    let sdk = 0u32;
    #[cfg(target_os = "android")]
    let release = goauld_art_bridge::android_version().unwrap_or_else(|_| "?".into());
    #[cfg(not(target_os = "android"))]
    let release = "host".to_string();
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
