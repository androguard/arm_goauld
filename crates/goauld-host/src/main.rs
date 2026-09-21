//! goauld host CLI (desktop).
//!
//! Injection / syscall tracing is **never** done with ptrace from this process.
//! The host pushes on-device binaries via adb and runs them on the phone.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use goauld_proto::{Message, RpcCall, ScriptLoad};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const DEVICE_DIR: &str = "/data/local/tmp/goauld";
const DEVICE_INJECTOR: &str = "/data/local/tmp/goauld/goauld-injector";
const DEVICE_AGENT: &str = "/data/local/tmp/goauld/libgoauld_agent.so";

#[derive(Parser, Debug)]
#[command(
    name = "goauld",
    about = "Android/arm64 dynamic instrumentation toolkit",
    version
)]
struct Cli {
    #[arg(long, global = true)]
    serial: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List processes on the device (`adb shell ps`).
    Ps,
    /// Push on-device injector + agent .so and ptrace-inject into a target.
    Inject {
        #[arg(long, conflicts_with = "package")]
        pid: Option<i32>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        injector: PathBuf,
        #[arg(long)]
        agent: PathBuf,
        #[arg(long)]
        stage_into_app: bool,
    },
    /// Deploy injector + agent to the device without injecting.
    Deploy {
        #[arg(long)]
        injector: PathBuf,
        #[arg(long)]
        agent: PathBuf,
    },
    /// Connect to an already-injected agent, or attach helpers (java / syscall).
    ///
    /// Plain: `attach --pid … --script …`  
    /// Android API trace (agent required): `attach java --pid …`  
    /// Syscall trace (injector only, no agent): `attach syscall --pid …`
    Attach {
        #[command(subcommand)]
        kind: Option<AttachKind>,
        #[arg(long, default_value = "27042")]
        port: u16,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        script: Option<PathBuf>,
        #[arg(long, default_value = "0")]
        max_wait_secs: u64,
        #[arg(long)]
        expect_send: Option<String>,
    },
    /// Live tracing helpers (syscalls / Android+Java API).
    Trace {
        #[command(subcommand)]
        kind: TraceCmd,
    },
    /// Stress agent↔host `send()` throughput against java-target and measure APK impact.
    Stress {
        #[arg(long, default_value = "com.example.javatarget")]
        package: String,
        #[arg(long, default_value = "dist/android-arm64/goauld-injector")]
        injector: PathBuf,
        #[arg(long, default_value = "dist/android-arm64/libgoauld_agent.so")]
        agent: PathBuf,
        #[arg(long)]
        stage_into_app: bool,
        #[arg(long, default_value = "27047")]
        port: u16,
        /// `flood` = unidirectional send(); `frida` = send/recv ping-pong + rpc.exports.
        #[arg(long, default_value = "flood")]
        mode: String,
        /// Number of stress messages / ping-pong rounds.
        #[arg(long, default_value = "2000")]
        count: u64,
        /// Extra pad / binary bytes per message.
        #[arg(long, default_value = "64")]
        payload: u64,
        /// Seconds of apk-tick sampling before the flood (flood mode).
        #[arg(long, default_value = "1")]
        baseline_secs: u64,
        /// Max seconds to wait for completion after ScriptLoad.
        #[arg(long, default_value = "60")]
        max_wait_secs: u64,
        /// RPC calls after ping-pong (frida mode).
        #[arg(long, default_value = "200")]
        rpc_count: u64,
        #[arg(long, default_value_t = true)]
        restart: bool,
        #[arg(long, default_value = "")]
        activity: String,
    },
}

/// Optional `attach` subcommands.
#[derive(Subcommand, Debug)]
enum AttachKind {
    /// Trace Android framework Java APIs on a live agent (no inject / restart).
    Java {
        #[arg(long, default_value = "27045")]
        port: u16,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        package: Option<String>,
        /// Seconds to listen for `android-api` events after install.
        #[arg(long, default_value = "20")]
        max_wait_secs: u64,
        #[arg(long)]
        script: Option<PathBuf>,
        /// Package prefixes to include (`android.,androidx.,java.`). Empty = defaults.
        #[arg(long, default_value = "")]
        filter: String,
        /// Cap emitted android-api events (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_events: u64,
        /// Optional Technique-A hooks: `Class.method` or `Class.method:(I)I` (comma-separated).
        #[arg(long, default_value = "")]
        java_hooks: String,
    },
    /// Trace syscalls in a running process via on-device `PTRACE_SYSCALL` (no agent `.so`).
    ///
    /// Example: `goauld attach syscall --pid 16785 --max-events 400 --max-wait-secs 60`
    #[command(name = "syscall", visible_alias = "syscalls")]
    Syscall {
        #[arg(long, conflicts_with = "package")]
        pid: Option<i32>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long, default_value = "dist/android-arm64/goauld-injector")]
        injector: PathBuf,
        /// How long to trace (same as `trace syscalls --duration-secs`).
        #[arg(long, default_value = "15")]
        max_wait_secs: u64,
        /// Alias for `--max-wait-secs` (matches `trace syscalls` naming).
        #[arg(long)]
        duration_secs: Option<u64>,
        #[arg(long, default_value = "0")]
        max_events: u64,
        #[arg(long, default_value = "")]
        filter: String,
        #[arg(long)]
        enter_only: bool,
    },
}

#[derive(Subcommand, Debug)]
enum TraceCmd {
    /// Trace all (or filtered) syscalls via on-device `PTRACE_SYSCALL`.
    Syscalls {
        #[arg(long, conflicts_with = "package")]
        pid: Option<i32>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long, default_value = "dist/android-arm64/goauld-injector")]
        injector: PathBuf,
        /// Seconds to trace on device.
        #[arg(long, default_value = "15")]
        duration_secs: u64,
        #[arg(long, default_value = "0")]
        max_events: u64,
        /// Comma-separated name substrings (`openat,connect,write`).
        #[arg(long, default_value = "")]
        filter: String,
        #[arg(long)]
        enter_only: bool,
    },
    /// Trace Android framework Java APIs ([API reference](https://developer.android.com/reference))
    /// via ART `ArtMethod::Invoke`, plus optional Technique-A `Java.use` hooks.
    Java {
        #[arg(long, conflicts_with = "package")]
        pid: Option<i32>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long, default_value = "dist/android-arm64/goauld-injector")]
        injector: PathBuf,
        #[arg(long, default_value = "dist/android-arm64/libgoauld_agent.so")]
        agent: PathBuf,
        #[arg(long)]
        stage_into_app: bool,
        #[arg(long, default_value = "27045")]
        port: u16,
        /// Seconds to listen for `send()` events after install.
        #[arg(long, default_value = "20")]
        max_wait_secs: u64,
        /// Optional path to a custom trace script (default: built-in fixture).
        #[arg(long)]
        script: Option<PathBuf>,
        /// Package prefixes to include (`android.,androidx.,java.`). Empty = defaults.
        #[arg(long, default_value = "")]
        filter: String,
        /// Cap emitted android-api events (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_events: u64,
        /// Optional Technique-A hooks: `Class.method` or `Class.method:(I)I` (comma-separated).
        #[arg(long, default_value = "")]
        java_hooks: String,
        /// Force-stop + launch the package before inject so a fresh agent listens.
        /// Disable with `--no-restart` when reusing a live agent session.
        #[arg(long, default_value_t = true)]
        restart: bool,
        /// Skip inject — only attach and load the trace script (agent must already be present).
        #[arg(long)]
        no_inject: bool,
        /// Explicit activity for `--restart` (`pkg/.Activity`). Empty → launcher via monkey.
        #[arg(long, default_value = "")]
        activity: String,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    // Skip noisy banner for `--version` / `--help` (clap exits before main on those).
    eprintln!("goauld-host {}", goauld_proto::version_info());
    let serial = cli.serial.as_deref();
    match cli.cmd {
        Cmd::Ps => cmd_ps(serial)?,
        Cmd::Inject {
            pid,
            package,
            injector,
            agent,
            stage_into_app,
        } => cmd_inject(serial, pid, package.as_deref(), &injector, &agent, stage_into_app)?,
        Cmd::Deploy { injector, agent } => {
            deploy(serial, &injector, &agent)?;
            println!("deployed to {DEVICE_DIR}/");
        }
        Cmd::Attach {
            kind,
            port,
            pid,
            script,
            max_wait_secs,
            expect_send,
        } => match kind {
            Some(AttachKind::Java {
                port,
                pid,
                package,
                max_wait_secs,
                script,
                filter,
                max_events,
                java_hooks,
            }) => cmd_attach_java(
                serial,
                port,
                pid,
                package.as_deref(),
                max_wait_secs,
                script.as_deref(),
                &filter,
                max_events,
                &java_hooks,
            )?,
            Some(AttachKind::Syscall {
                pid,
                package,
                injector,
                max_wait_secs,
                duration_secs,
                max_events,
                filter,
                enter_only,
            }) => {
                let duration = duration_secs.unwrap_or(max_wait_secs);
                cmd_trace_syscalls(
                    serial,
                    pid,
                    package.as_deref(),
                    &injector,
                    duration,
                    max_events,
                    &filter,
                    enter_only,
                )?
            }
            None => cmd_attach(
                serial,
                port,
                pid,
                script.as_deref(),
                max_wait_secs,
                expect_send.as_deref(),
                None,
                /*continue_after_expect*/ false,
            )?,
        },
        Cmd::Trace { kind } => match kind {
            TraceCmd::Syscalls {
                pid,
                package,
                injector,
                duration_secs,
                max_events,
                filter,
                enter_only,
            } => cmd_trace_syscalls(
                serial,
                pid,
                package.as_deref(),
                &injector,
                duration_secs,
                max_events,
                &filter,
                enter_only,
            )?,
            TraceCmd::Java {
                pid,
                package,
                injector,
                agent,
                stage_into_app,
                port,
                max_wait_secs,
                script,
                filter,
                max_events,
                java_hooks,
                restart,
                no_inject,
                activity,
            } => cmd_trace_java(
                serial,
                pid,
                package.as_deref(),
                &injector,
                &agent,
                stage_into_app,
                port,
                max_wait_secs,
                script.as_deref(),
                &filter,
                max_events,
                &java_hooks,
                restart,
                no_inject,
                activity.as_str(),
            )?,
        },
        Cmd::Stress {
            package,
            injector,
            agent,
            stage_into_app,
            port,
            mode,
            count,
            payload,
            baseline_secs,
            max_wait_secs,
            rpc_count,
            restart,
            activity,
        } => {
            if mode.eq_ignore_ascii_case("frida") || mode.eq_ignore_ascii_case("comm") {
                cmd_stress_frida(
                    serial,
                    &package,
                    &injector,
                    &agent,
                    stage_into_app,
                    port,
                    count,
                    payload,
                    rpc_count,
                    max_wait_secs,
                    restart,
                    activity.as_str(),
                )?;
            } else {
                cmd_stress(
                    serial,
                    &package,
                    &injector,
                    &agent,
                    stage_into_app,
                    port,
                    count,
                    payload,
                    baseline_secs,
                    max_wait_secs,
                    restart,
                    activity.as_str(),
                )?;
            }
        }
    }
    Ok(())
}

fn adb(serial: Option<&str>) -> Command {
    let mut c = Command::new("adb");
    if let Some(s) = serial {
        c.args(["-s", s]);
    }
    c
}

/// Ensure `tcp:{port}` forwards to `localabstract:{name}`.
///
/// Skips remove+add when the forward is already correct — each adb round-trip is
/// ~10–20 ms on emulator and dominated script-load ping before this change.
fn ensure_adb_forward(serial: Option<&str>, port: u16, abstract_name: &str) -> Result<()> {
    let spec = format!("tcp:{port}");
    let local = format!("localabstract:{abstract_name}");
    let listed = adb(serial).args(["forward", "--list"]).output()?;
    let list = String::from_utf8_lossy(&listed.stdout);
    let already = list.lines().any(|line| {
        let parts: Vec<_> = line.split_whitespace().collect();
        // serial tcp:PORT localabstract:NAME
        parts.len() >= 3 && parts[1] == spec && parts[2] == local
    });
    if already {
        return Ok(());
    }
    let _ = adb(serial).args(["forward", "--remove", &spec]).status();
    eprintln!("adb forward {spec} {local}");
    run_checked(adb(serial).args(["forward", &spec, &local]))?;
    Ok(())
}

fn cmd_ps(serial: Option<&str>) -> Result<()> {
    let out = adb(serial).args(["shell", "ps", "-A"]).output()?;
    if !out.status.success() {
        bail!("adb shell ps failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

fn deploy(serial: Option<&str>, injector: &Path, agent: &Path) -> Result<()> {
    if !injector.exists() {
        bail!("injector not found: {}", injector.display());
    }
    if !agent.exists() {
        bail!("agent .so not found: {}", agent.display());
    }
    let status = adb(serial)
        .args(["shell", "mkdir", "-p", DEVICE_DIR])
        .status()?;
    if !status.success() {
        bail!("mkdir {DEVICE_DIR} failed");
    }
    run_checked(adb(serial).args(["push"]).arg(injector).arg(DEVICE_INJECTOR))?;
    run_checked(adb(serial).args(["push"]).arg(agent).arg(DEVICE_AGENT))?;
    run_checked(adb(serial).args(["shell", "chmod", "755", DEVICE_INJECTOR]))?;
    run_checked(adb(serial).args(["shell", "chmod", "644", DEVICE_AGENT]))?;
    Ok(())
}

fn deploy_injector_only(serial: Option<&str>, injector: &Path) -> Result<()> {
    if !injector.exists() {
        bail!("injector not found: {}", injector.display());
    }
    let _ = adb(serial)
        .args(["shell", "mkdir", "-p", DEVICE_DIR])
        .status()?;
    run_checked(adb(serial).args(["push"]).arg(injector).arg(DEVICE_INJECTOR))?;
    run_checked(adb(serial).args(["shell", "chmod", "755", DEVICE_INJECTOR]))?;
    Ok(())
}

fn shell_root(serial: Option<&str>, remote: &str) -> Result<()> {
    let script = format!("su -c '{remote}'");
    eprintln!("on-device: {script}");
    let out = adb(serial).args(["shell", &script]).output()?;
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    print!("{}", String::from_utf8_lossy(&out.stdout));
    if out.status.success() {
        return Ok(());
    }
    eprintln!("su path failed; retrying without su…");
    let out = adb(serial).args(["shell", remote]).output()?;
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    print!("{}", String::from_utf8_lossy(&out.stdout));
    if !out.status.success() {
        bail!("on-device command failed");
    }
    Ok(())
}

fn cmd_inject(
    serial: Option<&str>,
    pid: Option<i32>,
    package: Option<&str>,
    injector: &Path,
    agent: &Path,
    stage_into_app: bool,
) -> Result<()> {
    if pid.is_none() && package.is_none() {
        bail!("pass --pid or --package");
    }
    deploy(serial, injector, agent)?;

    let mut remote = format!("{DEVICE_INJECTOR} inject --so {DEVICE_AGENT}");
    if let Some(p) = pid {
        remote.push_str(&format!(" --pid {p}"));
    }
    if let Some(pkg) = package {
        remote.push_str(&format!(" --package {pkg}"));
    }
    if stage_into_app {
        remote.push_str(" --stage-into-app");
    }
    shell_root(serial, &remote)
}

fn resolve_pid_on_device(serial: Option<&str>, pid: Option<i32>, package: Option<&str>) -> Result<u32> {
    if let Some(p) = pid {
        return Ok(p as u32);
    }
    let pkg = package.context("pass --pid or --package")?;
    let out = adb(serial)
        .args(["shell", "pidof", "-s", pkg])
        .output()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        bail!("package not running: {pkg}");
    }
    Ok(s.parse()?)
}

fn cmd_trace_syscalls(
    serial: Option<&str>,
    pid: Option<i32>,
    package: Option<&str>,
    injector: &Path,
    duration_secs: u64,
    max_events: u64,
    filter: &str,
    enter_only: bool,
) -> Result<()> {
    if pid.is_none() && package.is_none() {
        bail!("pass --pid or --package");
    }
    deploy_injector_only(serial, injector)?;
    let mut remote = format!(
        "{DEVICE_INJECTOR} trace-syscalls --duration-secs {duration_secs} --max-events {max_events}"
    );
    if let Some(p) = pid {
        remote.push_str(&format!(" --pid {p}"));
    }
    if let Some(pkg) = package {
        remote.push_str(&format!(" --package {pkg}"));
    }
    if !filter.is_empty() {
        remote.push_str(&format!(" --filter {filter}"));
    }
    if enter_only {
        remote.push_str(" --enter-only");
    }
    shell_root(serial, &remote)
}

fn default_java_hooks_json(java_hooks: &str) -> String {
    let mut items: Vec<String> = Vec::new();
    let raw = java_hooks.trim();
    if !raw.is_empty() && raw != "-" && !raw.eq_ignore_ascii_case("none") {
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (left, sig) = match part.split_once(':') {
                Some((l, s)) => (l, s),
                None => (part, "(I)I"),
            };
            let (class, method) = match left.rsplit_once('.') {
                Some((c, m)) => (c, m),
                None => continue,
            };
            items.push(format!(
                r#"{{"class":"{class}","method":"{method}","sig":"{sig}"}}"#
            ));
        }
    }
    format!("[{}]", items.join(","))
}

fn restart_package(serial: Option<&str>, package: &str, activity: &str) -> Result<()> {
    eprintln!("restarting {package}…");
    let _ = adb(serial)
        .args(["shell", "am", "force-stop", package])
        .status()?;
    std::thread::sleep(Duration::from_millis(400));
    if !activity.trim().is_empty() {
        run_checked(
            adb(serial)
                .args(["shell", "am", "start", "-n", activity.trim()]),
        )?;
    } else {
        // Prefer explicit Target activity for the sample app; else launcher monkey.
        let sample = format!("{package}/.Target");
        let try_target = adb(serial)
            .args(["shell", "am", "start", "-n", &sample])
            .output()?;
        if !try_target.status.success() {
            run_checked(adb(serial).args([
                "shell",
                "monkey",
                "-p",
                package,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ]))?;
        } else {
            eprint!("{}", String::from_utf8_lossy(&try_target.stderr));
            print!("{}", String::from_utf8_lossy(&try_target.stdout));
        }
    }
    // Wait for process + cold start before inject.
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(250));
        let out = adb(serial)
            .args(["shell", "pidof", "-s", package])
            .output()?;
        if !String::from_utf8_lossy(&out.stdout).trim().is_empty() {
            std::thread::sleep(Duration::from_millis(500));
            return Ok(());
        }
    }
    bail!("package did not start: {package}");
}

fn build_java_trace_script(base: &str, filter: &str, max_events: u64, java_hooks: &str) -> String {
    let hooks = default_java_hooks_json(java_hooks);
    let filter_js = if filter.trim().is_empty() {
        "android.,androidx.,java.,javax.,com.android.,dalvik.".to_string()
    } else {
        filter.trim().to_string()
    };
    // Escape for JS string literal.
    let filter_esc = filter_js.replace('\\', "\\\\").replace('\'', "\\'");
    format!(
        "globalThis.__GOAULD_API_FILTER = '{filter_esc}';\n\
         globalThis.__GOAULD_API_MAX_EVENTS = {max_events};\n\
         globalThis.__GOAULD_JAVA_HOOKS = {hooks};\n\
         {base}"
    )
}

fn load_java_trace_fixture(script: Option<&Path>) -> Result<String> {
    if let Some(p) = script {
        return Ok(std::fs::read_to_string(p)?);
    }
    let candidates = [
        PathBuf::from("scripts/fixtures/trace_java_api.js"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/fixtures/trace_java_api.js"),
    ];
    for c in &candidates {
        if c.exists() {
            return Ok(std::fs::read_to_string(c)?);
        }
    }
    Ok(r#"
            send({type:'trace-java-ready', art_invoke_hook:0});
            send('java-api-trace-installed');
            "#
    .into())
}

/// Attach-only Android API tracing (agent must already be injected).
fn cmd_attach_java(
    serial: Option<&str>,
    port: u16,
    pid: Option<u32>,
    package: Option<&str>,
    max_wait_secs: u64,
    script: Option<&Path>,
    filter: &str,
    max_events: u64,
    java_hooks: &str,
) -> Result<()> {
    let pid_u = match pid {
        Some(p) => p,
        None => {
            if package.is_none() {
                bail!("attach java: pass --pid or --package");
            }
            resolve_pid_on_device(serial, None, package)?
        }
    };
    let source = build_java_trace_script(&load_java_trace_fixture(script)?, filter, max_events, java_hooks);
    cmd_attach(
        serial,
        port,
        Some(pid_u),
        None,
        max_wait_secs,
        Some("java-api-trace-installed"),
        Some(source),
        /*continue_after_expect*/ true,
    )?;
    Ok(())
}

fn cmd_trace_java(
    serial: Option<&str>,
    pid: Option<i32>,
    package: Option<&str>,
    injector: &Path,
    agent: &Path,
    stage_into_app: bool,
    port: u16,
    max_wait_secs: u64,
    script: Option<&Path>,
    filter: &str,
    max_events: u64,
    java_hooks: &str,
    restart: bool,
    no_inject: bool,
    activity: &str,
) -> Result<()> {
    if pid.is_none() && package.is_none() {
        bail!("pass --pid or --package");
    }
    if no_inject {
        let pid_u = resolve_pid_on_device(serial, pid, package)?;
        return cmd_attach_java(
            serial,
            port,
            Some(pid_u),
            None,
            max_wait_secs,
            script,
            filter,
            max_events,
            java_hooks,
        );
    }
    if restart {
        if let Some(pkg) = package {
            restart_package(serial, pkg, activity)?;
        } else {
            eprintln!("note: --restart ignored without --package (pass --no-restart to silence)");
        }
    }
    cmd_inject(serial, pid, package, injector, agent, stage_into_app)?;
    let pid_u = resolve_pid_on_device(serial, pid, package)?;

    let source = build_java_trace_script(&load_java_trace_fixture(script)?, filter, max_events, java_hooks);

    cmd_attach(
        serial,
        port,
        Some(pid_u),
        None,
        max_wait_secs,
        Some("java-api-trace-installed"),
        Some(source),
        /*continue_after_expect*/ true,
    )?;
    Ok(())
}

fn cmd_attach(
    serial: Option<&str>,
    port: u16,
    pid: Option<u32>,
    script: Option<&Path>,
    max_wait_secs: u64,
    expect_send: Option<&str>,
    inline_source: Option<String>,
    continue_after_expect: bool,
) -> Result<()> {
    let mut expect_send = expect_send;
    let agent_name = pid.map(|p| format!("goauld-agent-{p}"));
    if let Some(pid) = pid {
        let name = format!("goauld-agent-{pid}");
        ensure_adb_forward(serial, port, &name)?;
    }

    // Agent ctor thread may need a beat after dlopen before accept().
    let mut established = None;
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 1..=20 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut s) => {
                let _ = s.set_nodelay(true);
                let _ = s.set_read_timeout(Some(Duration::from_millis(if attempt == 1 {
                    250
                } else {
                    750
                })));
                match read_msg(&mut s) {
                    Ok(msg) => {
                        established = Some((s, msg));
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        // Stale forward / listener not ready yet — reconnect.
                    }
                }
            }
            Err(e) => last_err = Some(e),
        }
        if attempt < 20 {
            // Agent is usually already listening after inject; keep early
            // retries cheap instead of a flat 100 ms sleep.
            let backoff_ms = if attempt <= 3 { 15 } else { 50 };
            std::thread::sleep(Duration::from_millis(backoff_ms));
        }
    }
    let (mut stream, hello) = match established {
        Some(v) => v,
        None => {
            let hint = agent_name
                .as_deref()
                .unwrap_or("goauld-agent-<pid>");
            let why = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no connection".into());
            bail!(
                "agent did not send Hello on 127.0.0.1:{port} ({why}). \
                 abstract socket @{hint} is not accepting — often a re-inject into a process \
                 whose agent already exited. Force-stop the app and retry; \
                 `trace java --package …` restarts the app by default."
            );
        }
    };

    match &hello {
        Message::Hello(h) => {
            println!(
                "agent hello: pid={} pkg={} sdk={} abi={} version={}",
                h.pid, h.package, h.sdk_int, h.abi, h.version
            );
        }
        other => bail!("expected Hello, got {other:?}"),
    }

    if let Some(source) = inline_source {
        let len = source.len();
        write_msg(
            &mut stream,
            &Message::ScriptLoad(ScriptLoad {
                script_id: 1,
                source,
            }),
        )?;
        println!("ScriptLoad sent ({len} bytes, inline)");
    } else if let Some(path) = script {
        let source = std::fs::read_to_string(path)?;
        write_msg(
            &mut stream,
            &Message::ScriptLoad(ScriptLoad {
                script_id: 1,
                source,
            }),
        )?;
        println!("ScriptLoad sent ({} bytes)", path.metadata()?.len());
    }

    let deadline = if max_wait_secs == 0 {
        None
    } else {
        Some(std::time::Instant::now() + Duration::from_secs(max_wait_secs))
    };
    println!("listening for agent messages…");
    loop {
        if let Some(d) = deadline {
            if std::time::Instant::now() > d {
                if expect_send.is_some() {
                    bail!("timed out waiting for expected send");
                }
                println!("max-wait reached; exiting");
                return Ok(());
            }
        }
        match read_msg(&mut stream) {
            Ok(Message::Send {
                script_id,
                payload_json,
                data,
            }) => {
                println!(
                    "send[{script_id}]: {payload_json}{}",
                    data.as_ref()
                        .map(|d| format!(" (+{} bytes)", d.len()))
                        .unwrap_or_default()
                );
                if let Some(needle) = expect_send {
                    if payload_json.contains(needle) {
                        println!("OK expect-send matched {needle:?}");
                        if !continue_after_expect {
                            return Ok(());
                        }
                        // Keep listening for subsequent trace events until max-wait.
                        expect_send = None;
                    }
                }
            }
            Ok(Message::Log(l)) => println!("[{}] {}", l.level, l.message),
            Ok(other) => println!("msg: {other:?}"),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn cmd_stress(
    serial: Option<&str>,
    package: &str,
    injector: &Path,
    agent: &Path,
    stage_into_app: bool,
    port: u16,
    count: u64,
    payload: u64,
    baseline_secs: u64,
    max_wait_secs: u64,
    restart: bool,
    activity: &str,
) -> Result<()> {
    if restart {
        restart_package(serial, package, activity)?;
    }

    let _ = adb(serial).args(["logcat", "-c"]).status();
    cmd_inject(serial, None, Some(package), injector, agent, stage_into_app)?;
    let pid = resolve_pid_on_device(serial, None, Some(package))?;

    println!("baseline apk-tick sampling ({baseline_secs}s)…");
    let _ = adb(serial).args(["logcat", "-c"]).status();
    std::thread::sleep(Duration::from_secs(baseline_secs.max(1)));
    let baseline = sample_apk_ticks(serial, pid)?;
    let baseline_expected = (baseline_secs.max(1) as f64) / 0.050;
    println!(
        "baseline: ticks={} (~{:.0}% of expected) mean_dt_ms={:.2}",
        baseline.count,
        (baseline.count as f64 / baseline_expected) * 100.0,
        baseline.mean_dt_ms.unwrap_or(f64::NAN)
    );

    let fixture = load_stress_fixture()?;
    let source = format!(
        "globalThis.__GOAULD_STRESS_COUNT = {count};\n\
         globalThis.__GOAULD_STRESS_PAYLOAD = {payload};\n\
         {fixture}"
    );

    // Fresh forward + connect (reuse attach connect path).
    let name = format!("goauld-agent-{pid}");
    let spec = format!("tcp:{port}");
    let local = format!("localabstract:{name}");
    eprintln!("adb forward {spec} {local}");
    let _ = adb(serial).args(["forward", "--remove", &spec]).status();
    run_checked(adb(serial).args(["forward", &spec, &local]))?;

    let mut stream = None;
    let mut last_err = None;
    for attempt in 1..=20 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(Duration::from_millis(750)));
                match read_msg(&mut s) {
                    Ok(Message::Hello(h)) => {
                        println!(
                            "agent hello: pid={} pkg={} sdk={} abi={} version={}",
                            h.pid, h.package, h.sdk_int, h.abi, h.version
                        );
                        stream = Some(s);
                        break;
                    }
                    Ok(other) => last_err = Some(format!("expected Hello, got {other:?}")),
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            Err(e) => last_err = Some(e.to_string()),
        }
        if attempt < 20 {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let mut stream = stream.ok_or_else(|| {
        anyhow::anyhow!(
            "stress: no agent Hello ({})",
            last_err.unwrap_or_else(|| "connect failed".into())
        )
    })?;

    let t_clear = std::time::Instant::now();
    let _ = adb(serial).args(["logcat", "-c"]).status();
    write_msg(
        &mut stream,
        &Message::ScriptLoad(ScriptLoad {
            script_id: 1,
            source,
        }),
    )?;
    println!("ScriptLoad sent (stress count={count} payload={payload})");

    let mut got_start = false;
    let mut got_done = false;
    let mut recv = 0u64;
    let mut bytes = 0u64;
    let mut gaps = 0u64;
    let mut next_n = 0u64;
    let mut first_at: Option<std::time::Instant> = None;
    let mut last_at: Option<std::time::Instant> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(max_wait_secs.max(5));

    while std::time::Instant::now() < deadline {
        match read_msg(&mut stream) {
            Ok(Message::Send {
                payload_json,
                data,
                ..
            }) => {
                let now = std::time::Instant::now();
                let sz = payload_json.len() as u64 + data.as_ref().map(|d| d.len() as u64).unwrap_or(0);
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload_json) {
                    let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    match ty {
                        "stress-start" => {
                            got_start = true;
                            println!("stress-start: {payload_json}");
                        }
                        "stress" => {
                            recv += 1;
                            bytes += sz;
                            if first_at.is_none() {
                                first_at = Some(now);
                            }
                            last_at = Some(now);
                            if let Some(n) = v.get("n").and_then(|x| x.as_u64()) {
                                if n != next_n {
                                    gaps += 1;
                                }
                                next_n = n.saturating_add(1);
                            }
                        }
                        "stress-done" => {
                            got_done = true;
                            println!("stress-done: {payload_json}");
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e.into()),
        }
    }

    if !got_done {
        bail!("timed out waiting for stress-done (recv={recv}, start={got_start})");
    }

    let elapsed = match (first_at, last_at) {
        (Some(a), Some(b)) => b.duration_since(a).as_secs_f64().max(1e-6),
        _ => 1e-6,
    };
    let msg_s = recv as f64 / elapsed;
    let mib_s = (bytes as f64 / elapsed) / (1024.0 * 1024.0);

    // Let apk-tick catch up a moment, then sample ticks from the flood window.
    std::thread::sleep(Duration::from_millis(200));
    let during = sample_apk_ticks(serial, pid)?;
    let alive = adb(serial)
        .args(["shell", "kill", "-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let flood_wall = t_clear.elapsed().as_secs_f64();
    let expected_ticks = (flood_wall / 0.050).max(1.0);
    let tick_ratio = during.count as f64 / expected_ticks;

    println!();
    println!("=== stress report ===");
    println!("messages:     {recv}/{count}  seq_gaps={gaps}");
    println!("payload:      {payload} pad bytes / msg");
    println!("wall:         {elapsed:.3}s first→last stress msg");
    println!("throughput:   {msg_s:.0} msg/s  {mib_s:.3} MiB/s (json+data)");
    println!(
        "apk-tick:     baseline mean_dt_ms={:.2}  during mean_dt_ms={:.2}  ticks_during={}  (~{:.0}% of expected @50ms)",
        baseline.mean_dt_ms.unwrap_or(f64::NAN),
        during.mean_dt_ms.unwrap_or(f64::NAN),
        during.count,
        tick_ratio * 100.0
    );
    println!("process:      pid={pid} alive={alive}");
    if gaps > 0 || recv != count {
        bail!("stress incomplete or reordered (recv={recv} count={count} gaps={gaps})");
    }
    if !alive {
        bail!("target process died during stress");
    }
    println!("OK stress");
    Ok(())
}

#[derive(Debug, Default)]
struct TickSample {
    count: u64,
    mean_dt_ms: Option<f64>,
}

fn sample_apk_ticks(serial: Option<&str>, pid: u32) -> Result<TickSample> {
    let out = adb(serial)
        .args([
            "logcat",
            "-d",
            "--pid",
            &pid.to_string(),
            "-s",
            "java-target:I",
        ])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut times: Vec<u64> = Vec::new();
    for line in text.lines() {
        // apk-tick n=12 t=123456789
        if let Some(idx) = line.find("apk-tick ") {
            let rest = &line[idx..];
            if let Some(tpos) = rest.find(" t=") {
                let num = rest[tpos + 3..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                if let Ok(t) = num.parse::<u64>() {
                    times.push(t);
                }
            }
        }
    }
    if times.len() < 2 {
        return Ok(TickSample {
            count: times.len() as u64,
            mean_dt_ms: None,
        });
    }
    // Use last up to 40 intervals so baseline/during windows stay local.
    let start = times.len().saturating_sub(41);
    let slice = &times[start..];
    let mut sum = 0f64;
    let mut n = 0u64;
    for w in slice.windows(2) {
        if w[1] > w[0] {
            sum += (w[1] - w[0]) as f64 / 1_000_000.0; // ns → ms
            n += 1;
        }
    }
    Ok(TickSample {
        count: times.len() as u64,
        mean_dt_ms: if n > 0 { Some(sum / n as f64) } else { None },
    })
}

fn load_stress_fixture() -> Result<String> {
    load_fixture(&[
        "scripts/fixtures/stress_send.js",
        "../../scripts/fixtures/stress_send.js",
    ])
}

fn load_frida_comm_fixture() -> Result<String> {
    load_fixture(&[
        "scripts/fixtures/stress_frida_comm.js",
        "../../scripts/fixtures/stress_frida_comm.js",
    ])
}

fn load_fixture(rel_paths: &[&str]) -> Result<String> {
    let mut candidates = Vec::new();
    for p in rel_paths {
        candidates.push(PathBuf::from(p));
        if p.starts_with("../") {
            candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(p));
        } else {
            candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../").join(p));
        }
    }
    for c in &candidates {
        if c.exists() {
            return Ok(std::fs::read_to_string(c)?);
        }
    }
    bail!("missing fixture (tried {rel_paths:?})");
}

fn cmd_stress_frida(
    serial: Option<&str>,
    package: &str,
    injector: &Path,
    agent: &Path,
    stage_into_app: bool,
    port: u16,
    count: u64,
    payload: u64,
    rpc_count: u64,
    max_wait_secs: u64,
    restart: bool,
    activity: &str,
) -> Result<()> {
    if restart {
        restart_package(serial, package, activity)?;
    }
    cmd_inject(serial, None, Some(package), injector, agent, stage_into_app)?;
    let pid = resolve_pid_on_device(serial, None, Some(package))?;

    let fixture = load_frida_comm_fixture()?;
    let source = format!(
        "globalThis.__GOAULD_STRESS_COUNT = {count};\n\
         globalThis.__GOAULD_STRESS_PAYLOAD = {payload};\n\
         {fixture}"
    );

    let name = format!("goauld-agent-{pid}");
    let spec = format!("tcp:{port}");
    let local = format!("localabstract:{name}");
    eprintln!("adb forward {spec} {local}");
    let _ = adb(serial).args(["forward", "--remove", &spec]).status();
    run_checked(adb(serial).args(["forward", &spec, &local]))?;

    let mut stream = connect_agent_hello(port)?;
    write_msg(
        &mut stream,
        &Message::ScriptLoad(ScriptLoad {
            script_id: 1,
            source,
        }),
    )?;
    println!("ScriptLoad sent (frida-comm count={count} payload={payload})");

    let mut rounds = 0u64;
    let mut bytes = 0u64;
    let mut rtts_us: Vec<u64> = Vec::new();
    let mut pending_pong: Option<(u64, std::time::Instant)> = None;
    let mut done = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(max_wait_secs.max(10));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

    while std::time::Instant::now() < deadline && !done {
        match read_msg(&mut stream) {
            Ok(Message::Send {
                payload_json,
                data,
                ..
            }) => {
                let sz = payload_json.len() as u64
                    + data.as_ref().map(|d| d.len() as u64).unwrap_or(0);
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload_json) else {
                    continue;
                };
                let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match ty {
                    "comm-ready" => println!("comm-ready: {payload_json}"),
                    "comm-err" => bail!("agent reported error: {payload_json}"),
                    "ping" => {
                        let n = v.get("n").and_then(|x| x.as_u64()).unwrap_or(0);
                        if let Some((_, t0)) = pending_pong.take() {
                            rtts_us.push(t0.elapsed().as_micros() as u64);
                        }
                        pending_pong = Some((n, std::time::Instant::now()));
                        let pong = serde_json::json!({"type":"pong","n":n}).to_string();
                        write_msg(
                            &mut stream,
                            &Message::Post {
                                script_id: 1,
                                payload_json: pong,
                                data: data.clone(),
                            },
                        )?;
                        rounds += 1;
                        bytes += sz;
                    }
                    "comm-done" => {
                        if let Some((_, t0)) = pending_pong.take() {
                            rtts_us.push(t0.elapsed().as_micros() as u64);
                        }
                        done = true;
                        println!("comm-done: {payload_json}");
                    }
                    _ => {}
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e.into()),
        }
    }
    if !done {
        bail!("timed out waiting for comm-done (rounds={rounds})");
    }

    // RPC RTT batch (Frida script.exports style).
    let mut rpc_ok = 0u64;
    let mut rpc_us: Vec<u64> = Vec::new();
    for i in 0..rpc_count {
        let t0 = std::time::Instant::now();
        let args = if i % 2 == 0 {
            serde_json::json!([i, i + 1]).to_string()
        } else {
            serde_json::json!([format!("echo-{i}")]).to_string()
        };
        let fn_name = if i % 2 == 0 { "add" } else { "echo" };
        write_msg(
            &mut stream,
            &Message::RpcCall(RpcCall {
                script_id: 1,
                call_id: (i as u32) + 1,
                fn_name: fn_name.into(),
                args_json: args,
            }),
        )?;
        let rpc_deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if std::time::Instant::now() > rpc_deadline {
                bail!("rpc reply timeout call_id={}", i + 1);
            }
            match read_msg(&mut stream) {
                Ok(Message::RpcReply(r)) => {
                    if r.error.is_some() {
                        bail!("rpc error: {:?}", r.error);
                    }
                    rpc_ok += 1;
                    rpc_us.push(t0.elapsed().as_micros() as u64);
                    break;
                }
                Ok(Message::Send { .. }) => continue,
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }

    let alive = adb(serial)
        .args(["shell", "kill", "-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let ping_mean = if rtts_us.is_empty() {
        0.0
    } else {
        rtts_us.iter().sum::<u64>() as f64 / rtts_us.len() as f64
    };
    let rpc_mean = if rpc_us.is_empty() {
        0.0
    } else {
        rpc_us.iter().sum::<u64>() as f64 / rpc_us.len() as f64
    };

    println!();
    println!("=== frida-comm stress report ===");
    println!("ping/pong:    {rounds} rounds  (~{bytes} bytes agent→host)  mean_rtt_us={ping_mean:.0}");
    println!("rpc:          {rpc_ok}/{rpc_count}  mean_rtt_us={rpc_mean:.0}");
    println!("process:      pid={pid} alive={alive}");
    if !alive {
        bail!("target process died during frida-comm stress");
    }
    if rounds != count {
        bail!("ping/pong incomplete (rounds={rounds} count={count})");
    }
    if rpc_ok != rpc_count {
        bail!("rpc incomplete");
    }
    println!("OK frida-comm stress");
    Ok(())
}

fn connect_agent_hello(port: u16) -> Result<TcpStream> {
    let mut last_err = None;
    for attempt in 1..=20 {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(Duration::from_millis(750)));
                match read_msg(&mut s) {
                    Ok(Message::Hello(h)) => {
                        println!(
                            "agent hello: pid={} pkg={} sdk={} abi={} version={}",
                            h.pid, h.package, h.sdk_int, h.abi, h.version
                        );
                        return Ok(s);
                    }
                    Ok(other) => last_err = Some(format!("expected Hello, got {other:?}")),
                    Err(e) => last_err = Some(e.to_string()),
                }
            }
            Err(e) => last_err = Some(e.to_string()),
        }
        if attempt < 20 {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    bail!(
        "no agent Hello: {}",
        last_err.unwrap_or_else(|| "connect failed".into())
    )
}

fn run_checked(cmd: &mut Command) -> Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        bail!("command failed: {cmd:?}");
    }
    Ok(())
}

fn write_msg(w: &mut impl Write, msg: &Message) -> Result<()> {
    let bytes = msg.encode()?;
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

fn read_msg(r: &mut impl Read) -> std::io::Result<Message> {
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
