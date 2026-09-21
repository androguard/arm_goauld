//! `goauld-injector` — **on-device** arm64 Android binary.
//!
//! This is the process that actually calls `ptrace` / remote `dlopen`. It must
//! run on the phone (typically as root via `adb push` + `adb shell su -c ...`).
//! The desktop `goauld` host only orchestrates: build → push → exec this binary.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use goauld_inject::discover::find_by_package;
use goauld_inject::{
    enumerate_processes, inject_library, trace_syscalls, InjectOptions, SyscallTraceOptions,
};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "goauld-injector",
    about = "On-device ptrace injector / tracer for goauld (Android arm64)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    // ---- legacy flat flags (inject) kept for scripts ----
    #[arg(long)]
    pid: Option<i32>,
    #[arg(long)]
    package: Option<String>,
    #[arg(long)]
    so: Option<PathBuf>,
    #[arg(long)]
    ps: bool,
    #[arg(long)]
    stage_into_app: bool,
    #[arg(long)]
    use_namespace: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List processes.
    Ps,
    /// Ptrace-inject `libgoauld_agent.so` into a target.
    Inject {
        #[arg(long)]
        pid: Option<i32>,
        #[arg(long)]
        package: Option<String>,
        #[arg(long)]
        so: PathBuf,
        #[arg(long)]
        stage_into_app: bool,
        #[arg(long)]
        use_namespace: bool,
    },
    /// Trace syscalls in a running process (`PTRACE_SYSCALL`).
    TraceSyscalls {
        #[arg(long, conflicts_with = "package")]
        pid: Option<i32>,
        #[arg(long)]
        package: Option<String>,
        /// Seconds to trace (0 = until max-events only / forever if both 0).
        #[arg(long, default_value = "15")]
        duration_secs: u64,
        /// Stop after N syscall enters (0 = unlimited).
        #[arg(long, default_value = "0")]
        max_events: u64,
        /// Comma-separated name substrings (e.g. `openat,connect,write`).
        #[arg(long, default_value = "")]
        filter: String,
        #[arg(long)]
        enter_only: bool,
    },
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    eprintln!("goauld-injector {}", goauld_proto::version_info());

    if let Err(e) = run() {
        eprintln!("goauld-injector error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Prefer explicit subcommand; fall back to legacy flat inject/ps flags.
    match cli.cmd {
        Some(Cmd::Ps) => cmd_ps(),
        Some(Cmd::Inject {
            pid,
            package,
            so,
            stage_into_app,
            use_namespace,
        }) => cmd_inject(pid, package.as_deref(), so, stage_into_app, use_namespace),
        Some(Cmd::TraceSyscalls {
            pid,
            package,
            duration_secs,
            max_events,
            filter,
            enter_only,
        }) => cmd_trace_syscalls(
            pid,
            package.as_deref(),
            duration_secs,
            max_events,
            &filter,
            enter_only,
        ),
        None => {
            if cli.ps {
                return cmd_ps();
            }
            let so = cli.so.context("--so is required (or use `inject` subcommand)")?;
            cmd_inject(
                cli.pid,
                cli.package.as_deref(),
                so,
                cli.stage_into_app,
                cli.use_namespace,
            )
        }
    }
}

fn cmd_ps() -> Result<()> {
    for p in enumerate_processes()? {
        println!(
            "{:>6}  {:12}  {}",
            p.pid,
            p.abi.as_deref().unwrap_or("?"),
            p.package.as_deref().unwrap_or(&p.cmdline)
        );
    }
    Ok(())
}

fn cmd_inject(
    pid: Option<i32>,
    package: Option<&str>,
    so_path: PathBuf,
    stage_into_app: bool,
    use_namespace: bool,
) -> Result<()> {
    let so = so_path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", so_path.display()))
        .unwrap_or(so_path.clone());
    if !so.exists() {
        bail!("agent .so not found: {}", so.display());
    }

    let (pid, package) = resolve_target(pid, package)?;

    let mut library_path = so.to_string_lossy().into_owned();
    if stage_into_app {
        let pkg = package
            .as_deref()
            .context("--stage-into-app needs a package")?;
        library_path = stage_so_into_app(pid, pkg, &so)?;
        eprintln!("staged agent to {library_path}");
    }

    eprintln!(
        "injecting {} into pid={pid} ({})",
        library_path,
        package.as_deref().unwrap_or("?")
    );

    let handle = inject_library(
        pid,
        &InjectOptions {
            library_path,
            use_namespace,
        },
    )?;
    println!("OK handle={handle:#x} pid={pid}");
    Ok(())
}

fn cmd_trace_syscalls(
    pid: Option<i32>,
    package: Option<&str>,
    duration_secs: u64,
    max_events: u64,
    filter: &str,
    enter_only: bool,
) -> Result<()> {
    let (pid, package) = resolve_target(pid, package)?;
    let filter: Vec<String> = filter
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    eprintln!(
        "tracing syscalls pid={pid} ({}) duration={}s max_events={max_events} filter={filter:?}",
        package.as_deref().unwrap_or("?"),
        duration_secs
    );
    let opts = SyscallTraceOptions {
        max_events,
        duration: if duration_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(duration_secs))
        },
        filter,
        enter_only,
    };
    let n = trace_syscalls(pid, &opts)?;
    eprintln!("OK traced {n} syscall enters");
    Ok(())
}

fn resolve_target(pid: Option<i32>, package: Option<&str>) -> Result<(i32, Option<String>)> {
    if let Some(pid) = pid {
        let cmd = read_cmdline(pid);
        if cmd.is_empty() {
            if let Some(pkg) = package {
                eprintln!("goauld-inject: pid {pid} is not running; looking up {pkg}");
                let info = find_by_package(pkg)
                    .with_context(|| format!("pid {pid} is not running and {pkg} has no app process"))?;
                eprintln!(
                    "goauld-inject: using live pid={} for {pkg}",
                    info.pid
                );
                return Ok((info.pid as i32, Some(pkg.to_string())));
            }
            bail!("pid {pid} is not running");
        }
        if let Some(pkg) = package {
            let first = cmd.split_whitespace().next().unwrap_or("");
            if first != pkg && !first.starts_with(&format!("{pkg}:")) {
                bail!(
                    "pid {pid} is not {pkg} (cmdline: {}). Refusing to inject into a shell that only mentions the package.",
                    clip(&cmd)
                );
            }
        }
        let package = package.map(|s| s.to_string()).or_else(|| {
            enumerate_processes().ok().and_then(|list| {
                list.into_iter()
                    .find(|p| p.pid as i32 == pid)
                    .and_then(|p| p.package)
            })
        });
        eprintln!("goauld-inject: using pid={pid} cmd={}", clip(&cmd));
        return Ok((pid, package));
    }
    if let Some(pkg) = package {
        let info = find_by_package(pkg).with_context(|| format!("package not running: {pkg}"))?;
        return Ok((info.pid as i32, Some(pkg.to_string())));
    }
    bail!("pass --pid or --package")
}

fn read_cmdline(pid: i32) -> String {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    raw.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn clip(cmd: &str) -> String {
    let mut s: String = cmd.chars().take(140).collect();
    if cmd.chars().count() > 140 {
        s.push('…');
    }
    s
}

fn stage_so_into_app(pid: i32, package: &str, so: &std::path::Path) -> Result<String> {
    let dest_name = so
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("libgoauld_agent.so");
    let uid = {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    };
    let user = uid / 100_000;
    let euid = effective_uid();
    eprintln!("goauld-inject: staging as euid={euid} into app uid={uid} user={user}");
    if euid != 0 {
        bail!(
            "not root (euid={euid}) — refuse to stage into the app mount namespace; \
             Magisk must grant su to the adb shell"
        );
    }

    // The app has its own mount namespace. A copy into the root namespace's
    // /data/data/<pkg> is invisible to dlopen ("library not found").
    let pkg_dirs = [
        format!("/data/user/{user}/{package}"),
        format!("/data/user_de/{user}/{package}"),
        format!("/data/data/{package}"),
    ];
    let pkg_dir = pkg_dirs
        .iter()
        .find(|dir| std::path::Path::new(&proc_root(pid, dir)).is_dir())
        .cloned()
        .unwrap_or_else(|| format!("/data/data/{package}"));
    let files_dir = format!("{pkg_dir}/files");
    let visible = format!("{files_dir}/{dest_name}");
    let host_dir = proc_root(pid, &files_dir);
    let host_file = proc_root(pid, &visible);
    let so_s = so.to_str().context("agent path")?;

    let mut last_err = String::new();

    // 1) Write through /proc/<pid>/root (same files the process sees).
    if stage_copy_into(&host_dir, &host_file, so_s, &proc_root(pid, &pkg_dir)) {
        return Ok(visible);
    }
    last_err = format!("/proc/{pid}/root copy failed");

    // 2) Enter the app mount namespace and copy there.
    if stage_nsenter(pid, &files_dir, &visible, so_s, &pkg_dir) {
        return Ok(visible);
    }
    last_err = format!("{last_err}; nsenter copy failed");

    // 3) Last resort: run-as (debuggable apps only).
    let _ = Command::new("run-as")
        .args([package, "mkdir", "-p", "files"])
        .status();
    let status = Command::new("run-as")
        .args([package, "cp", so_s, &format!("files/{dest_name}")])
        .status();
    if status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("staged agent via run-as: {visible}");
        return Ok(visible);
    }

    bail!("could not stage {so:?} into {visible} ({last_err})")
}

fn stage_copy_into(host_dir: &str, host_file: &str, so: &str, pkg_host: &str) -> bool {
    let mk = Command::new("mkdir").args(["-p", host_dir]).status();
    if !mk.map(|s| s.success()).unwrap_or(false) {
        eprintln!("goauld-inject: mkdir {host_dir} failed");
        return false;
    }
    let cp = Command::new("cp").args([so, host_file]).status();
    if !cp.map(|s| s.success()).unwrap_or(false) {
        eprintln!("goauld-inject: cp → {host_file} failed");
        return false;
    }
    let _ = Command::new("chmod").args(["755", host_file]).status();
    if let Ok(out) = Command::new("stat").args(["-c", "%u:%g", pkg_host]).output() {
        let ug = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if ug.contains(':') {
            let _ = Command::new("chown").args([&ug, host_file]).status();
        }
    }
    let _ = Command::new("chcon")
        .args(["u:object_r:app_data_file:s0", host_file])
        .status();
    let _ = Command::new("restorecon").args([host_file]).status();
    // Toybox chcon has no --reference. Copy the real MLS context (categories)
    // from the directory or a sibling, or the app still gets EACCES.
    if let Some(ctx) = selinux_context_of(pkg_host).or_else(|| selinux_context_of(host_dir)) {
        if Command::new("chcon")
            .args([&ctx, host_file])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            eprintln!("goauld-inject: chcon {ctx}");
        }
    }
    match std::fs::metadata(host_file) {
        Ok(meta) => {
            eprintln!("staged agent in app namespace: {host_file} ({} bytes)", meta.len());
            true
        }
        Err(e) => {
            eprintln!("staged path not visible via {host_file}: {e}");
            false
        }
    }
}

fn stage_nsenter(pid: i32, files_dir: &str, visible: &str, so: &str, pkg_dir: &str) -> bool {
    let mk = Command::new("nsenter")
        .args([
            "-t",
            &pid.to_string(),
            "-m",
            "--",
            "mkdir",
            "-p",
            files_dir,
        ])
        .status();
    if !mk.map(|s| s.success()).unwrap_or(false) {
        eprintln!("goauld-inject: nsenter mkdir failed");
        return false;
    }
    let cp = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-m", "--", "cp", so, visible])
        .status();
    if !cp.map(|s| s.success()).unwrap_or(false) {
        eprintln!("goauld-inject: nsenter cp failed");
        return false;
    }
    let _ = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-m", "--", "chmod", "755", visible])
        .status();
    if let Ok(out) = Command::new("nsenter")
        .args(["-t", &pid.to_string(), "-m", "--", "stat", "-c", "%u:%g", pkg_dir])
        .output()
    {
        let ug = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if ug.contains(':') {
            let _ = Command::new("nsenter")
                .args(["-t", &pid.to_string(), "-m", "--", "chown", &ug, visible])
                .status();
        }
    }
    let _ = Command::new("nsenter")
        .args([
            "-t",
            &pid.to_string(),
            "-m",
            "--",
            "chcon",
            "u:object_r:app_data_file:s0",
            visible,
        ])
        .status();
    eprintln!("staged agent via nsenter: {visible}");
    true
}

fn selinux_context_of(path: &str) -> Option<String> {
    let out = Command::new("ls").args(["-Zd", path]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .find(|t| t.starts_with("u:") && t.contains(":object_r:"))
        .map(|s| s.to_string())
}

fn effective_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        // Uid: real effective saved fs
        if let Some(euid) = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
            return euid;
        }
        if let Some(ruid) = rest.split_whitespace().next().and_then(|s| s.parse().ok()) {
            return ruid;
        }
    }
    0
}

fn proc_root(pid: i32, abs: &str) -> String {
    format!("/proc/{pid}/root{abs}")
}
