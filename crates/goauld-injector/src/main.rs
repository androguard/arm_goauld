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
    #[arg(long, conflicts_with = "package")]
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
        #[arg(long, conflicts_with = "package")]
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
        library_path = stage_so_into_app(pkg, &so)?;
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
    if let Some(pkg) = package {
        let info = find_by_package(pkg).with_context(|| format!("package not running: {pkg}"))?;
        return Ok((info.pid as i32, Some(pkg.to_string())));
    }
    let pid = pid.context("pass --pid or --package")?;
    let package = enumerate_processes().ok().and_then(|list| {
        list.into_iter()
            .find(|p| p.pid as i32 == pid)
            .and_then(|p| p.package)
    });
    Ok((pid, package))
}

fn stage_so_into_app(package: &str, so: &std::path::Path) -> Result<String> {
    let dest_name = so
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("libgoauld_agent.so");
    let files_dir = format!("/data/data/{package}/files");
    let dest = format!("{files_dir}/{dest_name}");

    let _ = Command::new("mkdir").args(["-p", &files_dir]).status();

    let root_cp = Command::new("cp")
        .args([so.to_str().unwrap(), &dest])
        .status();
    if let Ok(st) = root_cp {
        if st.success() {
            let _ = Command::new("chmod").args(["755", &dest]).status();
            if let Ok(out) = Command::new("stat")
                .args(["-c", "%u:%g", &files_dir])
                .output()
            {
                let ug = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !ug.is_empty() {
                    let _ = Command::new("chown").args([&ug, &dest]).status();
                }
            }
            return Ok(dest);
        }
    }

    let _ = Command::new("run-as")
        .args([package, "mkdir", "-p", "files"])
        .status();
    let status = Command::new("run-as")
        .args([
            package,
            "cp",
            so.to_str().unwrap(),
            &format!("files/{dest_name}"),
        ])
        .status()
        .with_context(|| format!("run-as {package} cp failed"))?;
    if !status.success() {
        bail!("could not stage {so:?} into {dest} (tried root cp and run-as)");
    }
    Ok(dest)
}
