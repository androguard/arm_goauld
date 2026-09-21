//! Target discovery via `/proc` (§3.1).

use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiscoverError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("process not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub cmdline: String,
    pub package: Option<String>,
    pub abi: Option<String>,
}

/// Enumerate processes from `/proc/<pid>/cmdline` (+ package heuristic from cmdline).
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>, DiscoverError> {
    let mut out = Vec::new();
    let proc = PathBuf::from(proc_root());
    if !proc.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(&proc)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let cmdline_path = entry.path().join("cmdline");
        let raw = match fs::read(&cmdline_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let cmdline = raw
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        if cmdline.is_empty() {
            continue;
        }
        let package = guess_package(&cmdline);
        let abi = resolve_abi(pid).ok();
        out.push(ProcessInfo {
            pid,
            cmdline,
            package,
            abi,
        });
    }
    Ok(out)
}

/// Resolve target ABI from `/proc/<pid>/maps` or `/proc/<pid>/exe`.
pub fn resolve_abi(pid: u32) -> Result<String, DiscoverError> {
    let maps = PathBuf::from(proc_root()).join(pid.to_string()).join("maps");
    let text = fs::read_to_string(&maps)?;
    if text.contains("/system/bin/app_process64") || text.contains("lib64/") {
        return Ok("arm64-v8a".into());
    }
    if text.contains("/system/bin/app_process32") || text.contains("/lib/") {
        return Ok("armeabi-v7a".into());
    }
    let exe = PathBuf::from(proc_root()).join(pid.to_string()).join("exe");
    if let Ok(link) = fs::read_link(&exe) {
        let s = link.to_string_lossy();
        if s.contains("64") {
            return Ok("arm64-v8a".into());
        }
    }
    Ok("unknown".into())
}

pub fn find_by_package(package: &str) -> Result<ProcessInfo, DiscoverError> {
    let skip = ancestor_pids();
    let mut hits: Vec<(u32, ProcessInfo)> = Vec::new();
    for proc in enumerate_processes()? {
        if skip.contains(&proc.pid) {
            continue;
        }
        let first = proc.cmdline.split_whitespace().next().unwrap_or("");
        let is_app = first == package || first.starts_with(&format!("{package}:"));
        if !is_app {
            if proc.cmdline.contains(package) {
                eprintln!(
                    "goauld-inject: ignoring pid={} uid={} (not the app process) {}",
                    proc.pid,
                    proc_uid(proc.pid),
                    clip_cmd(&proc.cmdline)
                );
            }
            continue;
        }
        let uid = proc_uid(proc.pid);
        eprintln!(
            "goauld-inject: app candidate pid={} uid={uid} cmd={}",
            proc.pid,
            clip_cmd(&proc.cmdline)
        );
        hits.push((uid, proc));
    }
    let mut apps: Vec<(u32, ProcessInfo)> = hits.into_iter().filter(|(uid, _)| *uid >= 10_000).collect();
    if apps.is_empty() {
        return Err(DiscoverError::NotFound(format!(
            "{package} (no running app process; a shell mentioning the name does not count)"
        )));
    }
    apps.sort_by_key(|(uid, proc)| {
        let first = proc.cmdline.split_whitespace().next().unwrap_or("");
        let main = if first == package { 0u8 } else { 1 };
        (main, *uid, proc.pid)
    });
    Ok(apps.remove(0).1)
}

fn proc_uid(pid: u32) -> u32 {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// This injector plus the su/timeout/sh parents that invoked it.
fn ancestor_pids() -> std::collections::HashSet<u32> {
    let mut set = std::collections::HashSet::new();
    let mut pid = std::process::id();
    set.insert(pid);
    for _ in 0..32 {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let ppid = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|r| r.trim().parse::<u32>().ok())
            .unwrap_or(0);
        if ppid <= 1 || !set.insert(ppid) {
            break;
        }
        pid = ppid;
    }
    set
}

fn clip_cmd(cmd: &str) -> String {
    let mut s: String = cmd.chars().take(140).collect();
    if cmd.chars().count() > 140 {
        s.push('…');
    }
    s
}

fn guess_package(cmdline: &str) -> Option<String> {
    // App processes often have cmdline = package name.
    let first = cmdline.split_whitespace().next()?;
    if first.contains('.') && !first.starts_with('/') {
        return Some(first.to_string());
    }
    None
}

fn proc_root() -> &'static str {
    // Allow host-side tests to point at a fake proc tree.
    option_env!("GOAULD_PROC_ROOT").unwrap_or("/proc")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_package_from_cmdline() {
        assert_eq!(
            guess_package("com.example.native_target"),
            Some("com.example.native_target".into())
        );
        assert_eq!(guess_package("/system/bin/surfaceflinger"), None);
    }

    #[test]
    fn app_process_name_is_not_a_shell_command() {
        let pkg = "com.google.android.calculator";
        let app = format!("{pkg}");
        let sub = format!("{pkg}:privileged");
        let shell = format!("timeout 120 su 0 sh -c '/data/local/tmp/goauld-injector inject --package {pkg}'");
        assert!(app.split_whitespace().next() == Some(pkg));
        assert!(sub.split_whitespace().next().unwrap().starts_with(&format!("{pkg}:")));
        assert_ne!(shell.split_whitespace().next(), Some(pkg));
        assert!(shell.contains(pkg));
    }
}
