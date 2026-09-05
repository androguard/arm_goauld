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
    enumerate_processes()?
        .into_iter()
        .find(|p| p.package.as_deref() == Some(package) || p.cmdline.contains(package))
        .ok_or_else(|| DiscoverError::NotFound(package.into()))
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
}
