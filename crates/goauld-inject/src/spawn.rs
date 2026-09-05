//! Spawn-and-inject (§3.3): `am start -D` then attach while suspended.

use crate::inject::{inject_library, InjectError, InjectOptions};
use std::process::Command;

/// Start `package/activity` suspended (`am start -D`) and inject `opts.library_path`.
///
/// Requires `adb` on PATH and a connected device/emulator. Returns the dlopen handle.
pub fn spawn_and_inject(
    adb_serial: Option<&str>,
    component: &str,
    opts: &InjectOptions,
) -> Result<(u32, u64), InjectError> {
    let mut cmd = Command::new("adb");
    if let Some(s) = adb_serial {
        cmd.args(["-s", s]);
    }
    let output = cmd
        .args(["shell", "am", "start", "-D", "-n", component])
        .output()
        .map_err(|e| InjectError::Msg(e.to_string()))?;
    if !output.status.success() {
        return Err(InjectError::Msg(format!(
            "am start failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Parse package from component (pkg/activity).
    let package = component
        .split('/')
        .next()
        .ok_or_else(|| InjectError::Msg("bad component".into()))?;

    // Wait briefly for the process to appear.
    let pid = wait_for_package(adb_serial, package, std::time::Duration::from_secs(10))?;
    let handle = inject_library(pid as i32, opts)?;
    Ok((pid, handle))
}

fn wait_for_package(
    adb_serial: Option<&str>,
    package: &str,
    timeout: std::time::Duration,
) -> Result<u32, InjectError> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(pid) = pidof(adb_serial, package) {
            return Ok(pid);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Err(InjectError::Msg(format!(
        "timeout waiting for {package}"
    )))
}

fn pidof(adb_serial: Option<&str>, package: &str) -> Result<u32, InjectError> {
    let mut cmd = Command::new("adb");
    if let Some(s) = adb_serial {
        cmd.args(["-s", s]);
    }
    let output = cmd
        .args(["shell", "pidof", package])
        .output()
        .map_err(|e| InjectError::Msg(e.to_string()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let pid = text
        .split_whitespace()
        .next()
        .ok_or_else(|| InjectError::Msg("pidof empty".into()))?
        .parse()
        .map_err(|e: std::num::ParseIntError| InjectError::Msg(e.to_string()))?;
    Ok(pid)
}
