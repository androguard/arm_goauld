//! Embed git revision + build time into `goauld_proto::version_info()`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GOAULD_GIT_REV");
    println!("cargo:rerun-if-env-changed=GOAULD_BUILD_TIME");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");

    let git = std::env::var("GOAULD_GIT_REV").unwrap_or_else(|_| {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into())
    });

    let built = std::env::var("GOAULD_BUILD_TIME").unwrap_or_else(|_| {
        // UTC timestamp; portable enough without chrono.
        Command::new("date")
            .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".into())
    });

    println!("cargo:rustc-env=GOAULD_GIT_REV={git}");
    println!("cargo:rustc-env=GOAULD_BUILD_TIME={built}");
}
