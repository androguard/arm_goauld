//! Host-side process discovery and ptrace injection (§3).

pub mod discover;
pub mod remote;
pub mod inject;
pub mod spawn;
pub mod syscall_trace;

pub use discover::{enumerate_processes, find_by_package, resolve_abi, ProcessInfo};
pub use inject::{find_libc, find_libdl, inject_library, InjectError, InjectOptions};
pub use remote::{RemoteCall, Tracee, TraceeError};
pub use syscall_trace::{syscall_name, trace_syscalls, SyscallTraceOptions};
