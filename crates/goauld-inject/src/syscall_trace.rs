//! Ptrace-based syscall tracer (on-device aarch64 Android/Linux).
//!
//! Attaches with `PTRACE_SYSCALL` + `PTRACE_O_TRACESYSGOOD`, prints enter/exit
//! lines: `tid=… sys_name(args…) = retval`.

use crate::remote::TraceeError;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SyscallTraceOptions {
    /// Stop after this many enter events (0 = unlimited).
    pub max_events: u64,
    /// Wall-clock budget (None = until max_events / interrupt).
    pub duration: Option<Duration>,
    /// If non-empty, only print these syscall names (or `sys_<nr>`).
    pub filter: Vec<String>,
    /// Print enter lines only (skip exit/retval).
    pub enter_only: bool,
}

impl Default for SyscallTraceOptions {
    fn default() -> Self {
        Self {
            max_events: 0,
            duration: Some(Duration::from_secs(15)),
            filter: Vec::new(),
            enter_only: false,
        }
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
mod imp {
    use super::*;
    use libc::{c_long, c_void, pid_t, user_regs_struct};
    use std::collections::HashMap;
    use std::io::{self, Write};
    use std::mem;
    use std::ptr;
    use std::time::Instant;

    const NT_PRSTATUS: i32 = 1;
    const PTRACE_SEIZE: i32 = 0x4206;
    const PTRACE_INTERRUPT: i32 = 0x4207;
    const PTRACE_O_TRACESYSGOOD: i32 = 0x0000_0001;
    const PTRACE_O_TRACECLONE: i32 = 0x0000_0008;
    const PTRACE_O_TRACEFORK: i32 = 0x0000_0002;
    const PTRACE_O_TRACEVFORK: i32 = 0x0000_0004;
    // Intentionally NOT setting PTRACE_O_EXITKILL: when the injector exits
    // (host timeout, Ctrl-C, adb disconnect) that flag SIGKILLs the app.
    const PTRACE_EVENT_CLONE: i32 = 3;
    const PTRACE_EVENT_FORK: i32 = 1;
    const PTRACE_EVENT_VFORK: i32 = 2;
    /// Wait for all threads (needed with PTRACE_SEIZE of thread group).
    const __WALL: i32 = 0x4000_0000;

    struct Pending {
        nr: u64,
        args: [u64; 6],
    }

    pub fn trace_syscalls(pid: i32, opts: &SyscallTraceOptions) -> Result<u64, TraceeError> {
        let tids = list_tids(pid)?;
        let options = PTRACE_O_TRACESYSGOOD
            | PTRACE_O_TRACECLONE
            | PTRACE_O_TRACEFORK
            | PTRACE_O_TRACEVFORK;

        for &tid in &tids {
            seize_tid(tid, options)?;
        }
        for &tid in &tids {
            ptrace_syscall(tid)?;
        }

        let mut pending: HashMap<i32, Pending> = HashMap::new();
        let mut events: u64 = 0;
        let deadline = opts.duration.map(|d| Instant::now() + d);
        let filter: Vec<String> = opts
            .filter
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        let mut attached: Vec<i32> = tids.clone();

        let result = (|| -> Result<u64, TraceeError> {
            loop {
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        break;
                    }
                }
                if opts.max_events > 0 && events >= opts.max_events {
                    break;
                }

                let Some((tid, status)) = wait_any_deadline(deadline)? else {
                    break; // deadline / no children
                };

                if !attached.contains(&tid) {
                    attached.push(tid);
                }

                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    pending.remove(&tid);
                    attached.retain(|&t| t != tid);
                    continue;
                }
                if !libc::WIFSTOPPED(status) {
                    let _ = ptrace_syscall(tid);
                    continue;
                }

                let sig = libc::WSTOPSIG(status);
                let event = status >> 16;

                if event == PTRACE_EVENT_CLONE
                    || event == PTRACE_EVENT_FORK
                    || event == PTRACE_EVENT_VFORK
                {
                    if let Ok(new_tid) = get_eventmsg(tid) {
                        let new_tid = new_tid as i32;
                        let _ = seize_tid(new_tid, options);
                        let _ = ptrace_syscall(new_tid);
                        if !attached.contains(&new_tid) {
                            attached.push(new_tid);
                        }
                    }
                    let _ = ptrace_syscall(tid);
                    continue;
                }

                let is_syscall = sig == (libc::SIGTRAP | 0x80) || sig == libc::SIGTRAP;
                if !is_syscall {
                    let _ = ptrace_cont_signal(tid, if sig == libc::SIGTRAP { 0 } else { sig });
                    continue;
                }

                let mut regs: user_regs_struct = unsafe { mem::zeroed() };
                getregs(tid, &mut regs)?;

                if let Some(ent) = pending.remove(&tid) {
                    if !opts.enter_only {
                        let name = syscall_name(ent.nr);
                        if filter.is_empty()
                            || filter
                                .iter()
                                .any(|f| name.contains(f.as_str()) || f == &name)
                        {
                            let retval = regs.regs[0] as i64;
                            let call =
                                format_syscall_call(pid, &name, &ent.args, Some(retval));
                            let _ = writeln!(out, "[{tid}] {call} = {retval:#x}");
                            // adb shell is not a tty, so stdout is block-buffered.
                            // Flush each line or the host sees nothing until exit.
                            let _ = out.flush();
                        }
                    }
                } else {
                    let nr = regs.regs[8];
                    let name = syscall_name(nr);
                    let args = [
                        regs.regs[0],
                        regs.regs[1],
                        regs.regs[2],
                        regs.regs[3],
                        regs.regs[4],
                        regs.regs[5],
                    ];
                    let pass = filter.is_empty()
                        || filter
                            .iter()
                            .any(|f| name.contains(f.as_str()) || f == &name);
                    if pass && opts.enter_only {
                        // Enter: write* buffers are already valid; read* not yet filled.
                        let call = format_syscall_call(pid, &name, &args, None);
                        let _ = writeln!(out, "[{tid}] → {call}");
                        let _ = out.flush();
                    }
                    if pass {
                        events += 1;
                    }
                    pending.insert(tid, Pending { nr, args });
                }

                let _ = ptrace_syscall(tid);
            }
            Ok(events)
        })();

        detach_all(&attached);
        result
    }

    fn detach_all(tids: &[i32]) {
        for &tid in tids {
            // Stop the thread if it is still running so DETACH can resume it cleanly.
            let _ = unsafe {
                libc::ptrace(
                    PTRACE_INTERRUPT,
                    tid as pid_t,
                    ptr::null_mut::<c_void>(),
                    ptr::null_mut::<c_void>(),
                )
            };
            for _ in 0..50 {
                let mut status = 0i32;
                let rc = unsafe {
                    libc::waitpid(tid as pid_t, &mut status, libc::WNOHANG | __WALL)
                };
                if rc > 0 || rc < 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = unsafe {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    tid as pid_t,
                    ptr::null_mut::<c_void>(),
                    ptr::null_mut::<c_void>(),
                )
            };
        }
    }

    fn seize_tid(tid: i32, options: i32) -> Result<(), TraceeError> {
        let _ = unsafe {
            libc::ptrace(
                PTRACE_SEIZE,
                tid as pid_t,
                ptr::null_mut::<c_void>(),
                options as usize as *mut c_void,
            )
        };
        let _ = unsafe {
            libc::ptrace(
                PTRACE_INTERRUPT,
                tid as pid_t,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            )
        };
        let _ = wait_tid(tid);
        Ok(())
    }

    fn ptrace_syscall(tid: i32) -> Result<(), TraceeError> {
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                tid as pid_t,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            )
        };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "PTRACE_SYSCALL tid={tid}: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn ptrace_cont_signal(tid: i32, sig: i32) -> Result<(), TraceeError> {
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                tid as pid_t,
                ptr::null_mut::<c_void>(),
                sig as usize as *mut c_void,
            )
        };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "PTRACE_CONT: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Non-blocking wait that respects an optional wall-clock deadline.
    /// Returns `None` on deadline or when there are no waitable children.
    fn wait_any_deadline(deadline: Option<Instant>) -> Result<Option<(i32, i32)>, TraceeError> {
        loop {
            let mut status: i32 = 0;
            let tid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG | __WALL) };
            if tid > 0 {
                return Ok(Some((tid, status)));
            }
            if tid < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ECHILD) {
                    return Ok(None);
                }
                return Err(TraceeError::Wait(err.to_string()));
            }
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Ok(None);
                }
            }
            // Short sleep so we can honor duration without spinning hard.
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_tid(tid: i32) -> Result<i32, TraceeError> {
        let mut status: i32 = 0;
        let rc = unsafe { libc::waitpid(tid as pid_t, &mut status, __WALL) };
        if rc < 0 {
            return Err(TraceeError::Wait(io::Error::last_os_error().to_string()));
        }
        Ok(status)
    }

    fn getregs(tid: i32, regs: &mut user_regs_struct) -> Result<(), TraceeError> {
        let mut iov = libc::iovec {
            iov_base: regs as *mut _ as *mut c_void,
            iov_len: mem::size_of::<user_regs_struct>(),
        };
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                tid as pid_t,
                NT_PRSTATUS as *mut c_void,
                &mut iov as *mut _ as *mut c_void,
            )
        };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "GETREGSET: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn get_eventmsg(tid: i32) -> Result<c_long, TraceeError> {
        let mut msg: c_long = 0;
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETEVENTMSG,
                tid as pid_t,
                ptr::null_mut::<c_void>(),
                &mut msg as *mut _ as *mut c_void,
            )
        };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "GETEVENTMSG: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(msg)
    }

    fn list_tids(pid: i32) -> Result<Vec<i32>, TraceeError> {
        let mut tids = Vec::new();
        let path = format!("/proc/{pid}/task");
        for e in std::fs::read_dir(&path)? {
            let e = e?;
            if let Ok(tid) = e.file_name().to_string_lossy().parse::<i32>() {
                tids.push(tid);
            }
        }
        if tids.is_empty() {
            tids.push(pid);
        }
        Ok(tids)
    }

    /// Cap for dumped buffer / path previews (strace `-s` analogue).
    const MAX_DUMP: usize = 128;

    /// Pretty-print syscall + decoded parameters (paths / buffers / sockaddr).
    ///
    /// `retval`: `Some` on syscall-exit (use for `read`/`recv*` lengths); `None` on enter.
    fn format_syscall_call(
        pid: i32,
        name: &str,
        args: &[u64; 6],
        retval: Option<i64>,
    ) -> String {
        match name {
            "openat" | "faccessat" | "fstatat" | "readlinkat" | "execveat" | "unlinkat"
            | "fchmodat" | "mkdirat" | "mknodat" => {
                let path = peek_cstr(pid, args[1]).unwrap_or_else(|| format!("{:#x}", args[1]));
                format!(
                    "{name}({:#x}, \"{}\", {:#x}, {:#x})",
                    args[0],
                    escape_str(&path),
                    args[2],
                    args[3]
                )
            }
            "open" | "execve" | "access" | "stat" | "lstat" | "unlink" | "chdir" | "mkdir"
            | "rmdir" | "readlink" | "chmod" => {
                let path = peek_cstr(pid, args[0]).unwrap_or_else(|| format!("{:#x}", args[0]));
                format!(
                    "{name}(\"{}\", {:#x}, {:#x}, {:#x})",
                    escape_str(&path),
                    args[1],
                    args[2],
                    args[3]
                )
            }
            "lseek" => format!(
                "lseek({:#x}, {:#x}, whence={:#x})",
                args[0], args[1], args[2]
            ),
            "read" | "write" | "pread64" | "pwrite64" => {
                let fd = args[0];
                let buf = args[1];
                let count = args[2] as usize;
                let dump_len = buffer_dump_len(name, count, retval);
                let preview = format_mem_preview(pid, buf, dump_len);
                if name.starts_with('p') {
                    format!("{name}({fd:#x}, {preview}, {count:#x}, {:#x})", args[3])
                } else {
                    format!("{name}({fd:#x}, {preview}, {count:#x})")
                }
            }
            "readv" | "writev" | "preadv" | "pwritev" => {
                let fd = args[0];
                let iov = args[1];
                let iovcnt = args[2] as usize;
                let preview = format_iovec_preview(pid, name, iov, iovcnt, retval);
                format!("{name}({fd:#x}, {preview}, {iovcnt})")
            }
            "sendto" | "recvfrom" => {
                let dump_len = buffer_dump_len(name, args[2] as usize, retval);
                let preview = format_mem_preview(pid, args[1], dump_len);
                let sa = if args[4] != 0 {
                    peek_sockaddr(pid, args[4], args[5] as usize)
                        .unwrap_or_else(|| format!("{:#x}", args[4]))
                } else {
                    "null".into()
                };
                format!(
                    "{name}({:#x}, {preview}, {:#x}, {:#x}, {sa}, {:#x})",
                    args[0], args[2], args[3], args[5]
                )
            }
            "sendmsg" | "recvmsg" => {
                format!("{name}({:#x}, {:#x}, {:#x})", args[0], args[1], args[2])
            }
            "connect" | "bind" => {
                let sa = peek_sockaddr(pid, args[1], args[2] as usize)
                    .unwrap_or_else(|| format!("{:#x}", args[1]));
                format!("{name}({:#x}, {sa}, {:#x})", args[0], args[2])
            }
            "socket" => format!(
                "socket(domain={:#x}, type={:#x}, proto={:#x})",
                args[0], args[1], args[2]
            ),
            "mmap" | "mprotect" | "munmap" => format!(
                "{name}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                args[0], args[1], args[2], args[3], args[4], args[5]
            ),
            "clone" => format!(
                "clone(flags={:#x}, stack={:#x}, ptid={:#x}, tls={:#x}, ctid={:#x})",
                args[0], args[1], args[2], args[3], args[4]
            ),
            "ioctl" => format!("ioctl({:#x}, {:#x}, {:#x})", args[0], args[1], args[2]),
            "prctl" => format!(
                "prctl({:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                args[0], args[1], args[2], args[3], args[4]
            ),
            "futex" => format!(
                "futex({:#x}, op={:#x}, val={:#x}, …)",
                args[0], args[1], args[2]
            ),
            "clock_gettime" | "nanosleep" => {
                format!("{name}({:#x}, {:#x})", args[0], args[1])
            }
            "close" | "getpid" | "gettid" | "getuid" | "geteuid" | "getppid" | "sched_yield" => {
                format!("{name}({:#x})", args[0])
            }
            _ => format!(
                "{name}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                args[0], args[1], args[2], args[3], args[4], args[5]
            ),
        }
    }

    /// How many bytes to dump from a userspace buffer.
    ///
    /// - `read`/`recv*`: only dump after a successful exit (`retval`), else 0 on enter.
    /// - `write`/`send*`: dump the outbound length (capped); on exit prefer `retval`.
    fn buffer_dump_len(name: &str, count: usize, retval: Option<i64>) -> usize {
        let count = count.min(MAX_DUMP);
        let is_inbound = matches!(
            name,
            "read"
                | "readv"
                | "pread64"
                | "preadv"
                | "recvfrom"
                | "recvmsg"
                | "recvmmsg"
        );
        match (is_inbound, retval) {
            (true, Some(n)) if n > 0 => (n as usize).min(count).min(MAX_DUMP),
            (true, _) => 0,
            (false, Some(n)) if n > 0 => (n as usize).min(count).min(MAX_DUMP),
            (false, Some(n)) if n < 0 => 0,
            (false, _) => count,
        }
    }

    fn format_mem_preview(pid: i32, addr: u64, len: usize) -> String {
        if addr < 0x1000 {
            return format!("{addr:#x}");
        }
        if len == 0 {
            return format!("{addr:#x}");
        }
        match peek_bytes(pid, addr, len) {
            Some(buf) => format_bytes_literal(&buf, /*truncated*/ len >= MAX_DUMP),
            None => format!("{addr:#x}"),
        }
    }

    /// Decode `struct iovec { void *iov_base; size_t iov_len; }` (16 bytes on aarch64).
    fn format_iovec_preview(
        pid: i32,
        name: &str,
        iov_addr: u64,
        iovcnt: usize,
        retval: Option<i64>,
    ) -> String {
        if iov_addr < 0x1000 || iovcnt == 0 {
            return format!("{iov_addr:#x}");
        }
        let nvec = iovcnt.min(8);
        let raw = match peek_bytes(pid, iov_addr, nvec * 16) {
            Some(b) if b.len() >= 16 => b,
            _ => return format!("{iov_addr:#x}"),
        };

        let is_inbound = name.starts_with("read") || name.starts_with("recv");
        let mut remaining = match (is_inbound, retval) {
            (true, Some(n)) if n > 0 => n as usize,
            (true, _) => 0,
            (false, Some(n)) if n > 0 => n as usize,
            (false, Some(n)) if n < 0 => 0,
            (false, _) => MAX_DUMP,
        };
        if remaining == 0 && is_inbound {
            return format!("[{nvec} iov @ {iov_addr:#x}]");
        }
        remaining = remaining.min(MAX_DUMP);

        let mut parts = Vec::new();
        let mut total = 0usize;
        for i in 0..nvec {
            if total >= MAX_DUMP || remaining == 0 {
                parts.push("…".into());
                break;
            }
            let off = i * 16;
            if off + 16 > raw.len() {
                break;
            }
            let base = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
            let ilen = usize::from_le_bytes(raw[off + 8..off + 16].try_into().unwrap());
            let take = ilen.min(remaining).min(MAX_DUMP - total);
            let preview = format_mem_preview(pid, base, take);
            parts.push(format!("{{base={base:#x}, len={ilen}, data={preview}}}"));
            total += take;
            remaining = remaining.saturating_sub(take);
        }
        if iovcnt > nvec {
            parts.push(format!("/* +{} iov */", iovcnt - nvec));
        }
        format!("[{}]", parts.join(", "))
    }

    fn format_bytes_literal(buf: &[u8], truncated: bool) -> String {
        let printable = buf
            .iter()
            .filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r')
            .count();
        let mostly_text = !buf.is_empty() && printable * 100 / buf.len() >= 70;

        let mut out = String::from("\"");
        if mostly_text {
            for &b in buf {
                match b {
                    b'\\' => out.push_str("\\\\"),
                    b'"' => out.push_str("\\\""),
                    b'\n' => out.push_str("\\n"),
                    b'\r' => out.push_str("\\r"),
                    b'\t' => out.push_str("\\t"),
                    0x20..=0x7e => out.push(b as char),
                    _ => out.push_str(&format!("\\x{b:02x}")),
                }
            }
        } else {
            for &b in buf {
                out.push_str(&format!("\\x{b:02x}"));
            }
        }
        out.push('"');
        if truncated {
            out.push_str("…");
        }
        out
    }

    fn peek_bytes(pid: i32, addr: u64, len: usize) -> Option<Vec<u8>> {
        if addr < 0x1000 || len == 0 {
            return None;
        }
        let mut try_len = len.min(MAX_DUMP);
        while try_len > 0 {
            if let Ok(buf) = crate::remote::read_memory(pid, addr, try_len) {
                return Some(buf);
            }
            // Cross-page / partial mapping: shrink and retry.
            try_len = if try_len > 64 {
                try_len / 2
            } else if try_len > 16 {
                16
            } else if try_len > 1 {
                try_len - 1
            } else {
                break;
            };
        }
        None
    }

    fn escape_str(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    fn peek_cstr(pid: i32, addr: u64) -> Option<String> {
        if addr < 0x1000 {
            return None;
        }
        let buf = peek_bytes(pid, addr, 256)?;
        let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len().min(200));
        let s = String::from_utf8_lossy(&buf[..nul]).into_owned();
        if s.is_empty() {
            return None;
        }
        // Reject obviously non-text.
        let ok = s
            .chars()
            .all(|c| c == '\t' || c == '\n' || (!c.is_control() && c != '\0'));
        if ok {
            Some(s)
        } else {
            None
        }
    }

    fn peek_sockaddr(pid: i32, addr: u64, len: usize) -> Option<String> {
        if addr < 0x1000 || len == 0 {
            return None;
        }
        let n = len.min(128).max(2);
        let buf = peek_bytes(pid, addr, n)?;
        if buf.len() < 2 {
            return None;
        }
        let family = u16::from_le_bytes([buf[0], buf[1]]);
        match family {
            1 => {
                // AF_UNIX
                let path = if buf.len() > 2 {
                    let rest = &buf[2..];
                    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len().min(108));
                    String::from_utf8_lossy(&rest[..end]).into_owned()
                } else {
                    String::new()
                };
                Some(format!("{{AF_UNIX,\"{}\"}}", escape_str(&path)))
            }
            2 => {
                // AF_INET: sin_port @2, sin_addr @4
                if buf.len() < 8 {
                    return Some("{AF_INET,…}".into());
                }
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
                Some(format!("{{AF_INET,{ip}:{port}}}"))
            }
            10 => {
                // AF_INET6 — print port + abbreviated
                if buf.len() < 24 {
                    return Some("{AF_INET6,…}".into());
                }
                let port = u16::from_be_bytes([buf[2], buf[3]]);
                Some(format!("{{AF_INET6,port={port}}}"))
            }
            other => Some(format!("{{af={other},…}}")),
        }
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub use imp::trace_syscalls;

#[cfg(not(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
)))]
pub fn trace_syscalls(_pid: i32, _opts: &SyscallTraceOptions) -> Result<u64, TraceeError> {
    Err(TraceeError::Unsupported)
}

/// aarch64 Linux/Android syscall names (`asm-generic` / arm64).
/// Unknown numbers still print as `sys_<nr>`.
pub fn syscall_name(nr: u64) -> String {
    let name = match nr {
        0 => "io_setup",
        1 => "io_destroy",
        2 => "io_submit",
        3 => "io_cancel",
        4 => "io_getevents",
        17 => "getcwd",
        19 => "eventfd2",
        20 => "epoll_create1",
        21 => "epoll_ctl",
        22 => "epoll_pwait",
        23 => "dup",
        24 => "dup3",
        25 => "fcntl",
        26 => "inotify_init1",
        27 => "inotify_add_watch",
        28 => "inotify_rm_watch",
        29 => "ioctl",
        32 => "flock",
        33 => "mknodat",
        34 => "mkdirat",
        35 => "unlinkat",
        36 => "symlinkat",
        37 => "linkat",
        38 => "renameat",
        43 => "statfs",
        44 => "fstatfs",
        45 => "truncate",
        46 => "ftruncate",
        47 => "fallocate",
        48 => "faccessat",
        49 => "chdir",
        50 => "fchdir",
        52 => "fchmod",
        53 => "fchmodat",
        54 => "fchownat",
        55 => "fchown",
        56 => "openat",
        57 => "close",
        59 => "pipe2",
        61 => "getdents64",
        62 => "lseek",
        63 => "read",
        64 => "write",
        65 => "readv",
        66 => "writev",
        67 => "pread64",
        68 => "pwrite64",
        69 => "preadv",
        70 => "pwritev",
        71 => "sendfile",
        72 => "pselect6",
        73 => "ppoll",
        74 => "signalfd4",
        78 => "readlinkat",
        79 => "fstatat",
        80 => "fstat",
        81 => "sync",
        82 => "fsync",
        83 => "fdatasync",
        85 => "timerfd_create",
        86 => "timerfd_settime",
        87 => "timerfd_gettime",
        88 => "utimensat",
        93 => "exit",
        94 => "exit_group",
        95 => "waitid",
        96 => "set_tid_address",
        97 => "unshare",
        98 => "futex",
        99 => "set_robust_list",
        100 => "get_robust_list",
        101 => "nanosleep",
        102 => "getitimer",
        103 => "setitimer",
        113 => "clock_gettime",
        114 => "clock_getres",
        115 => "clock_nanosleep",
        116 => "syslog",
        117 => "ptrace",
        118 => "sched_setparam",
        119 => "sched_setscheduler",
        120 => "sched_getscheduler",
        121 => "sched_getparam",
        122 => "sched_setaffinity",
        123 => "sched_getaffinity",
        124 => "sched_yield",
        125 => "sched_get_priority_max",
        126 => "sched_get_priority_min",
        127 => "sched_rr_get_interval",
        128 => "restart_syscall",
        129 => "kill",
        130 => "tkill",
        131 => "tgkill",
        132 => "sigaltstack",
        133 => "rt_sigsuspend",
        134 => "rt_sigaction",
        135 => "rt_sigprocmask",
        136 => "rt_sigpending",
        137 => "rt_sigtimedwait",
        138 => "rt_sigqueueinfo",
        139 => "rt_sigreturn",
        140 => "setpriority",
        141 => "getpriority",
        143 => "setregid",
        144 => "setgid",
        145 => "setreuid",
        146 => "setuid",
        147 => "setresuid",
        148 => "getresuid",
        149 => "setresgid",
        150 => "getresgid",
        151 => "setfsuid",
        152 => "setfsgid",
        153 => "times",
        154 => "setpgid",
        155 => "getpgid",
        156 => "getsid",
        157 => "setsid",
        158 => "getgroups",
        159 => "setgroups",
        160 => "uname",
        163 => "getrlimit",
        164 => "setrlimit",
        165 => "getrusage",
        166 => "umask",
        167 => "prctl",
        168 => "getcpu",
        169 => "gettimeofday",
        172 => "getpid",
        173 => "getppid",
        174 => "getuid",
        175 => "geteuid",
        176 => "getgid",
        177 => "getegid",
        178 => "gettid",
        179 => "sysinfo",
        198 => "socket",
        199 => "socketpair",
        200 => "bind",
        201 => "listen",
        202 => "accept",
        203 => "connect",
        204 => "getsockname",
        205 => "getpeername",
        206 => "sendto",
        207 => "recvfrom",
        208 => "setsockopt",
        209 => "getsockopt",
        210 => "shutdown",
        211 => "sendmsg",
        212 => "recvmsg",
        213 => "readahead",
        214 => "brk",
        215 => "munmap",
        216 => "mremap",
        217 => "add_key",
        218 => "request_key",
        219 => "keyctl",
        220 => "clone",
        221 => "execve",
        222 => "mmap",
        223 => "fadvise64",
        224 => "swapon",
        225 => "swapoff",
        226 => "mprotect",
        227 => "msync",
        228 => "mlock",
        229 => "munlock",
        230 => "mlockall",
        231 => "munlockall",
        232 => "mincore",
        233 => "madvise",
        234 => "remap_file_pages",
        235 => "mbind",
        236 => "get_mempolicy",
        237 => "set_mempolicy",
        238 => "migrate_pages",
        239 => "move_pages",
        240 => "rt_tgsigqueueinfo",
        241 => "perf_event_open",
        242 => "accept4",
        243 => "recvmmsg",
        260 => "wait4",
        261 => "prlimit64",
        262 => "fanotify_init",
        263 => "fanotify_mark",
        264 => "name_to_handle_at",
        265 => "open_by_handle_at",
        266 => "clock_adjtime",
        267 => "syncfs",
        268 => "setns",
        269 => "sendmmsg",
        270 => "process_vm_readv",
        271 => "process_vm_writev",
        272 => "kcmp",
        273 => "finit_module",
        274 => "sched_setattr",
        275 => "sched_getattr",
        276 => "renameat2",
        277 => "seccomp",
        278 => "getrandom",
        279 => "memfd_create",
        280 => "bpf",
        281 => "execveat",
        282 => "userfaultfd",
        283 => "membarrier",
        284 => "mlock2",
        285 => "copy_file_range",
        286 => "preadv2",
        287 => "pwritev2",
        288 => "pkey_mprotect",
        291 => "statx",
        292 => "io_pgetevents",
        293 => "rseq",
        424 => "pidfd_send_signal",
        434 => "pidfd_open",
        435 => "clone3",
        436 => "close_range",
        437 => "openat2",
        438 => "pidfd_getfd",
        439 => "faccessat2",
        441 => "epoll_pwait2",
        447 => "memfd_secret",
        450 => "set_mempolicy_home_node",
        _ => "",
    };
    if name.is_empty() {
        format!("sys_{nr}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_common() {
        assert_eq!(syscall_name(22), "epoll_pwait");
        assert_eq!(syscall_name(25), "fcntl");
        assert_eq!(syscall_name(29), "ioctl");
        assert_eq!(syscall_name(63), "read");
        assert_eq!(syscall_name(64), "write");
        assert_eq!(syscall_name(56), "openat");
        assert_eq!(syscall_name(135), "rt_sigprocmask");
        assert_eq!(syscall_name(203), "connect");
        assert_eq!(syscall_name(278), "getrandom");
        assert_eq!(syscall_name(9999), "sys_9999");
    }
}
