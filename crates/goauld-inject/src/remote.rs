//! Remote function call via ptrace (§3.2 RemoteCall abstraction).
//!
//! **Runs on-device** (aarch64 Android / Linux). The desktop host never ptrace's
//! app processes itself — it pushes [`goauld-injector`](../../goauld-injector)
//! and invokes it over `adb shell`.

use thiserror::Error;

/// True when this crate is built as the on-device arm64 injector.
#[macro_export]
macro_rules! cfg_on_device_aarch64 {
    ($($item:item)*) => {
        $(
            #[cfg(all(
                any(target_os = "linux", target_os = "android"),
                target_arch = "aarch64"
            ))]
            $item
        )*
    };
}

#[derive(Debug, Error)]
pub enum TraceeError {
    #[error("ptrace unsupported on this host (need on-device aarch64 Android/Linux)")]
    Unsupported,
    #[error("ptrace: {0}")]
    Ptrace(String),
    #[error("waitpid: {0}")]
    Wait(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

/// A seized, stopped process (all threads quiescent).
pub struct Tracee {
    pub pid: i32,
    pub tids: Vec<i32>,
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    saved_regs: Option<libc::user_regs_struct>,
}

impl Tracee {
    /// Seize main thread then every tid under `/proc/<pid>/task`, interrupt, wait stop.
    pub fn seize(pid: i32) -> Result<Self, TraceeError> {
        #[cfg(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        ))]
        {
            return device::seize(pid);
        }
        #[cfg(not(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        )))]
        {
            let _ = pid;
            Err(TraceeError::Unsupported)
        }
    }

    pub fn detach(self) -> Result<(), TraceeError> {
        #[cfg(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        ))]
        {
            return device::detach(self);
        }
        #[cfg(not(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        )))]
        {
            Ok(())
        }
    }
}

pub struct RemoteCall<'a> {
    pub tracee: &'a Tracee,
}

impl RemoteCall<'_> {
    /// Call `func_addr` with AAPCS64 args in x0–x7; return x0.
    pub fn call(&self, func_addr: u64, args: &[u64]) -> Result<u64, TraceeError> {
        if args.len() > 8 {
            return Err(TraceeError::Msg("too many args (max 8)".into()));
        }
        #[cfg(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        ))]
        {
            return device::remote_call(self.tracee, func_addr, args);
        }
        #[cfg(not(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        )))]
        {
            let _ = (func_addr, args, self.tracee);
            Err(TraceeError::Unsupported)
        }
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
mod device {
    use super::*;
    use std::fs;
    use std::mem;
    use std::ptr;

    const NT_PRSTATUS: i32 = 1;

    /// PTRACE_SEIZE / INTERRUPT / options — values match Linux uapi (bionic too).
    const PTRACE_SEIZE: i32 = 0x4206;
    const PTRACE_INTERRUPT: i32 = 0x4207;
    const PTRACE_O_EXITKILL: i32 = 0x0010_0000;
    const PTRACE_O_TRACEEXIT: i32 = 0x0000_0040;
    const __WALL: i32 = 0x4000_0000;

    pub(super) fn seize(pid: i32) -> Result<Tracee, TraceeError> {
        let tids = list_tids(pid)?;
        eprintln!("goauld-inject: seize pid={pid} tids={tids:?}");
        for &tid in &tids {
            // Prefer SEIZE; fall back to ATTACH on older/odd kernels.
            let rc = unsafe {
                libc::ptrace(
                    PTRACE_SEIZE,
                    tid,
                    ptr::null_mut::<libc::c_void>(),
                    (PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL) as usize as *mut libc::c_void,
                )
            };
            if rc != 0 {
                eprintln!(
                    "goauld-inject: SEIZE tid={tid} failed ({}); trying ATTACH",
                    std::io::Error::last_os_error()
                );
                let rc = unsafe {
                    libc::ptrace(
                        libc::PTRACE_ATTACH,
                        tid,
                        ptr::null_mut::<libc::c_void>(),
                        ptr::null_mut::<libc::c_void>(),
                    )
                };
                if rc != 0 {
                    return Err(TraceeError::Ptrace(format!(
                        "ATTACH tid={tid}: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            } else {
                let rc = unsafe {
                    libc::ptrace(
                        PTRACE_INTERRUPT,
                        tid,
                        ptr::null_mut::<libc::c_void>(),
                        ptr::null_mut::<libc::c_void>(),
                    )
                };
                if rc != 0 {
                    return Err(TraceeError::Ptrace(format!(
                        "INTERRUPT tid={tid}: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            }
            wait_stop(tid)?;
            eprintln!("goauld-inject: tid={tid} stopped");
        }
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        getregs(pid, &mut regs)?;
        eprintln!(
            "goauld-inject: regs pc={:#x} sp={:#x} x0={:#x}",
            regs.pc, regs.sp, regs.regs[0]
        );
        Ok(Tracee {
            pid,
            tids,
            saved_regs: Some(regs),
        })
    }

    pub(super) fn detach(tracee: Tracee) -> Result<(), TraceeError> {
        if let Some(regs) = tracee.saved_regs {
            setregs(tracee.pid, &regs)?;
        }
        for tid in tracee.tids {
            let rc = unsafe {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    tid,
                    ptr::null_mut::<libc::c_void>(),
                    ptr::null_mut::<libc::c_void>(),
                )
            };
            if rc != 0 {
                log::warn!("DETACH tid={tid}: {}", std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) fn remote_call(
        tracee: &Tracee,
        func_addr: u64,
        args: &[u64],
    ) -> Result<u64, TraceeError> {
        // Prefer an executable BRK gadget; fall back to caller-provided via
        // remote_call_with_lr once the injector has an RX scratch page.
        let lr = find_brk_gadget(tracee.pid)
            .or_else(|_| Err(TraceeError::Msg(
                "no brk gadget — use remote_call_with_lr after planting one".into(),
            )))?;
        remote_call_with_lr(tracee, func_addr, args, lr)
    }

    pub fn remote_call_stub(
        tracee: &Tracee,
        stub_addr: u64,
        args: &[u64],
    ) -> Result<u64, TraceeError> {
        // Stub layout (16 bytes + literal):
        //   +0  LDR X16, #12
        //   +4  BLR X16
        //   +8  BRK #0   ← expected landing after callee returns
        //   +12 <u64 callee>
        let brk_pc = stub_addr + 8;
        let tid = tracee.pid;
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        getregs(tid, &mut regs)?;
        let backup = regs;
        for (i, a) in args.iter().enumerate() {
            regs.regs[i] = *a;
        }
        regs.pc = stub_addr;
        setregs(tid, &regs)?;
        eprintln!("goauld-inject: run stub @{stub_addr:#x} brk={brk_pc:#x} args={args:?}");
        let ret = match cont_until_pc(tid, brk_pc) {
            Ok(v) => v,
            Err(e) => {
                let _ = setregs(tid, &backup);
                return Err(e);
            }
        };
        eprintln!("goauld-inject: stub done ret={ret:#x}");
        setregs(tid, &backup)?;
        Ok(ret)
    }

    pub fn remote_call_with_lr(
        tracee: &Tracee,
        func_addr: u64,
        args: &[u64],
        lr: u64,
    ) -> Result<u64, TraceeError> {
        let tid = tracee.pid;
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        getregs(tid, &mut regs)?;
        let backup = regs;

        for (i, a) in args.iter().enumerate() {
            regs.regs[i] = *a;
        }

        eprintln!(
            "goauld-inject: remote_call func={func_addr:#x} lr={lr:#x} args={args:?}"
        );
        regs.regs[30] = lr;
        regs.pc = func_addr;
        setregs(tid, &regs)?;
        let ret = match cont_until_pc(tid, lr) {
            Ok(v) => v,
            Err(e) => {
                let _ = setregs(tid, &backup);
                return Err(e);
            }
        };
        eprintln!("goauld-inject: remote_call returned {ret:#x}");
        setregs(tid, &backup)?;
        Ok(ret)
    }

    /// `PTRACE_CONT` until `pc` lands on `expected_pc` (typically a planted BRK).
    /// Intermediate stops (spurious traps, signals) are logged and resumed with
    /// signal 0 so the remote call can finish.
    fn cont_until_pc(tid: i32, expected_pc: u64) -> Result<u64, TraceeError> {
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        for step in 0..64u32 {
            let rc = unsafe {
                libc::ptrace(
                    libc::PTRACE_CONT,
                    tid,
                    ptr::null_mut::<libc::c_void>(),
                    ptr::null_mut::<libc::c_void>(),
                )
            };
            if rc != 0 {
                return Err(TraceeError::Ptrace(format!(
                    "CONT: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let status = wait_stop_status(tid)?;
            getregs(tid, &mut regs)?;
            let sig = if libc::WIFSTOPPED(status) {
                libc::WSTOPSIG(status)
            } else {
                0
            };
            let event = status >> 16;
            eprintln!(
                "goauld-inject: stop#{step} status={status:#x} sig={sig} event={event} pc={:#x} x0={:#x} lr={:#x} sp={:#x}",
                regs.pc, regs.regs[0], regs.regs[30], regs.sp
            );
            // Landed on BRK (PC at insn) or just after.
            if regs.pc == expected_pc || regs.pc == expected_pc + 4 {
                return Ok(regs.regs[0]);
            }
            // Fatal faults — don't spin.
            if matches!(sig, 4 | 7 | 8 | 11) {
                // SIGILL, SIGBUS, SIGFPE, SIGSEGV
                return Err(TraceeError::Msg(format!(
                    "remote call fault sig={sig} pc={:#x} x0={:#x} (want brk {expected_pc:#x})",
                    regs.pc, regs.regs[0]
                )));
            }
        }
        getregs(tid, &mut regs)?;
        Err(TraceeError::Msg(format!(
            "remote call did not reach brk {expected_pc:#x}; last pc={:#x}",
            regs.pc
        )))
    }

    /// Remote mmap via direct SVC using an *existing* `svc #0` gadget in the
    /// target's libc (avoids writing new instructions + I-cache flush).
    pub fn remote_mmap_svc(
        tracee: &Tracee,
        size: u64,
        prot: u64,
        flags: u64,
    ) -> Result<u64, TraceeError> {
        let tid = tracee.pid;
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        getregs(tid, &mut regs)?;
        let backup = regs;

        let svc_addr = find_svc_gadget(tid)?;
        eprintln!("goauld-inject: remote_mmap via svc gadget @{svc_addr:#x}");

        // AArch64 Linux/Android mmap: nr=222
        regs.regs[8] = 222;
        regs.regs[0] = 0;
        regs.regs[1] = size;
        regs.regs[2] = prot;
        regs.regs[3] = flags;
        regs.regs[4] = (-1i64) as u64;
        regs.regs[5] = 0;
        // Return to a BRK we temporarily plant in the *original* PC page after
        // the syscall instruction would return — instead: use PTRACE_SYSCALL
        // stop-on-exit so we never need a BRK cave.
        regs.pc = svc_addr;
        setregs(tid, &regs)?;

        // Syscall-enter stop then syscall-exit stop.
        syscall_step(tid)?; // runs until syscall entry (already at svc — may be entry or need one step)
        // After first SYSCALL, we may be at entry or exit depending on PC alignment.
        // Issue another SYSCALL to ensure we observe the exit with result in x0.
        syscall_step(tid)?;

        getregs(tid, &mut regs)?;
        let ret = regs.regs[0];
        eprintln!("goauld-inject: mmap returned {ret:#x}");
        setregs(tid, &backup)?;
        Ok(ret)
    }

    /// Remote mprotect via svc gadget (nr=226 on aarch64).
    pub fn remote_mprotect_svc(
        tracee: &Tracee,
        addr: u64,
        len: u64,
        prot: u64,
    ) -> Result<u64, TraceeError> {
        let tid = tracee.pid;
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        getregs(tid, &mut regs)?;
        let backup = regs;
        let svc_addr = find_svc_gadget(tid)?;
        regs.regs[8] = 226; // mprotect
        regs.regs[0] = addr;
        regs.regs[1] = len;
        regs.regs[2] = prot;
        regs.pc = svc_addr;
        setregs(tid, &regs)?;
        syscall_step(tid)?;
        syscall_step(tid)?;
        getregs(tid, &mut regs)?;
        let ret = regs.regs[0];
        eprintln!("goauld-inject: mprotect returned {ret}");
        setregs(tid, &backup)?;
        Ok(ret)
    }

    fn syscall_step(tid: i32) -> Result<(), TraceeError> {
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                tid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            )
        };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "SYSCALL: {}",
                std::io::Error::last_os_error()
            )));
        }
        wait_stop(tid)
    }

    /// Scan executable mappings for a `brk #0` instruction (LR landing pad).
    fn find_brk_gadget(pid: i32) -> Result<u64, TraceeError> {
        const BRK0: [u8; 4] = [0x00, 0x00, 0x20, 0xD4]; // brk #0
        scan_exec_gadget(pid, &BRK0, "brk #0")
    }

    fn scan_exec_gadget(pid: i32, needle: &[u8; 4], label: &str) -> Result<u64, TraceeError> {
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|e| TraceeError::Msg(e.to_string()))?;
        for line in maps.lines() {
            if !(line.contains("r-xp") || line.contains("r-x")) {
                continue;
            }
            // Prefer libc / linker / libdl text.
            if !(line.contains("libc.so")
                || line.contains("libdl.so")
                || line.contains("/linker"))
            {
                continue;
            }
            let range = line.split_whitespace().next().unwrap_or("");
            let mut segs = range.split('-');
            let start = u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
            let end = u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
            if end <= start {
                continue;
            }
            let len = (end - start).min(0x20_0000) as usize;
            let buf = read_memory(pid, start, len)?;
            for i in (0..buf.len().saturating_sub(4)).step_by(4) {
                if buf[i..i + 4] == *needle {
                    return Ok(start + i as u64);
                }
            }
        }
        Err(TraceeError::Msg(format!("{label} gadget not found")))
    }

    /// Scan the target's libc executable mapping for an `svc #0` instruction.
    fn find_svc_gadget(pid: i32) -> Result<u64, TraceeError> {
        const SVC0: [u8; 4] = [0x01, 0x00, 0x00, 0xD4]; // svc #0
        scan_exec_gadget(pid, &SVC0, "svc #0")
    }

    pub fn write_memory(pid: i32, addr: u64, data: &[u8]) -> Result<(), TraceeError> {
        let local = libc::iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut _,
            iov_len: data.len(),
        };
        let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
        if n == data.len() as isize {
            return Ok(());
        }
        let mut padded = data.to_vec();
        while padded.len() % 8 != 0 {
            padded.push(0);
        }
        for (i, chunk) in padded.chunks(8).enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            let w = u64::from_le_bytes(word);
            let rc = unsafe {
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    pid,
                    (addr + (i as u64) * 8) as *mut libc::c_void,
                    w as *mut libc::c_void,
                )
            };
            if rc != 0 {
                return Err(TraceeError::Ptrace(format!(
                    "POKEDATA: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }

    pub fn read_memory(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>, TraceeError> {
        let mut buf = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr as *mut _,
            iov_len: len,
        };
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n == len as isize {
            return Ok(buf);
        }
        Err(TraceeError::Msg(format!(
            "process_vm_readv short read ({n}/{len}): {}",
            std::io::Error::last_os_error()
        )))
    }

    fn list_tids(pid: i32) -> Result<Vec<i32>, TraceeError> {
        let path = format!("/proc/{pid}/task");
        let mut tids = Vec::new();
        for e in fs::read_dir(path)? {
            let e = e?;
            if let Ok(t) = e.file_name().to_string_lossy().parse::<i32>() {
                tids.push(t);
            }
        }
        if tids.is_empty() {
            tids.push(pid);
        }
        Ok(tids)
    }

    fn wait_stop(tid: i32) -> Result<(), TraceeError> {
        wait_stop_status(tid).map(|_| ())
    }

    fn wait_stop_status(tid: i32) -> Result<i32, TraceeError> {
        let mut status = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let w = unsafe { libc::waitpid(tid, &mut status, __WALL) };
            if w < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(TraceeError::Wait(err.to_string()));
            }
            if w == tid {
                if libc::WIFSTOPPED(status) {
                    return Ok(status);
                }
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    return Err(TraceeError::Wait(format!("tid {tid} exited: {status:#x}")));
                }
            }
            if std::time::Instant::now() > deadline {
                return Err(TraceeError::Wait(format!(
                    "timeout waiting for tid {tid} stop"
                )));
            }
        }
    }

    fn getregs(tid: i32, regs: &mut libc::user_regs_struct) -> Result<(), TraceeError> {
        let mut iov = libc::iovec {
            iov_base: regs as *mut _ as *mut _,
            iov_len: mem::size_of::<libc::user_regs_struct>(),
        };
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                tid,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _,
            )
        };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "GETREGSET: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn setregs(tid: i32, regs: &libc::user_regs_struct) -> Result<(), TraceeError> {
        let mut iov = libc::iovec {
            iov_base: regs as *const _ as *mut _,
            iov_len: mem::size_of::<libc::user_regs_struct>(),
        };
        let rc = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                tid,
                NT_PRSTATUS as *mut libc::c_void,
                &mut iov as *mut _,
            )
        };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "SETREGSET: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn peek_data(tid: i32, addr: u64, out: &mut [u64]) -> Result<(), TraceeError> {
        for (i, slot) in out.iter_mut().enumerate() {
            clear_errno();
            let word = unsafe {
                libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    tid,
                    (addr + (i as u64) * 8) as *mut libc::c_void,
                    ptr::null_mut::<libc::c_void>(),
                )
            };
            if word == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error().unwrap_or(0) != 0 {
                    return Err(TraceeError::Ptrace(format!("PEEKDATA: {err}")));
                }
            }
            *slot = word as u64;
        }
        Ok(())
    }

    fn poke_data(tid: i32, addr: u64, words: &[u64]) -> Result<(), TraceeError> {
        for (i, w) in words.iter().enumerate() {
            let rc = unsafe {
                libc::ptrace(
                    libc::PTRACE_POKEDATA,
                    tid,
                    (addr + (i as u64) * 8) as *mut libc::c_void,
                    *w as *mut libc::c_void,
                )
            };
            if rc != 0 {
                return Err(TraceeError::Ptrace("POKEDATA restore".into()));
            }
        }
        Ok(())
    }

    fn poke_words(tid: i32, addr: u64, words: &[u32]) -> Result<(), TraceeError> {
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        while bytes.len() % 8 != 0 {
            bytes.push(0);
        }
        let mut u64s = Vec::new();
        for c in bytes.chunks(8) {
            u64s.push(u64::from_le_bytes(c.try_into().unwrap()));
        }
        poke_data(tid, addr, &u64s)
    }

    fn clear_errno() {
        #[cfg(target_os = "android")]
        unsafe {
            *libc::__errno() = 0;
        }
        #[cfg(not(target_os = "android"))]
        unsafe {
            *libc::__errno_location() = 0;
        }
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub use device::{
    read_memory, remote_call_stub, remote_call_with_lr, remote_mmap_svc, remote_mprotect_svc,
    write_memory,
};
