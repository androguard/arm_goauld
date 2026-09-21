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
    // Not PTRACE_O_EXITKILL: a host timeout or a later inject that stops a
    // leftover tracer would SIGKILL the app. Detach-on-tracer-exit is enough.
    const __WALL: i32 = 0x4000_0000;

    /// uid 0 is not enough to ptrace an app. SELinux (`shell` cannot ptrace
    /// `untrusted_app`), Yama `ptrace_scope`, a missing `CAP_SYS_PTRACE`, or an
    /// existing tracer all return EPERM. Log which one it is, then relax the
    /// ones root can actually change.
    fn prepare_ptrace(pid: i32) -> Result<(), TraceeError> {
        let hint = ptrace_context(pid);
        eprintln!("goauld-inject: {hint}");
        if let Some(tracer) = tracer_pid(pid) {
            if tracer > 0 {
                release_stale_tracer(pid, tracer)?;
            }
        }
        relax_yama();
        ensure_cap_sys_ptrace();
        Ok(())
    }

    fn ptrace_context(pid: i32) -> String {
        let self_ctx = read_proc_attr("/proc/self/attr/current");
        let tgt_ctx = read_proc_attr(&format!("/proc/{pid}/attr/current"));
        let tracer = tracer_pid(pid)
            .map(|t| t.to_string())
            .unwrap_or_else(|| "?".into());
        let yama = read_proc_attr("/proc/sys/kernel/yama/ptrace_scope");
        let enforce = read_proc_attr("/sys/fs/selinux/enforce");
        let caps = cap_eff();
        format!(
            "ptrace context self={self_ctx} target={tgt_ctx} TracerPid={tracer} yama={} enforce={} CapEff={caps:#x} cap_sys_ptrace={}",
            if yama.is_empty() { "?".into() } else { yama },
            if enforce.is_empty() { "off".into() } else { enforce },
            caps & (1 << 19) != 0
        )
    }

    fn read_proc_attr(path: &str) -> String {
        fs::read(path)
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                    .to_string()
            })
            .unwrap_or_default()
    }

    fn proc_cmdline(pid: i32) -> String {
        fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .replace('\0', " ")
                    .trim()
                    .to_string()
            })
            .unwrap_or_default()
    }

    /// A previous injector that is still alive keeps `TracerPid` set. Magisk `su`
    /// often survives the host `timeout`, so that process can sit there forever.
    /// Stop it and continue when the app is still alive. `PTRACE_O_EXITKILL` on
    /// older injectors SIGKILLs the app when the tracer dies — say so.
    fn release_stale_tracer(target: i32, tracer: i32) -> Result<(), TraceeError> {
        if tracer <= 1 || tracer == std::process::id() as i32 {
            return Err(TraceeError::Ptrace(format!(
                "pid {target} is already traced by pid {tracer}"
            )));
        }
        let cmd = proc_cmdline(tracer);
        let comm = read_proc_attr(&format!("/proc/{tracer}/comm"));
        let ours = cmd.contains("goauld-injector") || comm.starts_with("goauld-inject");
        if !ours {
            let shown = if cmd.is_empty() { comm } else { cmd };
            return Err(TraceeError::Ptrace(format!(
                "pid {target} is already traced by pid {tracer} ({shown}) — detach that debugger first"
            )));
        }
        eprintln!(
            "goauld-inject: leftover injector pid={tracer} is still tracing pid={target} ({cmd}); stopping it"
        );
        let rc = unsafe { libc::kill(tracer, libc::SIGKILL) };
        if rc != 0 {
            return Err(TraceeError::Ptrace(format!(
                "pid {target} is traced by leftover injector {tracer}; kill failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if fs::metadata(format!("/proc/{target}")).is_err() {
                return Err(TraceeError::Ptrace(format!(
                    "leftover injector pid {tracer} was still attached; stopping it also stopped pid {target}. Relaunch the app and inject again"
                )));
            }
            match tracer_pid(target) {
                Some(0) | None => {
                    eprintln!("goauld-inject: pid {target} is no longer traced");
                    return Ok(());
                }
                Some(next) if next != tracer => {
                    return Err(TraceeError::Ptrace(format!(
                        "pid {target} is now traced by pid {next}"
                    )));
                }
                _ if std::time::Instant::now() >= deadline => {
                    return Err(TraceeError::Ptrace(format!(
                        "leftover injector pid {tracer} did not detach from pid {target}"
                    )));
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }

    fn tracer_pid(pid: i32) -> Option<i32> {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("TracerPid:") {
                return rest.trim().parse().ok();
            }
        }
        None
    }

    fn cap_eff() -> u64 {
        let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("CapEff:") {
                return u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
            }
        }
        0
    }

    fn selinux_type(ctx: &str) -> &str {
        ctx.split(':').nth(2).unwrap_or("")
    }

    fn relax_yama() {
        let path = "/proc/sys/kernel/yama/ptrace_scope";
        let cur = read_proc_attr(path);
        if cur.is_empty() || cur == "0" {
            return;
        }
        match fs::write(path, b"0") {
            Ok(()) => eprintln!("goauld-inject: set yama ptrace_scope=0 (was {cur})"),
            Err(e) => eprintln!("goauld-inject: could not set ptrace_scope ({e})"),
        }
    }

    fn ensure_cap_sys_ptrace() {
        const CAP_SYS_PTRACE: u64 = 1 << 19;
        if cap_eff() & CAP_SYS_PTRACE != 0 {
            return;
        }
        eprintln!("goauld-inject: CAP_SYS_PTRACE missing; trying capset");
        #[repr(C)]
        struct CapHdr {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let hdr = CapHdr {
            version: 0x2008_0522,
            pid: 0,
        };
        let data = [
            CapData {
                effective: u32::MAX,
                permitted: u32::MAX,
                inheritable: u32::MAX,
            },
            CapData {
                effective: 0x3ff,
                permitted: 0x3ff,
                inheritable: 0x3ff,
            },
        ];
        let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr as *const CapHdr, data.as_ptr()) };
        if rc != 0 {
            eprintln!(
                "goauld-inject: capset failed ({})",
                std::io::Error::last_os_error()
            );
        } else {
            eprintln!("goauld-inject: capset ok CapEff={:#x}", cap_eff());
        }
    }

    /// Shell-domain root can write app files and still be denied `process ptrace`.
    /// Move into the Magisk/su domain when that is allowed, and add a live allow.
    fn relax_selinux_ptrace(pid: i32) -> bool {
        let self_ctx = read_proc_attr("/proc/self/attr/current");
        let tgt_ctx = read_proc_attr(&format!("/proc/{pid}/attr/current"));
        let self_ty = selinux_type(&self_ctx);
        let tgt_ty = selinux_type(&tgt_ctx);
        eprintln!(
            "goauld-inject: ptrace denied ({self_ty} -> {tgt_ty}); relaxing SELinux"
        );
        let mut changed = false;
        if self_ty == "shell" || self_ty.is_empty() {
            for ctx in ["u:r:magisk:s0", "u:r:su:s0"] {
                if try_setcon(ctx) {
                    eprintln!("goauld-inject: setcon {ctx}");
                    changed = true;
                    break;
                }
            }
        }
        if !tgt_ty.is_empty() {
            let now = read_proc_attr("/proc/self/attr/current");
            let from = selinux_type(&now);
            let source = if from.is_empty() { self_ty } else { from };
            if !source.is_empty() && allow_ptrace_policy(source, tgt_ty) {
                changed = true;
            }
        }
        changed
    }

    fn try_setcon(ctx: &str) -> bool {
        let mut bytes = ctx.as_bytes().to_vec();
        bytes.push(0);
        fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/attr/current")
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(&bytes)
            })
            .is_ok()
    }

    fn allow_ptrace_policy(source: &str, target: &str) -> bool {
        let rule = format!("allow {source} {target} process ptrace");
        let bins = [
            "magiskpolicy",
            "/data/adb/magisk/magiskpolicy",
            "/debug_ramdisk/magiskpolicy",
            "supolicy",
        ];
        for bin in bins {
            let out = std::process::Command::new(bin)
                .args(["--live", &rule])
                .output();
            match out {
                Ok(out) if out.status.success() => {
                    eprintln!("goauld-inject: {bin} --live '{rule}'");
                    return true;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("goauld-inject: {bin} ({e})"),
            }
        }
        let applets = ["/debug_ramdisk/magisk", "magisk", "/sbin/magisk"];
        for bin in applets {
            let out = std::process::Command::new(bin)
                .args(["magiskpolicy", "--live", &rule])
                .output();
            match out {
                Ok(out) if out.status.success() => {
                    eprintln!("goauld-inject: {bin} magiskpolicy --live '{rule}'");
                    return true;
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => eprintln!("goauld-inject: {bin} ({e})"),
            }
        }
        eprintln!("goauld-inject: magiskpolicy not available for '{rule}'");
        false
    }

    fn stop_tid(tid: i32) -> Result<(), TraceeError> {
        // Prefer SEIZE; fall back to ATTACH on older/odd kernels.
        let seized = unsafe {
            libc::ptrace(
                PTRACE_SEIZE,
                tid,
                ptr::null_mut::<libc::c_void>(),
                ptr::null_mut::<libc::c_void>(),
            )
        };
        if seized != 0 {
            let seize_err = std::io::Error::last_os_error();
            eprintln!("goauld-inject: SEIZE tid={tid} failed ({seize_err}); trying ATTACH");
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
        Ok(())
    }

    fn is_eperm(err: &TraceeError) -> bool {
        let msg = err.to_string();
        msg.contains("Operation not permitted") || msg.contains("os error 1")
    }

    pub(super) fn seize(pid: i32) -> Result<Tracee, TraceeError> {
        prepare_ptrace(pid)?;
        let tids = list_tids(pid)?;
        eprintln!("goauld-inject: seize pid={pid} tids={tids:?}");
        let mut relaxed = false;
        for &tid in &tids {
            if let Err(err) = stop_tid(tid) {
                if !relaxed && is_eperm(&err) {
                    relaxed = true;
                    if relax_selinux_ptrace(pid) {
                        match stop_tid(tid) {
                            Ok(()) => continue,
                            Err(retry) => {
                                eprintln!("goauld-inject: {}", ptrace_context(pid));
                                return Err(retry);
                            }
                        }
                    }
                    eprintln!("goauld-inject: {}", ptrace_context(pid));
                }
                return Err(err);
            }
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
        // The linker's caller check uses LR. It must point at an executable
        // mapping of a real library (libc), not an anonymous stub.
        if let Ok(lr) = find_brk_gadget(tracee.pid) {
            eprintln!("goauld-inject: using brk gadget @{lr:#x}");
            return remote_call_with_lr(tracee, func_addr, args, lr, None);
        }
        let planted = plant_brk_in_libc(tracee)?;
        eprintln!("goauld-inject: planted brk @{:#x} in libc", planted.addr);
        let ret = remote_call_with_lr(tracee, func_addr, args, planted.addr, None);
        drop(planted);
        ret
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
        stack: Option<u64>,
    ) -> Result<u64, TraceeError> {
        let tid = tracee.pid;
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        getregs(tid, &mut regs)?;
        let backup = regs;

        for (i, a) in args.iter().enumerate() {
            regs.regs[i] = *a;
        }

        eprintln!(
            "goauld-inject: remote_call func={func_addr:#x} lr={lr:#x} sp={stack:?} args={args:?}"
        );
        regs.regs[30] = lr;
        regs.pc = func_addr;
        if let Some(sp) = stack {
            // Own stack so dlopen cannot smash the stopped thread's frame
            // (signal stack, or a shell blocked in wait).
            regs.sp = sp;
            regs.regs[29] = 0;
        }
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

    /// `openat(AT_FDCWD, path, O_RDONLY)` inside the target. Returns the raw x0
    /// (fd >= 0, or -errno). Does **not** close a successful fd.
    pub fn remote_openat(tracee: &Tracee, path_addr: u64) -> Result<i64, TraceeError> {
        remote_syscall(
            tracee,
            56,
            &[(-100i64) as u64, path_addr, 0, 0],
            "openat",
        )
    }

    pub fn remote_close(tracee: &Tracee, fd: u64) -> Result<i64, TraceeError> {
        remote_syscall(tracee, 57, &[fd], "close")
    }

    /// `memfd_create(name, MFD_CLOEXEC)` — name is a remote cstr address.
    pub fn remote_memfd_create(tracee: &Tracee, name_addr: u64) -> Result<i64, TraceeError> {
        // nr 279 on aarch64; MFD_CLOEXEC = 1
        remote_syscall(tracee, 279, &[name_addr, 1], "memfd_create")
    }

    pub fn remote_write(
        tracee: &Tracee,
        fd: u64,
        buf_addr: u64,
        len: u64,
    ) -> Result<i64, TraceeError> {
        remote_syscall(tracee, 64, &[fd, buf_addr, len], "write")
    }

    /// `lseek(fd, offset, whence)` inside the target.
    pub fn remote_lseek(
        tracee: &Tracee,
        fd: u64,
        offset: u64,
        whence: u64,
    ) -> Result<i64, TraceeError> {
        remote_syscall(tracee, 62, &[fd, offset, whence], "lseek")
    }

    fn remote_syscall(
        tracee: &Tracee,
        nr: u64,
        args: &[u64],
        label: &str,
    ) -> Result<i64, TraceeError> {
        let tid = tracee.pid;
        let mut regs: libc::user_regs_struct = unsafe { mem::zeroed() };
        getregs(tid, &mut regs)?;
        let backup = regs;
        let svc_addr = find_svc_gadget(tid)?;
        regs.regs[8] = nr;
        for (i, a) in args.iter().enumerate().take(6) {
            regs.regs[i] = *a;
        }
        regs.pc = svc_addr;
        setregs(tid, &regs)?;
        syscall_step(tid)?;
        syscall_step(tid)?;
        getregs(tid, &mut regs)?;
        let ret = regs.regs[0] as i64;
        eprintln!("goauld-inject: {label} returned {ret}");
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

    /// Scan executable libc/libdl/linker text for any `brk #imm` (LR landing pad).
    fn find_brk_gadget(pid: i32) -> Result<u64, TraceeError> {
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|e| TraceeError::Msg(e.to_string()))?;
        for line in maps.lines() {
            if !(line.contains("r-xp") || line.contains("r-x")) {
                continue;
            }
            if !(line.contains("libc.so") || line.contains("libdl.so") || line.contains("/linker"))
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
                let word = u32::from_le_bytes(buf[i..i + 4].try_into().unwrap_or([0; 4]));
                // BRK: 11010100 001i iiii iiii iii0 0000
                if word & 0xFFE0_001F == 0xD420_0000 {
                    return Ok(start + i as u64);
                }
            }
        }
        Err(TraceeError::Msg("brk gadget not found".into()))
    }

    /// Temporarily replace the last instruction of libc's text with `brk #0`.
    /// Restored on drop. mprotect RW→write→RX flushes the I-cache on arm64.
    fn plant_brk_in_libc(tracee: &Tracee) -> Result<PlantedBrk<'_>, TraceeError> {
        let maps = fs::read_to_string(format!("/proc/{}/maps", tracee.pid))
            .map_err(|e| TraceeError::Msg(e.to_string()))?;
        let mut best: Option<(u64, u64)> = None;
        for line in maps.lines() {
            if !(line.contains("r-xp") || line.contains("r-x")) || !line.contains("libc.so") {
                continue;
            }
            let range = line.split_whitespace().next().unwrap_or("");
            let mut segs = range.split('-');
            let start = u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
            let end = u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
            if end > start + 4 {
                best = Some((start, end));
            }
        }
        let (_start, end) = best.ok_or_else(|| TraceeError::Msg("libc exec mapping not found".into()))?;
        let addr = (end - 4) & !3;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0x1000) as u64;
        let page = addr & !(page_size - 1);
        const PROT_RW: u64 = 1 | 2;
        const PROT_RX: u64 = 1 | 4;

        let saved = read_memory(tracee.pid, addr, 4)?;
        let mut saved4 = [0u8; 4];
        saved4.copy_from_slice(&saved[..4]);

        let mp = remote_mprotect_svc(tracee, page, page_size, PROT_RW)?;
        if mp != 0 {
            return Err(TraceeError::Msg(format!(
                "mprotect RW libc @{page:#x} failed: {mp:#x}"
            )));
        }
        write_memory(tracee.pid, addr, &0xD420_0000u32.to_le_bytes())?;
        let mp = remote_mprotect_svc(tracee, page, page_size, PROT_RX)?;
        if mp != 0 {
            let _ = remote_mprotect_svc(tracee, page, page_size, PROT_RW);
            let _ = write_memory(tracee.pid, addr, &saved4);
            let _ = remote_mprotect_svc(tracee, page, page_size, PROT_RX);
            return Err(TraceeError::Msg(format!(
                "mprotect RX libc @{page:#x} failed: {mp:#x}"
            )));
        }
        Ok(PlantedBrk {
            tracee,
            page,
            page_len: page_size,
            addr,
            saved: saved4,
        })
    }

    struct PlantedBrk<'a> {
        tracee: &'a Tracee,
        page: u64,
        page_len: u64,
        addr: u64,
        saved: [u8; 4],
    }

    impl Drop for PlantedBrk<'_> {
        fn drop(&mut self) {
            const PROT_RW: u64 = 1 | 2;
            const PROT_RX: u64 = 1 | 4;
            let _ = remote_mprotect_svc(self.tracee, self.page, self.page_len, PROT_RW);
            let _ = write_memory(self.tracee.pid, self.addr, &self.saved);
            let _ = remote_mprotect_svc(self.tracee, self.page, self.page_len, PROT_RX);
        }
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
    read_memory, remote_call_stub, remote_call_with_lr, remote_close, remote_lseek,
    remote_memfd_create, remote_mmap_svc, remote_mprotect_svc, remote_openat, remote_write,
    write_memory,
};
