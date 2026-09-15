//! Frida-shaped `MemoryAccessMonitor` — page-granularity access traps via mprotect.
//!
//! Semantics match Frida's common case: each monitored page notifies **once**, then
//! is restored to its previous protection so the faulting access can complete.
//! Delivery to JS is asynchronous (pipe + drain thread → `js_queue`).

use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Once;

#[derive(Clone)]
struct PageEntry {
    prev_prot: i32,
    range_index: usize,
    page_index: usize,
    completed: bool,
}

struct MonitorState {
    pages: HashMap<u64, PageEntry>,
    pages_total: usize,
    pages_completed: usize,
}

static STATE: Mutex<Option<MonitorState>> = Mutex::new(None);
static ENABLED: AtomicBool = AtomicBool::new(false);
static PIPE_RD: AtomicI32 = AtomicI32::new(-1);
static PIPE_WR: AtomicI32 = AtomicI32::new(-1);
static DRAIN_STARTED: Once = Once::new();
static HANDLER_INSTALLED: Once = Once::new();

#[cfg(any(target_os = "linux", target_os = "android"))]
static mut PREV_SEGV: Option<libc::sigaction> = None;

fn page_size() -> u64 {
    crate::api::memory::page_size()
}

fn strip(addr: u64) -> u64 {
    addr & 0x00FF_FFFF_FFFF_FFFF
}

fn query_prot_flags(addr: u64) -> i32 {
    #[cfg(unix)]
    {
        if let Some(s) = crate::api::memory::query_protection(crate::api::NativePointer(addr)) {
            let mut p = libc::PROT_NONE;
            let chars: Vec<char> = s.chars().take(3).collect();
            if chars.first() == Some(&'r') {
                p |= libc::PROT_READ;
            }
            if chars.get(1) == Some(&'w') {
                p |= libc::PROT_WRITE;
            }
            if chars.get(2) == Some(&'x') {
                p |= libc::PROT_EXEC;
            }
            // Fresh malloc pages may not appear in maps yet — default RW.
            if p == libc::PROT_NONE {
                return libc::PROT_READ | libc::PROT_WRITE;
            }
            return p;
        }
        libc::PROT_READ | libc::PROT_WRITE
    }
    #[cfg(not(unix))]
    {
        let _ = addr;
        0
    }
}

/// Install monitor over `ranges` as `(base, size)` pairs. Returns Ok(pages_total).
pub fn enable(ranges: &[(u64, u64)]) -> Result<usize, String> {
    disable();
    ensure_pipe_and_drain()?;
    ensure_signal_handler();

    let ps = page_size();
    let mut pages: HashMap<u64, PageEntry> = HashMap::new();
    let mut page_index = 0usize;

    for (ri, (base, size)) in ranges.iter().enumerate() {
        let base = strip(*base);
        let size = (*size).max(1);
        let start = base & !(ps - 1);
        let end = (base + size + ps - 1) & !(ps - 1);
        let mut page = start;
        while page < end {
            pages.entry(page).or_insert_with(|| {
                let prev = query_prot_flags(page);
                let idx = page_index;
                page_index += 1;
                PageEntry {
                    prev_prot: prev,
                    range_index: ri,
                    page_index: idx,
                    completed: false,
                }
            });
            page += ps;
        }
    }

    if pages.is_empty() {
        return Err("no pages to monitor".into());
    }

    let pages_total = pages.len();
    for page in pages.keys() {
        #[cfg(unix)]
        {
            let rc = unsafe {
                libc::mprotect(*page as *mut libc::c_void, ps as usize, libc::PROT_NONE)
            };
            if rc != 0 {
                disable();
                return Err(format!("mprotect(PROT_NONE) failed at {page:#x}"));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = page;
            return Err("MemoryAccessMonitor requires unix".into());
        }
    }

    *STATE.lock() = Some(MonitorState {
        pages,
        pages_total,
        pages_completed: 0,
    });
    ENABLED.store(true, Ordering::SeqCst);
    Ok(pages_total)
}

pub fn disable() {
    ENABLED.store(false, Ordering::SeqCst);
    let ps = page_size();
    let mut g = STATE.lock();
    if let Some(st) = g.take() {
        for (page, ent) in st.pages {
            #[cfg(unix)]
            unsafe {
                let _ = libc::mprotect(page as *mut libc::c_void, ps as usize, ent.prev_prot);
            }
            #[cfg(not(unix))]
            {
                let _ = (page, ent, ps);
            }
        }
    }
}

fn ensure_pipe_and_drain() -> Result<(), String> {
    if PIPE_WR.load(Ordering::SeqCst) >= 0 {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let mut fds = [0i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err("pipe() failed".into());
        }
        unsafe {
            let fl = libc::fcntl(fds[1], libc::F_GETFL);
            let _ = libc::fcntl(fds[1], libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
        PIPE_RD.store(fds[0], Ordering::SeqCst);
        PIPE_WR.store(fds[1], Ordering::SeqCst);
        DRAIN_STARTED.call_once(|| {
            let rd = fds[0];
            let _ = std::thread::Builder::new()
                .name("goauld-mam-drain".into())
                .spawn(move || drain_loop(rd));
        });
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err("pipe unavailable".into())
    }
}

fn drain_loop(rd: RawFd) {
    let mut file = unsafe { std::fs::File::from_raw_fd(rd) };
    let mut buf = [0u8; std::mem::size_of::<WireEvent>()];
    loop {
        match file.read_exact(&mut buf) {
            Ok(()) => {
                let ev = WireEvent::from_bytes(&buf);
                let json = serde_json::json!({
                    "operation": ev.operation_str(),
                    "from": ev.from,
                    "address": ev.address,
                    "rangeIndex": ev.range_index,
                    "pageIndex": ev.page_index,
                    "pagesCompleted": ev.pages_completed,
                    "pagesTotal": ev.pages_total,
                });
                let src = format!(
                    "try{{__goauld_mamOnAccess({j});}}catch(e){{try{{send('mam-err:'+e);}}catch(_){{}}}}",
                    j = json
                );
                let _ = crate::js_queue::submit_eval_async(src);
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WireEvent {
    operation: u8, // 0=read 1=write 2=execute
    _pad: [u8; 7],
    from: u64,
    address: u64,
    range_index: u32,
    page_index: u32,
    pages_completed: u32,
    pages_total: u32,
}

impl WireEvent {
    fn from_bytes(b: &[u8]) -> Self {
        assert!(b.len() >= std::mem::size_of::<Self>());
        unsafe { std::ptr::read_unaligned(b.as_ptr() as *const Self) }
    }

    fn operation_str(self) -> &'static str {
        match self.operation {
            1 => "write",
            2 => "execute",
            _ => "read",
        }
    }
}

fn ensure_signal_handler() {
    HANDLER_INSTALLED.call_once(|| {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_flags = libc::SA_SIGINFO;
            sa.sa_sigaction = mam_sig_handler as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGSEGV, &sa, &mut old);
            PREV_SEGV = Some(old);
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
        }
    });
}

#[cfg(any(target_os = "linux", target_os = "android"))]
extern "C" fn mam_sig_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    uctx: *mut libc::c_void,
) {
    if !ENABLED.load(Ordering::SeqCst) {
        chain_previous(sig, info, uctx);
        return;
    }
    let fault = unsafe {
        if info.is_null() {
            0u64
        } else {
            (*info).si_addr() as u64
        }
    };
    let fault = strip(fault);
    let ps = page_size();
    let page = fault & !(ps - 1);

    let (pc, operation) = unsafe { fault_pc_and_op(uctx, fault) };

    let mut handled = false;
    {
        // parking_lot::Mutex is not async-signal-safe in general; acceptable here
        // for a short critical section in the injected agent.
        let mut g = STATE.lock();
        if let Some(st) = g.as_mut() {
            if let Some(ent) = st.pages.get_mut(&page) {
                if !ent.completed {
                    ent.completed = true;
                    st.pages_completed = st.pages_completed.saturating_add(1);
                    let prev = ent.prev_prot;
                    let range_index = ent.range_index;
                    let page_index = ent.page_index;
                    let pages_completed = st.pages_completed;
                    let pages_total = st.pages_total;
                    drop(g);
                    unsafe {
                        let _ = libc::mprotect(page as *mut libc::c_void, ps as usize, prev);
                    }
                    let op = match operation {
                        Op::Write => 1u8,
                        Op::Execute => 2u8,
                        Op::Read => 0u8,
                    };
                    let ev = WireEvent {
                        operation: op,
                        _pad: [0; 7],
                        from: pc,
                        address: fault,
                        range_index: range_index as u32,
                        page_index: page_index as u32,
                        pages_completed: pages_completed as u32,
                        pages_total: pages_total as u32,
                    };
                    write_event(&ev);
                    handled = true;
                } else {
                    let prev = ent.prev_prot;
                    drop(g);
                    unsafe {
                        let _ = libc::mprotect(page as *mut libc::c_void, ps as usize, prev);
                    }
                    handled = true;
                }
            }
        }
    }

    if !handled {
        chain_previous(sig, info, uctx);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn chain_previous(sig: libc::c_int, info: *mut libc::siginfo_t, uctx: *mut libc::c_void) {
    unsafe {
        if let Some(ref old) = PREV_SEGV {
            if old.sa_flags & libc::SA_SIGINFO != 0
                && old.sa_sigaction != 0
                && old.sa_sigaction != libc::SIG_DFL
                && old.sa_sigaction != libc::SIG_IGN
            {
                let f: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                    std::mem::transmute(old.sa_sigaction);
                f(sig, info, uctx);
                return;
            } else if old.sa_sigaction == libc::SIG_IGN {
                return;
            }
        }
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

#[derive(Clone, Copy)]
enum Op {
    Read,
    Write,
    Execute,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn fault_pc_and_op(uctx: *mut libc::c_void, fault: u64) -> (u64, Op) {
    if uctx.is_null() {
        return (0, Op::Read);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let uc = uctx as *const libc::ucontext_t;
        let pc = (*uc).uc_mcontext.pc;
        let ps = page_size();
        if (pc & !(ps - 1)) == (fault & !(ps - 1)) {
            return (pc, Op::Execute);
        }
        let op = classify_arm64_access(pc);
        return (pc, op);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (uctx, fault);
        (0, Op::Read)
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn classify_arm64_access(pc: u64) -> Op {
    if pc < 0x1000 || pc & 0x3 != 0 {
        return Op::Read;
    }
    let word = std::panic::catch_unwind(|| unsafe { std::ptr::read_unaligned(pc as *const u32) });
    let Ok(insn) = word else {
        return Op::Read;
    };
    if ((insn >> 25) & 0x5) == 0x4 {
        let is_load = ((insn >> 22) & 1) == 1;
        if ((insn >> 27) & 0x7) == 0x4 {
            return if is_load { Op::Read } else { Op::Write };
        }
        let opc = (insn >> 25) & 0x7;
        if opc == 0x2 || opc == 0x3 {
            return if is_load { Op::Read } else { Op::Write };
        }
    }
    Op::Read
}

fn write_event(ev: &WireEvent) {
    let fd = PIPE_WR.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (ev as *const WireEvent) as *const u8,
            std::mem::size_of::<WireEvent>(),
        )
    };
    unsafe {
        let _ = libc::write(fd, bytes.as_ptr() as *const libc::c_void, bytes.len());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn wire_event_size() {
        assert_eq!(std::mem::size_of::<super::WireEvent>(), 40);
    }
}
