//! High-level inject_library sequence (§3.2).
//!
//! Intended to run **on the Android device** as the `goauld-injector` binary
//! (root / elevated), not on the desktop host.

use crate::remote::{Tracee, TraceeError};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InjectError {
    #[error(transparent)]
    Tracee(#[from] TraceeError),
    #[error("symbol not found: {0}")]
    Symbol(String),
    #[error("dlopen failed: {0:#x}")]
    DlOpen(u64),
    #[error("{0}")]
    Msg(String),
}

#[derive(Debug, Clone)]
pub struct InjectOptions {
    /// Absolute path to the agent `.so` **on the device filesystem**, already
    /// placed somewhere visible to the app's linker namespace when possible
    /// (e.g. `/data/local/tmp/` on permissive/root, or `/data/data/<pkg>/files/`
    /// via `run-as` / package-aware staging).
    pub library_path: String,
    /// Prefer `android_dlopen_ext` with classloader namespace when true.
    pub use_namespace: bool,
}

/// Inject a shared library into a running process via ptrace + remote dlopen.
///
/// State machine:
/// 1. Seize all threads
/// 2. Remote mmap scratch (RW)
/// 3. Resolve `android_dlopen_ext` / `dlopen` in the **target's** libc
/// 4. Write path string into scratch; remote-call dlopen
/// 5. Restore regs; detach
pub fn inject_library(pid: i32, opts: &InjectOptions) -> Result<u64, InjectError> {
    if !std::path::Path::new(&opts.library_path).exists() {
        return Err(InjectError::Msg(format!(
            "library not found on device: {}",
            opts.library_path
        )));
    }

    let tracee = Tracee::seize(pid)?;
    let result = (|| {
        #[cfg(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        ))]
        {
            use crate::remote::{
                remote_call_with_lr, remote_close, remote_mmap_svc, remote_mprotect_svc,
                remote_openat, write_memory, RemoteCall,
            };

            const PROT_READ: u64 = 1;
            const PROT_WRITE: u64 = 2;
            const PROT_EXEC: u64 = 4;
            const MAP_PRIVATE: u64 = 0x02;
            const MAP_ANONYMOUS: u64 = 0x20;
            const RTLD_NOW: u64 = 2;

            let page = remote_mmap_svc(
                &tracee,
                0x1000,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
            )?;
            if page == 0 || page >= 0xFFFF_FFFF_FFFF_F000 {
                return Err(InjectError::Msg(format!("mmap failed: {page:#x}")));
            }

            // Scratch stays RW. The call site must be inside a real .so: bionic
            // rejects dlopen when the return address is an anonymous stub
            // ("caller is not a valid library") and returns NULL.
            let mut path_bytes = opts.library_path.as_bytes().to_vec();
            path_bytes.push(0);
            write_memory(pid, page, &path_bytes)?;
            let mut can_open = false;
            match remote_openat(&tracee, page) {
                Ok(fd) if fd >= 0 => {
                    let _ = remote_close(&tracee, fd as u64);
                    can_open = true;
                    eprintln!("goauld-inject: target can open the agent");
                }
                Ok(err) => {
                    eprintln!(
                        "goauld-inject: target open failed errno {} ({})",
                        -err,
                        std::io::Error::from_raw_os_error((-err) as i32)
                    );
                }
                Err(e) => eprintln!("goauld-inject: openat probe failed: {e}"),
            }
            if !can_open {
                // App domains often get EACCES until the file carries the same
                // SELinux category as the rest of the app data directory.
                fix_app_file_context(&opts.library_path);
                write_memory(pid, page, &path_bytes)?;
                match remote_openat(&tracee, page) {
                    Ok(fd) if fd >= 0 => {
                        let _ = remote_close(&tracee, fd as u64);
                        can_open = true;
                        eprintln!("goauld-inject: target can open the agent after secontext fix");
                    }
                    Ok(err) => eprintln!(
                        "goauld-inject: target open still denied errno {}",
                        -err
                    ),
                    Err(e) => eprintln!("goauld-inject: openat retry failed: {e}"),
                }
            }

            let (libc_base, libc_path) = find_libc(pid)?;
            let (dl_base, dl_path) = find_libdl(pid).unwrap_or((libc_base, libc_path.clone()));
            let dlopen = resolve_elf_symbol(pid, dl_base, &dl_path, "dlopen")
                .or_else(|_| resolve_elf_symbol(pid, libc_base, &libc_path, "dlopen"))
                .map_err(InjectError::Symbol)?;
            eprintln!("goauld-inject: dlopen={dlopen:#x} from {dl_path}@{dl_base:#x}");
            // Sanity: first insn should be in an executable mapping.
            {
                let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
                    .unwrap_or_default();
                let mut ok = false;
                for line in maps.lines() {
                    if !(line.contains("r-xp") || line.contains("r-x")) {
                        continue;
                    }
                    let range = line.split_whitespace().next().unwrap_or("");
                    let mut segs = range.split('-');
                    let start =
                        u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
                    let end = u64::from_str_radix(segs.next().unwrap_or("0"), 16).unwrap_or(0);
                    if dlopen >= start && dlopen < end {
                        ok = true;
                        eprintln!("goauld-inject: dlopen falls in exec {start:#x}-{end:#x}");
                        break;
                    }
                }
                if !ok {
                    return Err(InjectError::Msg(format!(
                        "resolved dlopen {dlopen:#x} not in any r-xp mapping (bad load bias?)"
                    )));
                }
            }

            let caller = RemoteCall { tracee: &tracee };
            // __loader_dlopen takes the caller address as an argument, so LR can
            // land on a BRK in this scratch page. A plain dlopen() would treat
            // that anonymous return address as "not a library" and return NULL.
            let brk_addr = page + 0x800;
            write_memory(pid, brk_addr, &0xD420_0000u32.to_le_bytes())?;
            let mp = remote_mprotect_svc(&tracee, page, 0x1000, PROT_READ | PROT_EXEC)?;
            if mp != 0 {
                return Err(InjectError::Msg(format!("mprotect RX scratch failed: {mp:#x}")));
            }
            let libc_caller = libc_base.max(1);
            let mut handle = 0u64;
            if !can_open {
                // The process is already ptraced. Path dlopen cannot succeed while
                // the app domain is denied open() on the staged file, so load the
                // bytes through a memfd created inside the target.
                eprintln!(
                    "goauld-inject: app cannot open the staged file; ptrace memfd load"
                );
                handle = dlopen_via_memfd(
                    &tracee,
                    pid,
                    page,
                    &opts.library_path,
                    libc_base,
                    dl_base,
                    &dl_path,
                    &libc_path,
                )?;
                if handle == 0 {
                    let why = dlerror_text(pid, &caller, dl_base, &dl_path, libc_base, &libc_path);
                    return Err(InjectError::Msg(format!(
                        "memfd dlopen failed: {why}"
                    )));
                }
                return Ok(handle);
            }
            if let Some((linker_base, linker_path)) = find_linker(pid) {
                if let Ok(loader) =
                    resolve_elf_symbol(pid, linker_base, &linker_path, "__loader_dlopen")
                {
                    eprintln!(
                        "goauld-inject: __loader_dlopen={loader:#x} caller={libc_caller:#x}"
                    );
                    handle = remote_call_with_lr(
                        &tracee,
                        loader,
                        &[page, RTLD_NOW, libc_caller],
                        brk_addr,
                        None,
                    )?;
                }
            }
            if handle == 0 {
                // Make the scratch page writable again for the namespace fallback.
                let _ = remote_mprotect_svc(&tracee, page, 0x1000, PROT_READ | PROT_WRITE);
                if handle == 0 {
                    eprintln!("goauld-inject: __loader_dlopen missed; calling dlopen via libc return");
                    handle = caller.call(dlopen, &[page, RTLD_NOW]).unwrap_or(0);
                }
            }
            if handle == 0 {
                let why = dlerror_text(pid, &caller, dl_base, &dl_path, libc_base, &libc_path);
                eprintln!("goauld-inject: dlopen returned 0 ({why})");
                // Remake scratch writable for namespace / memfd helpers.
                let _ = remote_mprotect_svc(&tracee, page, 0x1000, PROT_READ | PROT_WRITE);
                write_memory(pid, page, &path_bytes)?;
                if can_open {
                    handle = dlopen_in_namespace(
                        pid,
                        &caller,
                        page,
                        &opts.library_path,
                        dl_base,
                        &dl_path,
                        libc_base,
                        &libc_path,
                    )?;
                }
                if handle == 0 {
                    eprintln!("goauld-inject: falling back to memfd + android_dlopen_ext(fd)");
                    handle = dlopen_via_memfd(
                        &tracee,
                        pid,
                        page,
                        &opts.library_path,
                        libc_base,
                        dl_base,
                        &dl_path,
                        &libc_path,
                    )?;
                }
                if handle == 0 {
                    let why2 =
                        dlerror_text(pid, &caller, dl_base, &dl_path, libc_base, &libc_path);
                    return Err(InjectError::Msg(format!(
                        "dlopen failed: {why2} (plain dlopen: {why})"
                    )));
                }
            }
            Ok(handle)
        }

        #[cfg(not(all(
            any(target_os = "linux", target_os = "android"),
            target_arch = "aarch64"
        )))]
        {
            Err(InjectError::Tracee(TraceeError::Unsupported))
        }
    })();

    let _ = tracee.detach();
    result
}

/// Copy a sibling/parent SELinux label. Toybox `chcon` has no `--reference`.
fn fix_app_file_context(path: &str) {
    let parent = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    if parent.is_empty() {
        return;
    }
    let mut donors = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&parent) {
        for ent in rd.flatten().take(8) {
            let p = ent.path();
            if p.to_string_lossy() != path {
                donors.push(p.to_string_lossy().into_owned());
            }
        }
    }
    donors.push(parent);
    for donor in donors {
        let Some(ctx) = selinux_context(&donor) else {
            continue;
        };
        let status = Command::new("chcon").args([&ctx, path]).status();
        if status.map(|s| s.success()).unwrap_or(false) {
            eprintln!("goauld-inject: chcon {ctx} → {path}");
            return;
        }
    }
    let _ = Command::new("restorecon").args(["-F", path]).status();
}

fn selinux_context(path: &str) -> Option<String> {
    let out = Command::new("ls").args(["-Zd", path]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .find(|t| t.starts_with("u:") && t.contains(":object_r:"))
        .map(|s| s.to_string())
}

/// A dlopen handle is a userspace soinfo pointer: canonical, aligned, not a small int.
fn plausible_so_handle(h: u64) -> bool {
    h >= 0x1_0000 && (h >> 48) == 0 && h % 8 == 0
}

/// Push the agent bytes into a memfd in the target and load via android_dlopen_ext(fd).
/// Bypasses path-based SELinux checks on app_data_file.
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn dlopen_via_memfd(
    tracee: &crate::remote::Tracee,
    pid: i32,
    page: u64,
    library_path: &str,
    libc_base: u64,
    dl_base: u64,
    dl_path: &str,
    libc_path: &str,
) -> Result<u64, InjectError> {
    use crate::remote::{
        remote_call_with_lr, remote_close, remote_lseek, remote_memfd_create, remote_mmap_svc,
        remote_mprotect_svc, remote_write, write_memory, RemoteCall,
    };

    const RTLD_NOW: u64 = 2;
    const DLEXT_USE_LIBRARY_FD: u64 = 0x10;
    const DLEXT_USE_LIBRARY_FD_OFFSET: u64 = 0x20;
    const PROT_READ: u64 = 1;
    const PROT_WRITE: u64 = 2;
    const PROT_EXEC: u64 = 4;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_ANONYMOUS: u64 = 0x20;

    let bytes = std::fs::read(library_path)
        .map_err(|e| InjectError::Msg(format!("read agent for memfd: {e}")))?;
    eprintln!("goauld-inject: memfd payload {} bytes", bytes.len());

    let _ = remote_mprotect_svc(tracee, page, 0x1000, PROT_READ | PROT_WRITE);
    write_cstr(pid, page, "libgoauld_agent.so")?;
    let fd = remote_memfd_create(tracee, page)?;
    if fd < 0 {
        return Err(InjectError::Msg(format!("memfd_create failed: {fd}")));
    }
    let fd_u = fd as u64;

    let map_len = (bytes.len() as u64 + 0xfff) & !0xfff;
    let buf = remote_mmap_svc(tracee, map_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)?;
    if buf == 0 || buf >= 0xFFFF_FFFF_FFFF_F000 {
        let _ = remote_close(tracee, fd_u);
        return Err(InjectError::Msg(format!("memfd buffer mmap failed: {buf:#x}")));
    }
    write_memory(pid, buf, &bytes)?;
    let mut off = 0u64;
    while off < bytes.len() as u64 {
        let n = remote_write(tracee, fd_u, buf + off, bytes.len() as u64 - off)?;
        if n <= 0 {
            let _ = remote_close(tracee, fd_u);
            return Err(InjectError::Msg(format!("memfd write failed at {off}: {n}")));
        }
        off += n as u64;
    }
    let seek = remote_lseek(tracee, fd_u, 0, 0)?;
    eprintln!("goauld-inject: memfd filled {off} bytes fd={fd} lseek={seek}");

    // Arguments stay writable. The BRK landing pad is a separate executable page
    // so the linker can read the path and dlextinfo.
    write_cstr(pid, page, "libgoauld_agent.so")?;
    let ext_addr = page + 0x400;
    let mut info = [0u8; 0x30];
    let flags = DLEXT_USE_LIBRARY_FD | DLEXT_USE_LIBRARY_FD_OFFSET;
    info[0..8].copy_from_slice(&flags.to_le_bytes());
    info[0x18..0x1c].copy_from_slice(&(-1i32).to_le_bytes()); // relro_fd
    info[0x1c..0x20].copy_from_slice(&(fd as i32).to_le_bytes()); // library_fd
    // library_fd_offset at 0x20 stays 0
    write_memory(pid, ext_addr, &info)?;

    let brk_page = remote_mmap_svc(tracee, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)?;
    if brk_page == 0 || brk_page >= 0xFFFF_FFFF_FFFF_F000 {
        let _ = remote_close(tracee, fd_u);
        return Err(InjectError::Msg(format!("brk page mmap failed: {brk_page:#x}")));
    }
    let brk_addr = brk_page;
    write_memory(pid, brk_addr, &0xD420_0000u32.to_le_bytes())?;
    let mp = remote_mprotect_svc(tracee, brk_page, 0x1000, PROT_READ | PROT_EXEC)?;
    if mp != 0 {
        let _ = remote_close(tracee, fd_u);
        return Err(InjectError::Msg(format!("mprotect RX for memfd dlopen failed: {mp:#x}")));
    }

    let stack_len = 0x4_0000u64;
    let stack = remote_mmap_svc(tracee, stack_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS)?;
    if stack == 0 || stack >= 0xFFFF_FFFF_FFFF_F000 {
        let _ = remote_close(tracee, fd_u);
        return Err(InjectError::Msg(format!("call stack mmap failed: {stack:#x}")));
    }
    let sp = (stack + stack_len) & !0xF;

    let (dlopen_ext, extra_caller) = linker_symbol(pid, "__loader_android_dlopen_ext")
        .map(|a| (a, true))
        .or_else(|| {
            resolve_symbol(pid, dl_base, dl_path, libc_base, libc_path, "android_dlopen_ext")
                .map(|a| (a, false))
        })
        .unwrap_or((0, false));
    if dlopen_ext == 0 {
        let _ = remote_close(tracee, fd_u);
        eprintln!("goauld-inject: android_dlopen_ext missing for memfd path");
        return Ok(0);
    }
    eprintln!("goauld-inject: android_dlopen_ext={dlopen_ext:#x} extra_caller={extra_caller}");

    let mut args = vec![page, RTLD_NOW, ext_addr];
    if extra_caller {
        args.push(libc_base.max(1));
    }
    let handle = remote_call_with_lr(tracee, dlopen_ext, &args, brk_addr, Some(sp))?;
    eprintln!("goauld-inject: memfd android_dlopen_ext handle={handle:#x}");
    if !plausible_so_handle(handle) {
        let caller = RemoteCall { tracee };
        let why = dlerror_text(pid, &caller, dl_base, dl_path, libc_base, libc_path);
        let _ = remote_close(tracee, fd_u);
        return Err(InjectError::Msg(format!(
            "memfd dlopen returned {handle:#x} ({why})"
        )));
    }
    let _ = remote_close(tracee, fd_u);
    Ok(handle)
}

/// Plain `dlopen` uses the caller's linker namespace, which cannot see
/// `/data/data/<pkg>/files`. Create a shared namespace that permits that
/// directory and load through `android_dlopen_ext`.
#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn dlopen_in_namespace(
    pid: i32,
    caller: &crate::remote::RemoteCall<'_>,
    page: u64,
    library_path: &str,
    dl_base: u64,
    dl_path: &str,
    libc_base: u64,
    libc_path: &str,
) -> Result<u64, InjectError> {
    use crate::remote::write_memory;

    const RTLD_NOW: u64 = 2;
    // ISOLATED | SHARED — search this path, resolve libc/libdl/libm/liblog from the parent.
    const NS_ISOLATED_SHARED: u64 = 3;
    const DLEXT_USE_NAMESPACE: u64 = 0x200;

    let (create, create_extra_caller) = linker_symbol(pid, "__loader_android_create_namespace")
        .map(|a| (a, true))
        .or_else(|| {
            resolve_symbol(pid, dl_base, dl_path, libc_base, libc_path, "android_create_namespace")
                .map(|a| (a, false))
        })
        .ok_or_else(|| {
            eprintln!("goauld-inject: android_create_namespace not found");
        })
        .ok()
        .unwrap_or((0, false));
    if create == 0 {
        return Ok(0);
    }
    let (dlopen_ext, ext_extra_caller) = linker_symbol(pid, "__loader_android_dlopen_ext")
        .map(|a| (a, true))
        .or_else(|| {
            resolve_symbol(pid, dl_base, dl_path, libc_base, libc_path, "android_dlopen_ext")
                .map(|a| (a, false))
        })
        .unwrap_or((0, false));
    if dlopen_ext == 0 {
        eprintln!("goauld-inject: android_dlopen_ext not found");
        return Ok(0);
    }

    let dir = std::path::Path::new(library_path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/data/local/tmp".into());
    let search = format!("{dir}:/system/lib64:/apex/com.android.runtime/lib64/bionic");

    let name_addr = page + 0x200;
    let dir_addr = page + 0x280;
    let ext_addr = page + 0x400;
    write_cstr(pid, name_addr, "goauld")?;
    write_cstr(pid, dir_addr, &search)?;

    eprintln!("goauld-inject: android_create_namespace permitted={search}");
    let mut ns_args = vec![name_addr, dir_addr, dir_addr, NS_ISOLATED_SHARED, dir_addr, 0];
    if create_extra_caller {
        ns_args.push(libc_base);
    }
    let ns = caller.call(create, &ns_args)?;
    if ns == 0 {
        let why = dlerror_text(pid, caller, dl_base, dl_path, libc_base, libc_path);
        eprintln!("goauld-inject: create_namespace failed ({why})");
        return Ok(0);
    }
    eprintln!("goauld-inject: namespace={ns:#x}");

    let mut info = [0u8; 0x30];
    info[0..8].copy_from_slice(&DLEXT_USE_NAMESPACE.to_le_bytes());
    info[0x18..0x1c].copy_from_slice(&(-1i32).to_le_bytes());
    info[0x1c..0x20].copy_from_slice(&(-1i32).to_le_bytes());
    info[0x28..0x30].copy_from_slice(&ns.to_le_bytes());
    write_memory(pid, ext_addr, &info)?;

    let mut ext_args = vec![page, RTLD_NOW, ext_addr];
    if ext_extra_caller {
        ext_args.push(libc_base);
    }
    let handle = caller.call(dlopen_ext, &ext_args)?;
    eprintln!("goauld-inject: android_dlopen_ext handle={handle:#x}");
    Ok(handle)
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn resolve_symbol(
    pid: i32,
    dl_base: u64,
    dl_path: &str,
    libc_base: u64,
    libc_path: &str,
    name: &str,
) -> Option<u64> {
    resolve_elf_symbol(pid, dl_base, dl_path, name)
        .or_else(|_| resolve_elf_symbol(pid, libc_base, libc_path, name))
        .ok()
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn write_cstr(pid: i32, addr: u64, s: &str) -> Result<(), InjectError> {
    use crate::remote::write_memory;
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    write_memory(pid, addr, &bytes)?;
    Ok(())
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn dlerror_text(
    pid: i32,
    caller: &crate::remote::RemoteCall<'_>,
    dl_base: u64,
    dl_path: &str,
    libc_base: u64,
    libc_path: &str,
) -> String {
    let Some(dlerror) = resolve_symbol(pid, dl_base, dl_path, libc_base, libc_path, "dlerror") else {
        return "dlerror symbol missing".into();
    };
    match caller.call(dlerror, &[]) {
        Ok(p) if p != 0 => read_remote_cstr(pid, p),
        Ok(_) => "dlerror empty".into(),
        Err(e) => format!("dlerror call failed: {e}"),
    }
}

#[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "aarch64"))]
fn read_remote_cstr(pid: i32, addr: u64) -> String {
    let mut buf = vec![0u8; 512];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        return format!("unreadable dlerror @{addr:#x}");
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|b| *b == 0).unwrap_or(n);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Locate libdl / linker providing dlopen.
///
/// Returns `(load_bias, path)`. On Android with 64K ELF alignment the first
/// mapping is often `r--` at file offset 0 while `.text` is a later `r-xp`
/// mapping — symbol addresses are `load_bias + st_value`, where
/// `load_bias = map_start - file_offset` for any mapping of the SO.
pub fn find_libdl(pid: i32) -> Result<(u64, String), InjectError> {
    find_so_load_bias(pid, &["/libdl.so", "libdl.so", "/linker64", "/linker"])
}

/// Locate libc; returns `(load_bias, path)`.
pub fn find_libc(pid: i32) -> Result<(u64, String), InjectError> {
    find_so_load_bias(pid, &["/bionic/libc.so", "/libc.so"])
}

fn find_linker(pid: i32) -> Option<(u64, String)> {
    find_so_load_bias(pid, &["/linker64", "/linker"]).ok()
}

fn linker_symbol(pid: i32, name: &str) -> Option<u64> {
    let (base, path) = find_linker(pid)?;
    resolve_elf_symbol(pid, base, &path, name).ok()
}

fn find_so_load_bias(pid: i32, name_needles: &[&str]) -> Result<(u64, String), InjectError> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| InjectError::Msg(e.to_string()))?;
    for line in maps.lines() {
        let path = line.split_whitespace().last().unwrap_or("");
        if !path.starts_with('/') {
            continue;
        }
        if !name_needles.iter().any(|n| path.contains(n)) {
            continue;
        }
        // start-end perms offset dev inode path
        let mut parts = line.split_whitespace();
        let range = parts.next().unwrap_or("");
        let _perms = parts.next().unwrap_or("");
        let file_off_hex = parts.next().unwrap_or("0");
        let start_hex = range.split('-').next().unwrap_or("");
        let map_start = u64::from_str_radix(start_hex, 16)
            .map_err(|e| InjectError::Msg(e.to_string()))?;
        let file_off = u64::from_str_radix(file_off_hex, 16)
            .map_err(|e| InjectError::Msg(e.to_string()))?;
        if map_start < file_off {
            continue;
        }
        let load_bias = map_start - file_off;
        return Ok((load_bias, path.to_string()));
    }
    Err(InjectError::Msg(format!(
        "shared object not found ({name_needles:?})"
    )))
}

/// Resolve an exported symbol in the target's mapped ELF.
///
/// Reads the ELF file from the device path (same filesystem when running as
/// root on-device). Falls back to `/proc/<pid>/root<path>` if needed.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn resolve_elf_symbol(
    pid: i32,
    base: u64,
    libc_path: &str,
    name: &str,
) -> Result<u64, String> {
    let bytes = read_target_file(pid, libc_path)?;
    let off = find_dynsym_offset(&bytes, name).ok_or_else(|| name.to_string())?;
    Ok(base + off)
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn read_target_file(pid: i32, path: &str) -> Result<Vec<u8>, String> {
    if let Ok(b) = std::fs::read(path) {
        return Ok(b);
    }
    let via_root = format!("/proc/{pid}/root{path}");
    std::fs::read(&via_root).map_err(|e| format!("read {path} / {via_root}: {e}"))
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn find_dynsym_offset(image: &[u8], symbol: &str) -> Option<u64> {
    if image.len() < 64 || &image[0..4] != b"\x7fELF" || image[4] != 2 {
        return None;
    }
    let phoff = u64::from_le_bytes(image[32..40].try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(image[54..56].try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(image[56..58].try_into().ok()?) as usize;

    let mut dyn_vaddr = None;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(image[off..off + 4].try_into().ok()?);
        if p_type == 2 {
            dyn_vaddr = Some(u64::from_le_bytes(image[off + 16..off + 24].try_into().ok()?));
        }
    }
    let dyn_vaddr = dyn_vaddr?;
    let dyn_off = vaddr_to_file_off(image, phoff, phentsize, phnum, dyn_vaddr)?;

    let mut symtab = None;
    let mut strtab = None;
    let mut syment = 24u64;
    let mut pos = dyn_off;
    while pos + 16 <= image.len() {
        let tag = i64::from_le_bytes(image[pos..pos + 8].try_into().ok()?);
        let val = u64::from_le_bytes(image[pos + 8..pos + 16].try_into().ok()?);
        pos += 16;
        match tag {
            0 => break,
            6 => symtab = Some(val),
            5 => strtab = Some(val),
            11 => syment = val,
            _ => {}
        }
    }
    let symtab = vaddr_to_file_off(image, phoff, phentsize, phnum, symtab?)?;
    let strtab = vaddr_to_file_off(image, phoff, phentsize, phnum, strtab?)?;

    for i in 0..8192 {
        let sym = symtab + i * syment as usize;
        if sym + 24 > image.len() {
            break;
        }
        let st_name = u32::from_le_bytes(image[sym..sym + 4].try_into().ok()?) as usize;
        let st_value = u64::from_le_bytes(image[sym + 8..sym + 16].try_into().ok()?);
        let st_shndx = u16::from_le_bytes(image[sym + 6..sym + 8].try_into().ok()?);
        if st_value == 0 || st_shndx == 0 {
            continue;
        }
        let name = read_cstr(image, strtab + st_name);
        if name == symbol {
            return Some(st_value);
        }
    }
    None
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn vaddr_to_file_off(
    image: &[u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    vaddr: u64,
) -> Option<usize> {
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(image[off..off + 4].try_into().ok()?);
        if p_type != 1 {
            continue;
        }
        let p_offset = u64::from_le_bytes(image[off + 8..off + 16].try_into().ok()?);
        let p_vaddr = u64::from_le_bytes(image[off + 16..off + 24].try_into().ok()?);
        let p_filesz = u64::from_le_bytes(image[off + 32..off + 40].try_into().ok()?);
        if vaddr >= p_vaddr && vaddr < p_vaddr + p_filesz {
            return Some((p_offset + (vaddr - p_vaddr)) as usize);
        }
    }
    None
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn read_cstr(image: &[u8], start: usize) -> String {
    if start >= image.len() {
        return String::new();
    }
    let slice = &image[start..];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(0);
    String::from_utf8_lossy(&slice[..nul]).into_owned()
}
