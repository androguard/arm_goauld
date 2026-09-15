//! High-level inject_library sequence (§3.2).
//!
//! Intended to run **on the Android device** as the `goauld-injector` binary
//! (root / elevated), not on the desktop host.

use crate::remote::{Tracee, TraceeError};
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
                remote_call_stub, remote_mmap_svc, remote_mprotect_svc, write_memory,
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

            // Layout: [path cstr ...] [padding] [brk #0 at +0x800]
            let mut path_bytes = opts.library_path.as_bytes().to_vec();
            path_bytes.push(0);
            write_memory(pid, page, &path_bytes)?;
            let brk_off = 0x800u64;
            write_memory(pid, page + brk_off, &0xD420_0000u32.to_le_bytes())?;

            let (libc_base, libc_path) = find_libc(pid)?;
            let (dl_base, dl_path) = find_libdl(pid).unwrap_or((libc_base, libc_path.clone()));
            // Prefer plain dlopen (2 args) — fewer namespace ABI quirks.
            let (dlopen, dl_nargs) = match resolve_elf_symbol(pid, dl_base, &dl_path, "dlopen")
                .or_else(|_| resolve_elf_symbol(pid, libc_base, &libc_path, "dlopen"))
            {
                Ok(a) => (a, 2u32),
                Err(_) => (
                    resolve_elf_symbol(pid, dl_base, &dl_path, "android_dlopen_ext")
                        .map_err(InjectError::Symbol)?,
                    3u32,
                ),
            };
            eprintln!(
                "goauld-inject: dlopen={dlopen:#x} from {dl_path}@{dl_base:#x} nargs={dl_nargs}"
            );
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

            // Stub at page+0x700:
            //   LDR X16, #12 ; BLR X16 ; BRK #0 ; <u64 dlopen>
            let mut stub = Vec::new();
            stub.extend_from_slice(&(0x5800_0010u32 | (3u32 << 5)).to_le_bytes());
            stub.extend_from_slice(&0xD63F_0200u32.to_le_bytes());
            stub.extend_from_slice(&0xD420_0000u32.to_le_bytes());
            stub.extend_from_slice(&dlopen.to_le_bytes());
            let stub_addr = page + 0x700;
            write_memory(pid, stub_addr, &stub)?;
            // Also keep classic LR BRK at +0x800 as backup landing.
            let _ = brk_off;
            let mprotect = remote_mprotect_svc(&tracee, page, 0x1000, PROT_READ | PROT_EXEC)?;
            if mprotect != 0 {
                return Err(InjectError::Msg(format!(
                    "mprotect RX failed: {mprotect}"
                )));
            }

            let args: Vec<u64> = if dl_nargs == 2 {
                vec![page, RTLD_NOW]
            } else {
                vec![page, RTLD_NOW, 0]
            };
            let handle = remote_call_stub(&tracee, stub_addr, &args)?;
            if handle == 0 {
                return Err(InjectError::DlOpen(handle));
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
