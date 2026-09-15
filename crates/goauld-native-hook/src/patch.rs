//! Memory patching for inline hooks (§4.5).

use crate::decoder::{Arm64Decoder, DisasmAdapter};
use crate::encode::encode_abs_branch;
use crate::icache::clear_icache;
use crate::relocator::build_trampoline;
use crate::trampoline::{
    alloc_hook_id, build_enter_thunk, build_leave_thunk, list_hook_ids, register_hook,
    unregister_hook, goauld_dispatch_enter, goauld_dispatch_leave, HookCallbacks, HookEntry,
    HookId,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HookError {
    #[error("relocation: {0}")]
    Reloc(#[from] crate::relocator::RelocError),
    #[error("mprotect failed: {0}")]
    Mprotect(i32),
    #[error("mmap failed")]
    Mmap,
    #[error("hook not found: {0}")]
    NotFound(HookId),
    #[error("{0}")]
    Msg(String),
}

pub struct InlineHook {
    pub id: HookId,
    pub target: u64,
    pub patch_len: usize,
}

/// Scratch page layout:
/// `[0 .. LEAVE_OFF)` enter thunk  
/// `[LEAVE_OFF .. RELOC_OFF)` leave thunk  
/// `[RELOC_OFF ..)` relocated original
const LEAVE_OFF: usize = 256;
const RELOC_OFF: usize = 512;

/// Install an inline hook at `target` (`Interceptor.attach` / JS replace-mode).
pub fn attach(
    target: u64,
    code: &[u8],
    callbacks: HookCallbacks,
) -> Result<InlineHook, HookError> {
    attach_with_decoder(&DisasmAdapter, target, code, callbacks)
}

pub fn attach_with_decoder(
    decoder: &impl Arm64Decoder,
    target: u64,
    code: &[u8],
    callbacks: HookCallbacks,
) -> Result<InlineHook, HookError> {
    let id = alloc_hook_id();
    let replace_mode = callbacks.replace_mode;
    let need_leave = callbacks.on_leave.is_some() || replace_mode;

    let scratch_cap = 4096usize;
    let scratch = alloc_exec(scratch_cap)?;

    let block = build_trampoline(decoder, target, code, scratch as u64 + RELOC_OFF as u64)?;

    let enter = build_enter_thunk(
        id,
        goauld_dispatch_enter as *const () as usize as u64,
        scratch as u64 + RELOC_OFF as u64,
        replace_mode,
    );
    if enter.len() > LEAVE_OFF {
        return Err(HookError::Msg("enter thunk exceeds reserved space".into()));
    }

    let leave = if need_leave {
        build_leave_thunk(id, goauld_dispatch_leave as *const () as usize as u64)
    } else {
        Vec::new()
    };
    if leave.len() > RELOC_OFF - LEAVE_OFF {
        return Err(HookError::Msg("leave thunk exceeds reserved space".into()));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(enter.as_ptr(), scratch, enter.len());
        if !leave.is_empty() {
            std::ptr::copy_nonoverlapping(leave.as_ptr(), scratch.add(LEAVE_OFF), leave.len());
        }
        std::ptr::copy_nonoverlapping(
            block.code.as_ptr(),
            scratch.add(RELOC_OFF),
            block.code.len(),
        );
        clear_icache(scratch, RELOC_OFF + block.code.len());
    }

    let leave_thunk = if need_leave {
        scratch as u64 + LEAVE_OFF as u64
    } else {
        0
    };

    let patch = encode_abs_branch(scratch as u64);
    let original_bytes = code[..block.patch_len].to_vec();

    #[cfg(all(target_arch = "aarch64", target_os = "android"))]
    {
        unsafe {
            mprotect_rwx(target as *mut u8, block.patch_len)?;
            std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, 16);
            for off in (16..block.patch_len).step_by(4) {
                let nop = 0xD503_201Fu32.to_le_bytes();
                std::ptr::copy_nonoverlapping(nop.as_ptr(), (target as *mut u8).add(off), 4);
            }
            clear_icache(target as *const u8, block.patch_len);
        }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "android")))]
    {
        let _ = patch;
        log::debug!(
            "attach: host build — recorded hook {id} at {target:#x} without live patch"
        );
    }

    register_hook(HookEntry {
        id,
        target,
        trampoline: scratch as u64,
        leave_thunk,
        patch_len: block.patch_len,
        original_bytes,
        callbacks,
        saved_lr: Default::default(),
    });

    Ok(InlineHook {
        id,
        target,
        patch_len: block.patch_len,
    })
}

/// `Interceptor.replace(target, replacementPtr)` — absolute branch, no trampoline call.
pub fn replace_ptr(target: u64, code: &[u8], replacement: u64) -> Result<InlineHook, HookError> {
    let id = alloc_hook_id();
    let patch_len = 16usize.min(code.len());
    if patch_len < 16 {
        return Err(HookError::Msg("need ≥16 prologue bytes for replace".into()));
    }
    let original_bytes = code[..patch_len].to_vec();
    let patch = encode_abs_branch(replacement);

    #[cfg(all(target_arch = "aarch64", target_os = "android"))]
    {
        unsafe {
            mprotect_rwx(target as *mut u8, patch_len)?;
            std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, 16);
            clear_icache(target as *const u8, patch_len);
        }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "android")))]
    {
        let _ = patch;
        log::debug!("replace_ptr: host build — recorded replace {id} at {target:#x}");
    }

    register_hook(HookEntry {
        id,
        target,
        trampoline: 0,
        leave_thunk: 0,
        patch_len,
        original_bytes,
        callbacks: HookCallbacks::default(),
        saved_lr: Default::default(),
    });

    Ok(InlineHook {
        id,
        target,
        patch_len,
    })
}

pub fn detach(id: HookId) -> Result<(), HookError> {
    let entry = unregister_hook(id).ok_or(HookError::NotFound(id))?;
    restore_bytes(&entry)?;
    Ok(())
}

/// Restore every live hook (Frida `Interceptor.detachAll`).
pub fn detach_all() -> Result<(), HookError> {
    let ids = list_hook_ids();
    for id in ids {
        let _ = detach(id);
    }
    Ok(())
}

/// Frida `Interceptor.flush` — icache sync for all hooked targets (no deferred queue yet).
pub fn flush() {
    let ids = list_hook_ids();
    for id in ids {
        let _ = with_hook_target(id, |target, len| {
            #[cfg(all(target_arch = "aarch64", target_os = "android"))]
            unsafe {
                clear_icache(target as *const u8, len);
            }
            #[cfg(not(all(target_arch = "aarch64", target_os = "android")))]
            {
                let _ = (target, len);
            }
        });
    }
}

fn with_hook_target<R>(id: HookId, f: impl FnOnce(u64, usize) -> R) -> Option<R> {
    crate::trampoline::with_hook_mut(id, |e| f(e.target, e.patch_len))
}

fn restore_bytes(entry: &HookEntry) -> Result<(), HookError> {
    #[cfg(all(target_arch = "aarch64", target_os = "android"))]
    {
        if entry.original_bytes.is_empty() {
            return Ok(());
        }
        unsafe {
            mprotect_rwx(entry.target as *mut u8, entry.patch_len)?;
            std::ptr::copy_nonoverlapping(
                entry.original_bytes.as_ptr(),
                entry.target as *mut u8,
                entry.original_bytes.len(),
            );
            clear_icache(entry.target as *const u8, entry.patch_len);
        }
    }
    let _ = entry;
    Ok(())
}

fn alloc_exec(len: usize) -> Result<*mut u8, HookError> {
    #[cfg(unix)]
    {
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if page == libc::MAP_FAILED {
            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if page == libc::MAP_FAILED {
                return Err(HookError::Mmap);
            }
            let rc = unsafe { libc::mprotect(page, len, libc::PROT_READ | libc::PROT_EXEC) };
            if rc != 0 {
                #[cfg(all(target_arch = "aarch64", target_os = "android"))]
                return Err(HookError::Mprotect(rc));
            }
            return Ok(page as *mut u8);
        }
        Ok(page as *mut u8)
    }
    #[cfg(not(unix))]
    {
        let _ = len;
        Err(HookError::Mmap)
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "android"))]
unsafe fn mprotect_rwx(addr: *mut u8, len: usize) -> Result<(), HookError> {
    let page = page_align(addr as usize);
    let end = (addr as usize + len + page_size() - 1) & !(page_size() - 1);
    let span = end - page;
    let rc = libc::mprotect(
        page as *mut _,
        span,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    );
    if rc != 0 {
        let rc = libc::mprotect(page as *mut _, span, libc::PROT_READ | libc::PROT_WRITE);
        if rc != 0 {
            return Err(HookError::Mprotect(rc));
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[allow(dead_code)]
fn page_align(addr: usize) -> usize {
    addr & !(page_size() - 1)
}
