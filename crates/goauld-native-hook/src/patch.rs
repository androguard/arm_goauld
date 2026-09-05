//! Memory patching for inline hooks (§4.5).

use crate::decoder::{Arm64Decoder, DisasmAdapter};
use crate::encode::encode_abs_branch;
use crate::icache::clear_icache;
use crate::relocator::build_trampoline;
use crate::trampoline::{
    alloc_hook_id, build_enter_thunk, register_hook, unregister_hook, HookCallbacks, HookEntry,
    HookId, goauld_dispatch_enter,
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

/// Install an inline hook at `target`.
///
/// `code` must contain at least 16 bytes of the function prologue.
/// On Android aarch64 this writes the patch into the live process; on host
/// builds it allocates a local trampoline and records the hook without
/// patching (for unit tests of the relocator path).
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

    // Allocate RWX (or RW→RX) scratch for enter thunk + relocated trampoline.
    let scratch_cap = 4096usize;
    let scratch = alloc_exec(scratch_cap)?;

    // Layout: [enter_thunk] [relocated trampoline]
    // We don't know enter size yet — build relocated at a tentative offset, then
    // rebuild enter with the final relocated address.
    let tentative_reloc_off = 512usize;
    let block = build_trampoline(decoder, target, code, scratch as u64 + tentative_reloc_off as u64)?;

    let enter = build_enter_thunk(
        id,
        goauld_dispatch_enter as *const () as usize as u64,
        scratch as u64 + tentative_reloc_off as u64,
    );
    if enter.len() > tentative_reloc_off {
        return Err(HookError::Msg("enter thunk exceeds reserved space".into()));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(enter.as_ptr(), scratch, enter.len());
        std::ptr::copy_nonoverlapping(
            block.code.as_ptr(),
            scratch.add(tentative_reloc_off),
            block.code.len(),
        );
        clear_icache(scratch, tentative_reloc_off + block.code.len());
    }

    let patch = encode_abs_branch(scratch as u64);
    let original_bytes = code[..block.patch_len].to_vec();

    // Patch the live target when running on Android aarch64.
    #[cfg(all(target_arch = "aarch64", target_os = "android"))]
    {
        unsafe {
            mprotect_rwx(target as *mut u8, block.patch_len)?;
            std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, 16);
            // Pad remaining overwritten bytes with NOP if patch_len > 16.
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

pub fn detach(id: HookId) -> Result<(), HookError> {
    let entry = unregister_hook(id).ok_or(HookError::NotFound(id))?;
    #[cfg(all(target_arch = "aarch64", target_os = "android"))]
    {
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
            // Fallback: RW then mprotect RX (W^X friendly path).
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
                // Keep RW for host tests that only inspect bytes.
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
        // Try RW window then caller re-asserts RX after write.
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
