//! Arm64 I-cache / D-cache maintenance for self-modified code (§4.5).

/// Query CTR_EL0 for D/I min line size in bytes. Falls back to 64 if unavailable.
#[inline]
pub fn cache_line_size() -> usize {
    #[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
    {
        let ctr: u64;
        unsafe {
            core::arch::asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack));
        }
        // DminLine = CTR_EL0[19:16], IminLine = CTR_EL0[3:0]; log2(words)
        let dmin = ((ctr >> 16) & 0xF) as u32;
        let imin = (ctr & 0xF) as u32;
        let d_bytes = 4usize << dmin;
        let i_bytes = 4usize << imin;
        d_bytes.max(i_bytes).max(4)
    }
    #[cfg(not(all(target_arch = "aarch64", not(target_os = "macos"))))]
    {
        64
    }
}

/// Clean D-cache to Point of Unification and invalidate I-cache for `[start, start+len)`.
///
/// Mandatory on arm64 after writing instructions — the CPU does not guarantee
/// I/D coherency for self-modified code.
#[inline]
pub unsafe fn clear_icache(start: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
    {
        let line = cache_line_size() as u64;
        let start_u = start as u64;
        let end = start_u + len as u64;
        // Align start down to line boundary.
        let mut addr = start_u & !(line - 1);
        let mut addr2 = addr;
        core::arch::asm!(
            "1:",
            "dc cvau, {addr}",
            "add {addr}, {addr}, {line}",
            "cmp {addr}, {end}",
            "b.lo 1b",
            "dsb ish",
            "2:",
            "ic ivau, {addr2}",
            "add {addr2}, {addr2}, {line}",
            "cmp {addr2}, {end}",
            "b.lo 2b",
            "dsb ish",
            "isb",
            addr = inout(reg) addr,
            addr2 = inout(reg) addr2,
            end = in(reg) end,
            line = in(reg) line,
            options(nostack)
        );
    }
    #[cfg(not(all(target_arch = "aarch64", not(target_os = "macos"))))]
    {
        let _ = (start, len);
        // Host/dev builds: no-op (hooks only execute on Android aarch64).
    }
}
