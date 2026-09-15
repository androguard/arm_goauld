//! Enter/leave thunk layout and CpuContext (§4.4).

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Saved GP register file presented to enter/leave callbacks.
///
/// Layout mirrors the arm64 `user_regs_struct` field order so JS
/// `this.context.x0` maps directly onto these slots.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuContext {
    pub x: [u64; 31], // X0–X30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

impl Default for CpuContext {
    fn default() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
        }
    }
}

pub type HookId = u32;

pub type EnterFn = Box<dyn FnMut(&mut CpuContext) + Send>;
pub type LeaveFn = Box<dyn FnMut(&mut CpuContext, u64 /* retval in x0 */) + Send>;

pub struct HookCallbacks {
    pub on_enter: Option<EnterFn>,
    pub on_leave: Option<LeaveFn>,
    /// When true, enter thunk also saves/restores Q0–Q31 (expensive).
    pub save_simd: bool,
    /// `Interceptor.replace`: run enter callback then return without calling original.
    pub replace_mode: bool,
}

impl Default for HookCallbacks {
    fn default() -> Self {
        Self {
            on_enter: None,
            on_leave: None,
            save_simd: false,
            replace_mode: false,
        }
    }
}

pub struct HookEntry {
    pub id: HookId,
    pub target: u64,
    pub trampoline: u64,
    /// Absolute address of leave thunk inside `trampoline` page (0 = none).
    pub leave_thunk: u64,
    pub patch_len: usize,
    pub original_bytes: Vec<u8>,
    pub callbacks: HookCallbacks,
    /// Per-thread stack of saved original LR for reentrant onLeave.
    pub saved_lr: Mutex<HashMap<u32 /* tid */, Vec<u64>>>,
}

static NEXT_HOOK_ID: AtomicU32 = AtomicU32::new(1);
// Mutex (not RwLock): callbacks are `FnMut + Send` but not `Sync`.
static HOOKS: Mutex<Option<HashMap<HookId, HookEntry>>> = Mutex::new(None);

fn registry() -> parking_lot::MutexGuard<'static, Option<HashMap<HookId, HookEntry>>> {
    let mut g = HOOKS.lock();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    g
}

pub fn alloc_hook_id() -> HookId {
    NEXT_HOOK_ID.fetch_add(1, Ordering::Relaxed)
}

pub fn register_hook(entry: HookEntry) {
    let id = entry.id;
    registry().as_mut().unwrap().insert(id, entry);
}

pub fn unregister_hook(id: HookId) -> Option<HookEntry> {
    registry().as_mut().and_then(|m| m.remove(&id))
}

pub fn list_hook_ids() -> Vec<HookId> {
    registry()
        .as_ref()
        .map(|m| m.keys().copied().collect())
        .unwrap_or_default()
}

pub fn with_hook_mut<R>(id: HookId, f: impl FnOnce(&mut HookEntry) -> R) -> Option<R> {
    let mut g = registry();
    g.as_mut().and_then(|m| m.get_mut(&id).map(f))
}

/// Called from the assembly enter thunk.
#[no_mangle]
pub unsafe extern "C" fn goauld_dispatch_enter(ctx: *mut CpuContext, hook_id: u32) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *ctx;
    let tid = gettid();

    // Must not hold the hook registry lock while running callbacks: they may
    // block on the JS worker (or re-enter attach/detach), which also needs HOOKS.
    let mut on_enter = {
        let mut g = registry();
        let Some(map) = g.as_mut() else {
            return;
        };
        let Some(entry) = map.get_mut(&hook_id) else {
            return;
        };
        let want_leave = entry.callbacks.on_leave.is_some() || entry.callbacks.replace_mode;
        if want_leave && entry.leave_thunk != 0 {
            let original_lr = ctx.x[30];
            entry
                .saved_lr
                .lock()
                .entry(tid)
                .or_default()
                .push(original_lr);
            ctx.x[30] = entry.leave_thunk;
        }
        entry.callbacks.on_enter.take()
    };

    if let Some(ref mut cb) = on_enter {
        cb(ctx);
    }

    let mut g = registry();
    if let Some(entry) = g.as_mut().and_then(|m| m.get_mut(&hook_id)) {
        if entry.callbacks.on_enter.is_none() {
            entry.callbacks.on_enter = on_enter;
        }
    }
}

/// Called from the assembly leave thunk; retval is in `ctx.x[0]`.
#[no_mangle]
pub unsafe extern "C" fn goauld_dispatch_leave(ctx: *mut CpuContext, hook_id: u32) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *ctx;
    let tid = gettid();

    let (mut on_leave, retval) = {
        let mut g = registry();
        let Some(map) = g.as_mut() else {
            return;
        };
        let Some(entry) = map.get_mut(&hook_id) else {
            return;
        };
        let retval = ctx.x[0];
        (entry.callbacks.on_leave.take(), retval)
    };

    if let Some(ref mut cb) = on_leave {
        cb(ctx, retval);
    }

    let mut g = registry();
    if let Some(entry) = g.as_mut().and_then(|m| m.get_mut(&hook_id)) {
        if entry.callbacks.on_leave.is_none() {
            entry.callbacks.on_leave = on_leave;
        }
        if let Some(stack) = entry.saved_lr.lock().get_mut(&tid) {
            if let Some(lr) = stack.pop() {
                ctx.x[30] = lr;
            }
        }
    }
}

fn gettid() -> u32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        unsafe { libc::syscall(libc::SYS_gettid) as u32 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::thread::current().id().hash(&mut h);
        h.finish() as u32
    }
}

/// Enter thunk: spill regs → dispatch → restore → (optional LR redirect) → original or RET.
pub fn build_enter_thunk(
    hook_id: u32,
    dispatch: u64,
    relocated: u64,
    replace_mode: bool,
) -> Vec<u8> {
    use crate::encode::encode_abs_branch;

    let mut out = Vec::new();
    // STP X29, X30, [SP, #-16]!
    out.extend_from_slice(&0xA9BF_7BFDu32.to_le_bytes());
    let sub_sp = 0xD100_0000u32 | (0x100u32 << 10) | (31 << 5) | 31;
    out.extend_from_slice(&sub_sp.to_le_bytes());

    for i in (0..30).step_by(2) {
        let imm7 = ((i * 8) / 8) as u32;
        let stp = 0xA900_0000u32
            | (imm7 << 15)
            | ((i as u32 + 1) << 10)
            | (31 << 5)
            | (i as u32);
        out.extend_from_slice(&stp.to_le_bytes());
    }
    let str_x30 = 0xF900_0000u32 | ((240u32 / 8) << 10) | (31 << 5) | 30;
    out.extend_from_slice(&str_x30.to_le_bytes());

    out.extend_from_slice(&0x9100_03E0u32.to_le_bytes()); // MOV X0, SP
    let movz = 0x5280_0001u32 | ((hook_id as u32 & 0xFFFF) << 5);
    out.extend_from_slice(&movz.to_le_bytes());
    out.extend_from_slice(&encode_blr_abs(dispatch));

    for i in (0..30).step_by(2) {
        let imm7 = ((i * 8) / 8) as u32;
        let ldp = 0xA940_0000u32
            | (imm7 << 15)
            | ((i as u32 + 1) << 10)
            | (31 << 5)
            | (i as u32);
        out.extend_from_slice(&ldp.to_le_bytes());
    }
    let ldr_x30 = 0xF940_0000u32 | ((240u32 / 8) << 10) | (31 << 5) | 30;
    out.extend_from_slice(&ldr_x30.to_le_bytes());

    // Preserve redirected LR across frame teardown.
    out.extend_from_slice(&0xAA1E_03F0u32.to_le_bytes()); // MOV X16, X30
    let add_sp = 0x9100_0000u32 | (0x100u32 << 10) | (31 << 5) | 31;
    out.extend_from_slice(&add_sp.to_le_bytes());
    out.extend_from_slice(&(0xF900_0000u32 | ((8u32 / 8) << 10) | (31 << 5) | 16).to_le_bytes());
    out.extend_from_slice(&0xA8C1_7BFDu32.to_le_bytes()); // LDP X29, X30, [SP], #16

    if replace_mode {
        out.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET → leave thunk
    } else {
        out.extend_from_slice(&encode_abs_branch(relocated));
    }

    out
}

/// Leave thunk: spill → dispatch_leave → restore original LR → RET.
pub fn build_leave_thunk(hook_id: u32, dispatch: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA9BF_7BFDu32.to_le_bytes());
    let sub_sp = 0xD100_0000u32 | (0x100u32 << 10) | (31 << 5) | 31;
    out.extend_from_slice(&sub_sp.to_le_bytes());

    for i in (0..30).step_by(2) {
        let imm7 = ((i * 8) / 8) as u32;
        let stp = 0xA900_0000u32
            | (imm7 << 15)
            | ((i as u32 + 1) << 10)
            | (31 << 5)
            | (i as u32);
        out.extend_from_slice(&stp.to_le_bytes());
    }
    let str_x30 = 0xF900_0000u32 | ((240u32 / 8) << 10) | (31 << 5) | 30;
    out.extend_from_slice(&str_x30.to_le_bytes());

    out.extend_from_slice(&0x9100_03E0u32.to_le_bytes());
    let movz = 0x5280_0001u32 | ((hook_id as u32 & 0xFFFF) << 5);
    out.extend_from_slice(&movz.to_le_bytes());
    out.extend_from_slice(&encode_blr_abs(dispatch));

    for i in (0..30).step_by(2) {
        let imm7 = ((i * 8) / 8) as u32;
        let ldp = 0xA940_0000u32
            | (imm7 << 15)
            | ((i as u32 + 1) << 10)
            | (31 << 5)
            | (i as u32);
        out.extend_from_slice(&ldp.to_le_bytes());
    }
    let ldr_x30 = 0xF940_0000u32 | ((240u32 / 8) << 10) | (31 << 5) | 30;
    out.extend_from_slice(&ldr_x30.to_le_bytes());

    out.extend_from_slice(&0xAA1E_03F0u32.to_le_bytes()); // MOV X16, X30
    let add_sp = 0x9100_0000u32 | (0x100u32 << 10) | (31 << 5) | 31;
    out.extend_from_slice(&add_sp.to_le_bytes());
    out.extend_from_slice(&(0xF900_0000u32 | ((8u32 / 8) << 10) | (31 << 5) | 16).to_le_bytes());
    out.extend_from_slice(&0xA8C1_7BFDu32.to_le_bytes());
    out.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET

    out
}

fn encode_blr_abs(target: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    let ldr = 0x5800_0010u32 | (3u32 << 5); // LDR X16, #12
    out.extend_from_slice(&ldr.to_le_bytes());
    out.extend_from_slice(&0xD63F_0200u32.to_le_bytes()); // BLR X16
    out.extend_from_slice(&0x1400_0003u32.to_le_bytes()); // B #12
    out.extend_from_slice(&target.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_thunk_has_branch_or_ret() {
        let t = build_enter_thunk(1, 0x1000, 0x2000, false);
        assert!(t.len() > 40);
        let r = build_enter_thunk(1, 0x1000, 0x2000, true);
        assert_eq!(&r[r.len() - 4..], &0xD65F_03C0u32.to_le_bytes());
    }

    #[test]
    fn leave_thunk_ends_with_ret() {
        let t = build_leave_thunk(7, 0x3000);
        assert_eq!(&t[t.len() - 4..], &0xD65F_03C0u32.to_le_bytes());
    }
}
