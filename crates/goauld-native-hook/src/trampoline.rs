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
}

pub struct HookEntry {
    pub id: HookId,
    pub target: u64,
    pub trampoline: u64,
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
    with_hook_mut(hook_id, |entry| {
        if entry.callbacks.on_leave.is_some() {
            // Redirect LR to leave thunk; stash original LR for later.
            let original_lr = ctx.x[30];
            entry
                .saved_lr
                .lock()
                .entry(tid)
                .or_default()
                .push(original_lr);
            // leave_thunk address is stored in trampoline page metadata — for now
            // callers patch LR via HookEntry after installing leave stub.
            let _ = original_lr;
        }
        if let Some(ref mut cb) = entry.callbacks.on_enter {
            cb(ctx);
        }
    });
}

/// Called from the assembly leave thunk; `retval` is the function's X0.
#[no_mangle]
pub unsafe extern "C" fn goauld_dispatch_leave(ctx: *mut CpuContext, hook_id: u32) {
    if ctx.is_null() {
        return;
    }
    let ctx = &mut *ctx;
    let tid = gettid();
    with_hook_mut(hook_id, |entry| {
        let retval = ctx.x[0];
        if let Some(ref mut cb) = entry.callbacks.on_leave {
            cb(ctx, retval);
        }
        // Restore original LR into X30 so leave thunk can RET to it.
        if let Some(stack) = entry.saved_lr.lock().get_mut(&tid) {
            if let Some(lr) = stack.pop() {
                ctx.x[30] = lr;
            }
        }
    });
}

fn gettid() -> u32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        unsafe { libc::syscall(libc::SYS_gettid) as u32 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // Host unit tests only — not used for real leave-thunk LR stacks.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::thread::current().id().hash(&mut h);
        h.finish() as u32
    }
}

/// Machine-code builder for a minimal GP-only enter thunk.
///
/// The thunk:
/// 1. Saves FP/LR and X0–X30 onto a stack frame shaped like [`CpuContext`]
/// 2. Calls `goauld_dispatch_enter(ctx, hook_id)`
/// 3. Restores registers (dispatcher may have mutated them)
/// 4. Branches to `relocated_trampoline`
///
/// Returns raw AArch64 bytes; caller places them in an RX page.
pub fn build_enter_thunk(hook_id: u32, dispatch: u64, relocated: u64) -> Vec<u8> {
    use crate::encode::encode_abs_branch;

    let mut out = Vec::new();
    // STP X29, X30, [SP, #-16]!
    out.extend_from_slice(&0xA9BF_7BFDu32.to_le_bytes());
    // SUB SP, SP, #256  (31*8 = 248, round to 256 for CpuContext.x + room)
    // SUB SP, SP, #0x100 → 0xD100_03FF with imm
    out.extend_from_slice(&0xD103_03FFu32.to_le_bytes()); // SUB SP, SP, #192? use 0x100
    // Actually: SUB <Xd|SP>, <Xn|SP>, #imm12 — sf=1, op=1, S=0, sh=0
    // 0xD100_0000 | imm12<<10 | rn<<5 | rd  with rn=rd=31 (SP), imm=256=0x100
    let sub_sp = 0xD100_0000u32 | (0x100u32 << 10) | (31 << 5) | 31;
    // Replace the placeholder SUB
    let n = out.len();
    out[n - 4..].copy_from_slice(&sub_sp.to_le_bytes());

    // Store X0–X30 at [SP, #i*8]. Use STP pairs where possible.
    for i in (0..30).step_by(2) {
        // STP Xi, Xi+1, [SP, #(i*8)]
        let imm7 = ((i * 8) / 8) as u32; // scaled by 8 for 64-bit
        let stp = 0xA900_0000u32
            | (imm7 << 15)
            | ((i as u32 + 1) << 10)
            | (31 << 5)
            | (i as u32);
        out.extend_from_slice(&stp.to_le_bytes());
    }
    // STR X30, [SP, #240]
    let str_x30 = 0xF900_0000u32 | ((240u32 / 8) << 10) | (31 << 5) | 30;
    out.extend_from_slice(&str_x30.to_le_bytes());

    // MOV X0, SP
    out.extend_from_slice(&0x9100_03E0u32.to_le_bytes());
    // MOV X1, #hook_id  (MOVZ W1, #imm16)
    let movz = 0x5280_0001u32 | ((hook_id as u32 & 0xFFFF) << 5);
    out.extend_from_slice(&movz.to_le_bytes());

    // Absolute BL to dispatch: ADR LR, resume; LDR X16,#8; BR X16; <addr>
    // Simpler: use LDR X16 + BLR X16 with embedded address
    let bl_seq = encode_blr_abs(dispatch);
    out.extend_from_slice(&bl_seq);

    // Restore X0–X30
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

    // ADD SP, SP, #256
    let add_sp = 0x9100_0000u32 | (0x100u32 << 10) | (31 << 5) | 31;
    out.extend_from_slice(&add_sp.to_le_bytes());
    // LDP X29, X30, [SP], #16
    out.extend_from_slice(&0xA8C1_7BFDu32.to_le_bytes());

    // B relocated
    out.extend_from_slice(&encode_abs_branch(relocated));

    let _ = relocated;
    out
}

fn encode_blr_abs(target: u64) -> Vec<u8> {
    // Layout (20 bytes):
    //   0: LDR X16, #12   // load absolute target from offset 12
    //   4: BLR X16
    //   8: B  #12         // skip the 8-byte literal after return
    //  12: <u64 target>
    //  20: caller continues
    let mut out = Vec::with_capacity(20);
    let ldr = 0x5800_0010u32 | (3u32 << 5); // LDR X16, #12
    out.extend_from_slice(&ldr.to_le_bytes());
    out.extend_from_slice(&0xD63F_0200u32.to_le_bytes()); // BLR X16
    out.extend_from_slice(&0x1400_0003u32.to_le_bytes()); // B #12
    out.extend_from_slice(&target.to_le_bytes());
    out
}
