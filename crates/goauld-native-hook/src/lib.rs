//! goauld native hooking engine (Android / arm64).
//!
//! Inline hooks overwrite ≥16 bytes at the target with an absolute branch stub,
//! relocate displaced instructions into a trampoline, and dispatch enter/leave
//! callbacks through a global hook registry.

pub mod decoder;
pub mod encode;
pub mod icache;
pub mod patch;
pub mod relocator;
pub mod trampoline;
pub mod got;

pub use decoder::{Arm64Decoder, Cond, DecodedInsn, DisasmAdapter, InsnKind};
pub use patch::{HookError, InlineHook, attach, detach, detach_all, flush, replace_ptr};
pub use trampoline::{CpuContext, HookCallbacks, HookEntry, HookId};

/// Minimum patch size for a full-range absolute branch (LDR X17,#8; BR X17; <u64>).
pub const ABS_BRANCH_LEN: usize = 16;
