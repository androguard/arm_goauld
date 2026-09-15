//! JS scripting layer (§6).
//!
//! Threading: a re-entrant mutex keyed by thread id (§6.1). Hook dispatchers
//! acquire it before touching JS; nested hook fires on the same thread execute
//! synchronously without re-locking.
//!
//! ART/Java hooks are marshalled onto a dedicated JS worker (`js_queue`) so
//! the engine never runs on an ART binder/hook thread.
//!
//! Engine selection (mutually exclusive features):
//! - `quickjs` (default) — rquickjs / QuickJS
//! - `symbiote` — path-dep [`symbiote-core`](https://github.com/arm-goauld/symbiote) + JIT

#![cfg_attr(all(feature = "quickjs", feature = "symbiote"), allow(unused_imports))]

#[cfg(all(feature = "quickjs", feature = "symbiote"))]
compile_error!("enable only one JS engine feature: `quickjs` or `symbiote`");

mod engine;
mod js_lock;
pub mod api;
pub mod arm64_code;
pub mod bridge;
pub mod cloak;
pub mod frida_prelude;
pub mod host_ops;
pub mod js_queue;
pub mod memory_access;
pub mod timers;

#[cfg(feature = "quickjs")]
pub mod bindings;

#[cfg(feature = "symbiote")]
pub mod bindings_symbiote;

/// Active JS backend (QuickJS or Symbiote), selected at compile time.
#[cfg(feature = "quickjs")]
pub mod js_backend {
    pub use crate::bindings::*;
}

#[cfg(feature = "symbiote")]
pub mod js_backend {
    pub use crate::bindings_symbiote::*;
}

pub use engine::{ScriptEngine, ScriptError, ScriptId};
pub use js_lock::JsLock;
