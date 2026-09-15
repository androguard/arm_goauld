//! JS scripting layer (§6).
//!
//! Threading: a re-entrant mutex keyed by thread id (§6.1). Hook dispatchers
//! acquire it before touching JS; nested hook fires on the same thread execute
//! synchronously without re-locking.
//!
//! ART/Java hooks are marshalled onto a dedicated JS worker (`js_queue`) so
//! QuickJS never runs on an ART binder/hook thread.

mod engine;
mod js_lock;
pub mod api;
pub mod cloak;
pub mod js_queue;
pub mod memory_access;
pub mod timers;

#[cfg(feature = "quickjs")]
pub mod bindings;

pub use engine::{ScriptEngine, ScriptError, ScriptId};
pub use js_lock::JsLock;
