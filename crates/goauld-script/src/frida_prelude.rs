//! Shared Frida-shaped JS prelude (Process / Memory / Interceptor / Java / Arm64Writer / …).
//!
//! Both QuickJS and Symbiote evaluate this after installing `__goauld` host helpers
//! and a `NativePointer` constructor.

pub const FRIDA_PRELUDE: &str = include_str!("frida_prelude.inc.js");
