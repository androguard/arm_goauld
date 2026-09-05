//! Re-entrant JS lock keyed by thread id (§6.1).

use parking_lot::Mutex;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    static HOLDING: Cell<bool> = const { Cell::new(false) };
}

static DEPTH: AtomicU64 = AtomicU64::new(0);

pub struct JsLock {
    inner: Mutex<()>,
}

impl Default for JsLock {
    fn default() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }
}

impl JsLock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `f` while holding the JS lock. If this thread already holds it,
    /// run `f` without re-locking (re-entrancy for nested hook → JS → hook).
    pub fn with<R>(&self, f: impl FnOnce() -> R) -> R {
        if HOLDING.with(|h| h.get()) {
            DEPTH.fetch_add(1, Ordering::Relaxed);
            let r = f();
            DEPTH.fetch_sub(1, Ordering::Relaxed);
            return r;
        }
        let _guard = self.inner.lock();
        HOLDING.with(|h| h.set(true));
        let r = f();
        HOLDING.with(|h| h.set(false));
        r
    }

    pub fn is_held_on_this_thread() -> bool {
        HOLDING.with(|h| h.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn reentrant_same_thread() {
        let lock = Arc::new(JsLock::new());
        let lock2 = lock.clone();
        lock.with(|| {
            assert!(JsLock::is_held_on_this_thread());
            lock2.with(|| {
                assert!(JsLock::is_held_on_this_thread());
            });
        });
        assert!(!JsLock::is_held_on_this_thread());
    }
}
