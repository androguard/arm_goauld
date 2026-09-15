//! setTimeout / setInterval / setImmediate scheduling onto the JS worker.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

struct TimerEntry {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn timers() -> &'static Mutex<HashMap<u64, TimerEntry>> {
    static TIMERS: OnceLock<Mutex<HashMap<u64, TimerEntry>>> = OnceLock::new();
    TIMERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Schedule a one-shot or repeating timer. Returns timer id.
pub fn schedule(delay_ms: u64, repeating: bool) -> u64 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    timers().lock().insert(
        id,
        TimerEntry {
            cancelled: cancelled.clone(),
        },
    );
    let delay = Duration::from_millis(delay_ms);
    thread::Builder::new()
        .name(format!("goauld-timer-{id}"))
        .spawn(move || {
            loop {
                thread::sleep(delay);
                if cancelled.load(Ordering::SeqCst) {
                    break;
                }
                let src = format!(
                    "try{{__goauld_fireTimer({id});}}catch(e){{try{{console.error('timer-err:'+e);}}catch(_){{}}}}"
                );
                let _ = crate::js_queue::submit_eval_async(src);
                if !repeating || cancelled.load(Ordering::SeqCst) {
                    // One-shot: drop entry if still ours.
                    let mut g = timers().lock();
                    if let Some(e) = g.get(&id) {
                        if Arc::ptr_eq(&e.cancelled, &cancelled) {
                            g.remove(&id);
                        }
                    }
                    break;
                }
            }
        })
        .ok();
    id
}

pub fn cancel(id: u64) {
    if let Some(e) = timers().lock().remove(&id) {
        e.cancelled.store(true, Ordering::SeqCst);
    }
}
