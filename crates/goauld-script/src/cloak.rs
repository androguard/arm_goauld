//! Frida-style Cloak: hide threads / ranges / fds from introspection APIs.

use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Range {
    pub base: u64,
    pub size: u64,
}

impl Range {
    pub fn end(self) -> u64 {
        self.base.saturating_add(self.size)
    }

    pub fn contains(self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    pub fn overlaps(self, other: Range) -> bool {
        self.base < other.end() && other.base < self.end()
    }
}

#[derive(Default)]
struct Registry {
    threads: HashSet<u64>,
    fds: HashSet<i32>,
    ranges: Vec<Range>,
}

fn registry() -> &'static Mutex<Registry> {
    static REG: OnceLock<Mutex<Registry>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(Registry::default()))
}

pub fn add_thread(id: u64) {
    registry().lock().threads.insert(id);
}

pub fn remove_thread(id: u64) {
    registry().lock().threads.remove(&id);
}

pub fn has_thread(id: u64) -> bool {
    registry().lock().threads.contains(&id)
}

pub fn has_current_thread() -> bool {
    has_thread(current_tid())
}

pub fn current_tid() -> u64 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: process id as stand-in on host builds.
        std::process::id() as u64
    }
}

pub fn add_range(base: u64, size: u64) {
    if size == 0 {
        return;
    }
    let mut g = registry().lock();
    let r = Range { base, size };
    // Merge simple overlaps / adjacency for compactness.
    g.ranges.retain(|x| !x.overlaps(r) && x.end() != r.base && r.end() != x.base);
    g.ranges.push(r);
}

pub fn remove_range(base: u64, size: u64) {
    let mut g = registry().lock();
    g.ranges.retain(|r| !(r.base == base && r.size == size));
}

pub fn has_range_containing(addr: u64) -> bool {
    registry().lock().ranges.iter().any(|r| r.contains(addr))
}

pub fn is_range_cloaked(base: u64, size: u64) -> bool {
    let probe = Range { base, size };
    registry()
        .lock()
        .ranges
        .iter()
        .any(|r| r.base <= probe.base && r.end() >= probe.end())
}

/// True if any cloaked range overlaps `[base, base+size)`.
pub fn range_overlaps_cloaked(base: u64, size: u64) -> bool {
    let probe = Range { base, size };
    registry().lock().ranges.iter().any(|r| r.overlaps(probe))
}

/// Visible fragments of `range`. `None` = entirely visible; `Some([])` = entirely cloaked.
pub fn clip_range(base: u64, size: u64) -> Option<Vec<Range>> {
    if size == 0 {
        return None;
    }
    let start = base;
    let end = base.saturating_add(size);
    let cloaked: Vec<Range> = {
        let g = registry().lock();
        let mut hits: Vec<Range> = g
            .ranges
            .iter()
            .filter_map(|r| {
                let lo = r.base.max(start);
                let hi = r.end().min(end);
                if lo < hi {
                    Some(Range {
                        base: lo,
                        size: hi - lo,
                    })
                } else {
                    None
                }
            })
            .collect();
        hits.sort_by_key(|r| r.base);
        hits
    };
    if cloaked.is_empty() {
        return None;
    }
    let mut visible = Vec::new();
    let mut cursor = start;
    for c in &cloaked {
        if cursor < c.base {
            visible.push(Range {
                base: cursor,
                size: c.base - cursor,
            });
        }
        cursor = cursor.max(c.end());
    }
    if cursor < end {
        visible.push(Range {
            base: cursor,
            size: end - cursor,
        });
    }
    Some(visible)
}

pub fn add_fd(fd: i32) {
    registry().lock().fds.insert(fd);
}

pub fn remove_fd(fd: i32) {
    registry().lock().fds.remove(&fd);
}

pub fn has_fd(fd: i32) -> bool {
    registry().lock().fds.contains(&fd)
}
