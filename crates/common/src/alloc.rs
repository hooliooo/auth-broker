//! A counting global allocator, for measuring what requests cost on the heap. Only with the
//! `alloc-stats` feature, which a binary enables to install [`Counting`] as its allocator; the
//! counts then appear on its metrics page. Every allocation pays a few atomic additions, so
//! production builds leave the feature off.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};

/// Allocations made since start.
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
/// Bytes allocated since start, counting each reallocation's new size.
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
/// Bytes freed since start.
static FREED: AtomicU64 = AtomicU64::new(0);
/// The most bytes live at once.
static PEAK: AtomicU64 = AtomicU64::new(0);

/// The system allocator, counting as it goes.
pub struct Counting;

/// Records `size` new bytes and updates the peak.
fn grew(size: usize) {
    let allocated = ALLOCATED.fetch_add(size as u64, Relaxed) + size as u64;
    let live = allocated.saturating_sub(FREED.load(Relaxed));
    PEAK.fetch_max(live, Relaxed);
}

// SAFETY: every call is passed to `System` unchanged; the counters never affect what it returns.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        grew(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, which `System` shares.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        grew(layout.size());
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        FREED.fetch_add(layout.size() as u64, Relaxed);
        // SAFETY: `ptr` was allocated by this allocator, that is by `System`, with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        FREED.fetch_add(layout.size() as u64, Relaxed);
        grew(new_size);
        // SAFETY: as for `dealloc`, and the caller upholds `realloc`'s contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// The counts so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Allocations and reallocations since start.
    pub allocations: u64,
    /// Bytes allocated since start.
    pub allocated_bytes: u64,
    /// Bytes allocated and not yet freed.
    pub live_bytes: u64,
    /// The most bytes live at once since start.
    pub peak_live_bytes: u64,
}

/// The current counts; all zero unless [`Counting`] is the global allocator.
pub fn snapshot() -> Snapshot {
    let allocated = ALLOCATED.load(Relaxed);
    Snapshot {
        allocations: ALLOCATIONS.load(Relaxed),
        allocated_bytes: allocated,
        live_bytes: allocated.saturating_sub(FREED.load(Relaxed)),
        peak_live_bytes: PEAK.load(Relaxed),
    }
}
