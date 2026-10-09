//! Lock helpers over `parking_lot`.
//!
//! `parking_lot` locks do not poison: a panic while a guard is held simply
//! releases the lock, so there is no recovery path to write (and no "cache
//! disabled forever" failure mode to guard against — the previous
//! `std::sync`-based helpers had to recover a poisoned guard to keep the DNS
//! caches functional). The block/try pair below is the only locking surface
//! the crate uses; it is a thin, allocation-free wrapper over
//! `parking_lot`'s guards.
//!
//! `parking_lot`'s uncontended fast path stays in user space (a CAS, no
//! futex), which is what the per-packet `try_lock` probes on the DNS shards
//! and session table pay.

pub fn lock_read<T>(l: &parking_lot::RwLock<T>) -> parking_lot::RwLockReadGuard<'_, T> {
    l.read()
}

pub fn lock_write<T>(l: &parking_lot::RwLock<T>) -> parking_lot::RwLockWriteGuard<'_, T> {
    l.write()
}

pub fn lock_mutex<T>(l: &parking_lot::Mutex<T>) -> parking_lot::MutexGuard<'_, T> {
    l.lock()
}

/// Non-blocking packet-path variants: never park a Tokio worker. `None` means
/// "contended right now" and the caller must fail fast (UDP drop semantics or
/// treat-as-miss), never block.
pub fn try_lock_read<T>(l: &parking_lot::RwLock<T>) -> Option<parking_lot::RwLockReadGuard<'_, T>> {
    l.try_read()
}

pub fn try_lock_write<T>(
    l: &parking_lot::RwLock<T>,
) -> Option<parking_lot::RwLockWriteGuard<'_, T>> {
    l.try_write()
}

pub fn try_lock_mutex<T>(l: &parking_lot::Mutex<T>) -> Option<parking_lot::MutexGuard<'_, T>> {
    l.try_lock()
}
