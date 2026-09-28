/// Poison-safe lock helpers. The previous `if let Ok(..)` handling silently
/// disabled all DNS caching forever after any panic while a lock was held;
/// recovering the guard keeps the cache functional (a HashMap cannot be left
/// in a half-formed state by such a panic).
fn warn_poisoned() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| tracing::warn!("a cache lock was poisoned; recovering"));
}

pub fn lock_read<T>(l: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

pub fn lock_write<T>(l: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

pub fn lock_mutex<T>(l: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    l.lock().unwrap_or_else(|e| {
        warn_poisoned();
        e.into_inner()
    })
}

/// Non-blocking packet-path variants: never park a Tokio worker. `None` means
/// "contended right now" and the caller must fail fast (UDP drop semantics or
/// treat-as-miss), never block. Poison is still recovered the same way.
pub fn try_lock_read<T>(l: &std::sync::RwLock<T>) -> Option<std::sync::RwLockReadGuard<'_, T>> {
    match l.try_read() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => {
            warn_poisoned();
            Some(e.into_inner())
        }
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

pub fn try_lock_write<T>(l: &std::sync::RwLock<T>) -> Option<std::sync::RwLockWriteGuard<'_, T>> {
    match l.try_write() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => {
            warn_poisoned();
            Some(e.into_inner())
        }
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}

pub fn try_lock_mutex<T>(l: &std::sync::Mutex<T>) -> Option<std::sync::MutexGuard<'_, T>> {
    match l.try_lock() {
        Ok(g) => Some(g),
        Err(std::sync::TryLockError::Poisoned(e)) => {
            warn_poisoned();
            Some(e.into_inner())
        }
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}
