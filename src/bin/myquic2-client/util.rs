//! Reconnect/backoff jitter.

/// Random milliseconds in `0..=199` for reconnect/backoff waits.
///
/// Draws from `rand`'s thread-local generator, which is per-thread seeded:
/// concurrent clients do not share one backoff sequence (the property the
/// hand-rolled xorshift this replaces was written to provide). All call
/// sites are cold — dial/redial backoff and the per-association idle-tick
/// phase — so the generator's cost is irrelevant there.
pub(crate) fn jitter_ms() -> u64 {
    rand::random_range(0..200u64)
}
