//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock time as seconds since the Unix epoch.
///
/// Wall clock (not [`std::time::Instant`]) is deliberate: session expiry is
/// embedded in HMAC-signed tokens handed to clients, so it must survive a
/// process restart and be comparable across replicas. The tradeoff is that a
/// backwards NTP step can extend a session; that window is bounded by the
/// session TTL and is acceptable here.
///
/// Returns 0 if the system clock is set before 1970, which only happens on a
/// badly misconfigured host. Returning 0 makes every token look expired
/// (fail-closed) rather than panicking inside a request path.
pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
