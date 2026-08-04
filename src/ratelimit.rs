//! Free-tier rate limiting, keyed on source IP.
//!
//! Uses the *sliding window counter* algorithm: each key keeps a count for the
//! current fixed window and the previous one, and the effective rate is the
//! current count plus a time-weighted fraction of the previous. That smooths
//! the burst a plain fixed window allows at a boundary (2x the limit across
//! two adjacent windows) while costing O(1) memory per key, unlike a log of
//! request timestamps.

use dashmap::DashMap;
use std::net::IpAddr;

use crate::util::now_epoch_secs;

/// Per-key counters for the current and preceding window.
#[derive(Debug, Clone, Copy)]
struct Window {
    /// Start timestamp of the current window, aligned to `window_secs`.
    start: u64,
    current: u64,
    previous: u64,
}

/// Redis key prefix for rate-limit counters.
const REDIS_RATELIMIT_PREFIX: &str = "x402:rl:";

/// Atomically evaluate and record one request against the sliding window.
///
/// Must be a script: reading both counters and then incrementing from Rust
/// would let concurrent requests across replicas each observe an
/// under-the-limit count and all be admitted. Redis runs this indivisibly.
///
/// `KEYS[1]` current window counter, `KEYS[2]` previous window counter.
/// `ARGV[1]` limit, `ARGV[2]` key TTL, `ARGV[3]` previous-window weight.
/// Returns 1 when the request is admitted (and counted), 0 when rejected.
///
/// Rejected requests are deliberately not counted, so a blocked client cannot
/// extend its own lockout by hammering the endpoint.
const CHECK_SCRIPT: &str = r#"
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local prev = tonumber(redis.call('GET', KEYS[2]) or '0')
if cur + prev * tonumber(ARGV[3]) >= tonumber(ARGV[1]) then return 0 end
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
return 1
"#;

/// In-process sliding-window rate limiter.
///
/// Counters are per-replica. See [`RedisRateLimiter`] for the shared variant.
#[derive(Debug)]
pub struct MemoryRateLimiter {
    windows: DashMap<IpAddr, Window>,
    max_requests: u64,
    window_secs: u64,
}

impl MemoryRateLimiter {
    /// # Panics
    /// If `window_secs` is zero. `Config::validate` rejects that at startup.
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        assert!(window_secs > 0, "window_secs must be greater than zero");
        Self {
            windows: DashMap::new(),
            max_requests,
            window_secs,
        }
    }

    pub fn len(&self) -> usize {
        self.windows.len()
    }

    /// Present to satisfy `clippy::len_without_is_empty`; kept for the metrics
    /// endpoint that will land alongside the Redis-backed store.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Record a request from `ip` and report whether it is within the limit.
    ///
    /// Returns `true` if allowed (the request is counted) and `false` if the
    /// limit is exceeded (the request is *not* counted, so a client cannot
    /// extend its own lockout by hammering the endpoint).
    pub fn check(&self, ip: IpAddr) -> bool {
        self.check_at(ip, now_epoch_secs())
    }

    /// Clock-injected variant of [`Self::check`].
    fn check_at(&self, ip: IpAddr, now: u64) -> bool {
        // Align to fixed window boundaries so all keys roll over together and
        // the weighting math below stays simple.
        let window_start = now - (now % self.window_secs);

        let mut entry = self.windows.entry(ip).or_insert(Window {
            start: window_start,
            current: 0,
            previous: 0,
        });

        if window_start > entry.start {
            // Exactly one window elapsed: today's count becomes yesterday's.
            // More than one: both windows are stale, so drop everything.
            if window_start - entry.start == self.window_secs {
                entry.previous = entry.current;
            } else {
                entry.previous = 0;
            }
            entry.current = 0;
            entry.start = window_start;
        }

        // Weight the previous window by how much of it still overlaps the
        // trailing `window_secs`. Just after a rollover the previous window
        // counts almost fully; by the end of the current window, not at all.
        let elapsed = now - entry.start;
        let carry_fraction = (self.window_secs - elapsed) as f64 / self.window_secs as f64;
        let estimated = entry.current as f64 + entry.previous as f64 * carry_fraction;

        if estimated >= self.max_requests as f64 {
            return false;
        }

        entry.current += 1;
        true
    }

    /// Drop keys that have been idle long enough to hold no useful history.
    ///
    /// Without this, the map grows once per distinct source IP forever, which
    /// is an unbounded-memory hazard on a public endpoint.
    pub fn cleanup_idle(&self) -> usize {
        self.cleanup_idle_at(now_epoch_secs())
    }

    fn cleanup_idle_at(&self, now: u64) -> usize {
        let before = self.windows.len();
        // Two windows of silence means both counters would be zeroed anyway.
        let cutoff = now.saturating_sub(self.window_secs * 2);
        self.windows.retain(|_, w| w.start >= cutoff);
        before - self.windows.len()
    }
}

/// Redis-backed sliding-window rate limiter shared across replicas.
///
/// Counter keys carry their window start, so expiry is handled by Redis TTLs
/// and no sweeper is required.
#[derive(Debug, Clone)]
pub struct RedisRateLimiter {
    conn: redis::aio::ConnectionManager,
    max_requests: u64,
    window_secs: u64,
}

impl RedisRateLimiter {
    pub async fn connect(
        url: &str,
        max_requests: u64,
        window_secs: u64,
    ) -> Result<Self, redis::RedisError> {
        assert!(window_secs > 0, "window_secs must be greater than zero");
        let client = redis::Client::open(url)?;
        let conn = redis::aio::ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            max_requests,
            window_secs,
        })
    }

    async fn check_at(&self, ip: IpAddr, now: u64) -> bool {
        let window_start = now - (now % self.window_secs);
        let previous_start = window_start.saturating_sub(self.window_secs);

        // Weight the previous window by how much of it still overlaps the
        // trailing window, matching the in-memory implementation exactly.
        let elapsed = now - window_start;
        let carry = (self.window_secs - elapsed) as f64 / self.window_secs as f64;

        let mut conn = self.conn.clone();
        let result: Result<i64, _> = redis::Script::new(CHECK_SCRIPT)
            .key(format!("{REDIS_RATELIMIT_PREFIX}{ip}:{window_start}"))
            .key(format!("{REDIS_RATELIMIT_PREFIX}{ip}:{previous_start}"))
            .arg(self.max_requests)
            .arg(self.window_secs * 2)
            .arg(carry)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok(allowed) => allowed == 1,
            Err(e) => {
                // Fail closed: an unreachable Redis must not become an
                // unmetered free tier.
                tracing::error!(error = %e, "redis rate-limit check failed; denying request");
                false
            }
        }
    }
}

/// Rate-limiting backend.
#[derive(Debug)]
pub enum RateLimiter {
    Memory(MemoryRateLimiter),
    Redis(RedisRateLimiter),
}

impl RateLimiter {
    /// Record a request from `ip` and report whether it is within the limit.
    pub async fn check(&self, ip: IpAddr) -> bool {
        match self {
            RateLimiter::Memory(l) => l.check(ip),
            RateLimiter::Redis(l) => l.check_at(ip, now_epoch_secs()).await,
        }
    }

    /// Reap idle keys. Redis expires its own counters via TTL.
    pub async fn cleanup_idle(&self) -> usize {
        match self {
            RateLimiter::Memory(l) => l.cleanup_idle(),
            RateLimiter::Redis(_) => 0,
        }
    }

    /// Tracked key count; Redis is not scanned (see `SessionStore::len`).
    pub fn len(&self) -> usize {
        match self {
            RateLimiter::Memory(l) => l.len(),
            RateLimiter::Redis(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Aligned to a 60-second boundary (1_700_000_040 % 60 == 0) so tests can
    /// reason about window rollovers precisely. Do not "round" this to
    /// 1_700_000_000 — that value is 20 seconds into a window, which silently
    /// shifts every boundary assertion below.
    const NOW: u64 = 1_700_000_040;
    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn allows_up_to_the_limit_then_denies() {
        let rl = MemoryRateLimiter::new(3, 60);
        for i in 0..3 {
            assert!(rl.check_at(ip(1), NOW), "request {i} should be allowed");
        }
        assert!(!rl.check_at(ip(1), NOW), "4th request should be denied");
    }

    #[test]
    fn denied_requests_are_not_counted() {
        // A blocked client hammering the endpoint must not push its own
        // recovery further out.
        let rl = MemoryRateLimiter::new(2, 60);
        assert!(rl.check_at(ip(1), NOW));
        assert!(rl.check_at(ip(1), NOW));
        for _ in 0..50 {
            assert!(!rl.check_at(ip(1), NOW));
        }
        // A full two windows later the history is gone and it recovers.
        assert!(rl.check_at(ip(1), NOW + 120));
    }

    #[test]
    fn limits_are_tracked_independently_per_ip() {
        let rl = MemoryRateLimiter::new(1, 60);
        assert!(rl.check_at(ip(1), NOW));
        assert!(!rl.check_at(ip(1), NOW));
        // A different client is unaffected.
        assert!(rl.check_at(ip(2), NOW));
    }

    #[test]
    fn quota_recovers_after_two_full_windows() {
        let rl = MemoryRateLimiter::new(2, 60);
        assert!(rl.check_at(ip(1), NOW));
        assert!(rl.check_at(ip(1), NOW));
        assert!(!rl.check_at(ip(1), NOW));
        assert!(rl.check_at(ip(1), NOW + 120));
    }

    #[test]
    fn sliding_window_smooths_the_boundary_burst() {
        // The property a fixed window lacks: spending the full limit at the end
        // of one window must not permit the full limit again immediately.
        let rl = MemoryRateLimiter::new(10, 60);
        for _ in 0..10 {
            assert!(rl.check_at(ip(1), NOW + 59));
        }
        // One second later a new window starts, but ~100% of the previous
        // window still overlaps, so the estimate stays at the cap.
        assert!(
            !rl.check_at(ip(1), NOW + 60),
            "fixed-window burst should be suppressed"
        );
        // Halfway through the new window the carry has decayed to ~50%,
        // leaving room again.
        assert!(rl.check_at(ip(1), NOW + 90));
    }

    #[test]
    fn stale_history_beyond_one_window_is_discarded_not_carried() {
        let rl = MemoryRateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(rl.check_at(ip(1), NOW));
        }
        // Skipping several windows must zero both counters, not carry them.
        assert!(rl.check_at(ip(1), NOW + 600));
    }

    #[test]
    fn cleanup_reaps_idle_keys_but_keeps_active_ones() {
        let rl = MemoryRateLimiter::new(5, 60);
        rl.check_at(ip(1), NOW); // Will go idle.
        rl.check_at(ip(2), NOW + 300); // Recently active.
        assert_eq!(rl.len(), 2);

        let reaped = rl.cleanup_idle_at(NOW + 300);
        assert_eq!(reaped, 1);
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn zero_limit_denies_everything() {
        let rl = MemoryRateLimiter::new(0, 60);
        assert!(!rl.check_at(ip(1), NOW));
    }

    // ---- Redis backend ----------------------------------------------------
    // See the note in session.rs: these no-op without X402_TEST_REDIS_URL.

    /// Unique-per-test IP so parallel tests cannot share a Redis counter key.
    fn unique_ip(tag: u16) -> IpAddr {
        IpAddr::from([10, 9, (tag >> 8) as u8, tag as u8])
    }

    async fn redis_limiter(max: u64, window: u64) -> Option<RedisRateLimiter> {
        let url = std::env::var("X402_TEST_REDIS_URL").ok()?;
        Some(
            RedisRateLimiter::connect(&url, max, window)
                .await
                .expect("connecting to the test redis"),
        )
    }

    #[tokio::test]
    async fn redis_allows_up_to_the_limit_then_denies() {
        let Some(rl) = redis_limiter(3, 60).await else {
            return;
        };
        let ip = unique_ip(1);
        for i in 0..3 {
            assert!(rl.check_at(ip, NOW).await, "request {i} should be allowed");
        }
        assert!(!rl.check_at(ip, NOW).await, "4th request should be denied");
    }

    #[tokio::test]
    async fn redis_tracks_limits_independently_per_ip() {
        let Some(rl) = redis_limiter(1, 60).await else {
            return;
        };
        assert!(rl.check_at(unique_ip(2), NOW).await);
        assert!(!rl.check_at(unique_ip(2), NOW).await);
        assert!(rl.check_at(unique_ip(3), NOW).await);
    }

    #[tokio::test]
    async fn redis_smooths_the_boundary_burst_like_the_memory_backend() {
        // Same property asserted for MemoryRateLimiter, so the two backends
        // cannot silently diverge in behavior.
        let Some(rl) = redis_limiter(10, 60).await else {
            return;
        };
        let ip = unique_ip(4);
        for _ in 0..10 {
            assert!(rl.check_at(ip, NOW + 59).await);
        }
        // New window, but ~100% of the previous one still overlaps.
        assert!(
            !rl.check_at(ip, NOW + 60).await,
            "fixed-window burst should be suppressed"
        );
        // Halfway through, the carry has decayed to ~50%.
        assert!(rl.check_at(ip, NOW + 90).await);
    }

    #[tokio::test]
    async fn redis_denied_requests_are_not_counted() {
        let Some(rl) = redis_limiter(2, 60).await else {
            return;
        };
        let ip = unique_ip(5);
        assert!(rl.check_at(ip, NOW).await);
        assert!(rl.check_at(ip, NOW).await);
        for _ in 0..20 {
            assert!(!rl.check_at(ip, NOW).await);
        }
        // Two windows on, history is gone and the client recovers.
        assert!(rl.check_at(ip, NOW + 120).await);
    }

    #[tokio::test]
    async fn redis_concurrent_checks_never_exceed_the_limit() {
        const LIMIT: u64 = 100;
        let Some(rl) = redis_limiter(LIMIT, 60).await else {
            return;
        };
        let rl = Arc::new(rl);
        let ip = unique_ip(6);

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let rl = Arc::clone(&rl);
                tokio::spawn(async move {
                    let mut allowed = 0usize;
                    for _ in 0..50 {
                        if rl.check_at(ip, NOW).await {
                            allowed += 1;
                        }
                    }
                    allowed
                })
            })
            .collect();

        let mut total = 0usize;
        for t in tasks {
            total += t.await.unwrap();
        }
        assert_eq!(total, LIMIT as usize);
    }

    #[test]
    fn concurrent_checks_never_exceed_the_limit() {
        const LIMIT: u64 = 100;
        let rl = Arc::new(MemoryRateLimiter::new(LIMIT, 60));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let rl = Arc::clone(&rl);
                std::thread::spawn(move || (0..100).filter(|_| rl.check_at(ip(1), NOW)).count())
            })
            .collect();

        let allowed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(allowed, LIMIT as usize);
    }
}
