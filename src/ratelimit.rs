//! Free-tier rate limiting, keyed on (policy, source IP).
//!
//! Uses the *sliding window counter* algorithm: each key keeps a count for the
//! current fixed window and the previous one, and the effective rate is the
//! current count plus a time-weighted fraction of the previous. That smooths
//! the burst a plain fixed window allows at a boundary (2x the limit across
//! two adjacent windows) while costing O(1) memory per key, unlike a log of
//! request timestamps.
//!
//! # Why limits are arguments, not fields
//!
//! Each policy carries its own `free_tier`, so the limit is a property of the
//! *request* rather than of the limiter. Buckets are keyed by policy as well as
//! IP: without that, spending the free allowance on a cheap route would also
//! exhaust it on an unrelated expensive one, and the two policies' limits would
//! fight over one counter.

use dashmap::DashMap;
use std::net::{IpAddr, Ipv6Addr};

use crate::util::now_epoch_secs;

/// What the free tier had left after considering one request.
///
/// Carries enough for `x-x402-free-*` response headers, so a client can see the
/// wall coming instead of discovering it as a 402.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowance {
    /// Whether this request was admitted (and therefore counted).
    pub allowed: bool,
    /// Requests still available in this window, after this one.
    pub remaining: u64,
    /// Configured ceiling, echoed so a client needs no second call to render a
    /// meter.
    pub limit: u64,
    /// Seconds until the current window rolls over.
    pub reset_secs: u64,
}

/// Collapse an address to the unit the free tier is metered on.
///
/// IPv4 is metered per address. IPv6 is metered per **/64**, because a typical
/// IPv6 client is *delegated* a /64 or shorter and can mint fresh addresses at
/// will — metering per address there is not rate limiting, it is an invitation
/// to iterate. /64 is the smallest block an end host is normally given, so it
/// is the smallest unit that means anything.
///
/// The tradeoff is deliberate: several users behind one /64 share a bucket.
/// That is the same property IPv4 NAT already has, and under-counting a
/// determined attacker is worse than over-counting a shared network.
fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
    }
}

/// Per-key counters for the current and preceding window.
#[derive(Debug, Clone, Copy)]
struct Window {
    /// Start timestamp of the current window, aligned to `window_secs`.
    start: u64,
    current: u64,
    previous: u64,
    /// Window length this key was last counted with. Stored per key because
    /// different policies use different windows, and the idle sweeper needs to
    /// know how long "idle" is for this particular bucket.
    window_secs: u64,
}

/// Bucket key: one counter per (policy, client). `policy` comes from config,
/// not from the request, so a client cannot mint fresh buckets by varying it.
fn key_for(policy: &str, ip: IpAddr) -> String {
    format!("{policy}|{}", bucket(ip))
}

/// Requests left after admitting one more, given a weighted window estimate.
///
/// Saturating on purpose: the estimate is fractional and can exceed the limit
/// mid-window after a rollover, which must read as "none left" rather than
/// underflow.
fn remaining_after(limit: u64, estimated: f64) -> u64 {
    let used = estimated.ceil().max(0.0) as u64;
    limit.saturating_sub(used)
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
///
/// Returns `{admitted, remaining}` so one round trip drives both the decision
/// and the client-facing meter.
///
/// Rejected requests are deliberately not counted, so a blocked client cannot
/// extend its own lockout by hammering the endpoint.
const CHECK_SCRIPT: &str = r#"
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local prev = tonumber(redis.call('GET', KEYS[2]) or '0')
local limit = tonumber(ARGV[1])
local est = cur + prev * tonumber(ARGV[3])
if est >= limit then return {0, 0} end
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
local remaining = limit - math.ceil(est + 1)
if remaining < 0 then remaining = 0 end
return {1, remaining}
"#;

/// In-process sliding-window rate limiter.
///
/// Counters are per-replica. See [`RedisRateLimiter`] for the shared variant.
#[derive(Debug, Default)]
pub struct MemoryRateLimiter {
    windows: DashMap<String, Window>,
}

impl MemoryRateLimiter {
    pub fn new() -> Self {
        Self::default()
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

    /// Record a request from `ip` under `policy` and report the allowance.
    ///
    /// A denied request is deliberately *not* counted, so a client cannot
    /// extend its own lockout by hammering the endpoint.
    ///
    /// # Panics
    /// If `window_secs` is zero. `Config::validate` rejects that at startup.
    pub fn check(&self, policy: &str, ip: IpAddr, max_requests: u64, window_secs: u64) -> Allowance {
        self.check_at(policy, ip, max_requests, window_secs, now_epoch_secs())
    }

    /// Clock-injected variant of [`Self::check`].
    fn check_at(
        &self,
        policy: &str,
        ip: IpAddr,
        max_requests: u64,
        window_secs: u64,
        now: u64,
    ) -> Allowance {
        assert!(window_secs > 0, "window_secs must be greater than zero");
        // Align to fixed window boundaries so all keys roll over together and
        // the weighting math below stays simple.
        let window_start = now - (now % window_secs);

        let mut entry = self.windows.entry(key_for(policy, ip)).or_insert(Window {
            start: window_start,
            current: 0,
            previous: 0,
            window_secs,
        });
        entry.window_secs = window_secs;

        if window_start > entry.start {
            // Exactly one window elapsed: today's count becomes yesterday's.
            // More than one: both windows are stale, so drop everything.
            if window_start - entry.start == window_secs {
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
        let carry_fraction = (window_secs - elapsed) as f64 / window_secs as f64;
        let estimated = entry.current as f64 + entry.previous as f64 * carry_fraction;
        let reset_secs = window_secs - elapsed;

        if estimated >= max_requests as f64 {
            return Allowance {
                allowed: false,
                remaining: 0,
                limit: max_requests,
                reset_secs,
            };
        }

        entry.current += 1;
        Allowance {
            allowed: true,
            remaining: remaining_after(max_requests, estimated + 1.0),
            limit: max_requests,
            reset_secs,
        }
    }

    /// Drop keys that have been idle long enough to hold no useful history.
    ///
    /// Without this, the map grows once per distinct (policy, source IP) pair
    /// forever, which is an unbounded-memory hazard on a public endpoint.
    pub fn cleanup_idle(&self) -> usize {
        self.cleanup_idle_at(now_epoch_secs())
    }

    fn cleanup_idle_at(&self, now: u64) -> usize {
        let before = self.windows.len();
        // Two windows of silence means both counters would be zeroed anyway.
        // The window length is per key, so the cutoff is computed per key too.
        self.windows
            .retain(|_, w| w.start >= now.saturating_sub(w.window_secs * 2));
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
}

impl RedisRateLimiter {
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let conn = redis::aio::ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    async fn check_at(
        &self,
        policy: &str,
        ip: IpAddr,
        max_requests: u64,
        window_secs: u64,
        now: u64,
    ) -> Allowance {
        assert!(window_secs > 0, "window_secs must be greater than zero");
        let key = key_for(policy, ip);
        let window_start = now - (now % window_secs);
        let previous_start = window_start.saturating_sub(window_secs);

        // Weight the previous window by how much of it still overlaps the
        // trailing window, matching the in-memory implementation exactly.
        let elapsed = now - window_start;
        let carry = (window_secs - elapsed) as f64 / window_secs as f64;
        let reset_secs = window_secs - elapsed;

        let mut conn = self.conn.clone();
        let result: Result<(i64, u64), _> = redis::Script::new(CHECK_SCRIPT)
            .key(format!("{REDIS_RATELIMIT_PREFIX}{key}:{window_start}"))
            .key(format!("{REDIS_RATELIMIT_PREFIX}{key}:{previous_start}"))
            .arg(max_requests)
            .arg(window_secs * 2)
            .arg(carry)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok((allowed, remaining)) => Allowance {
                allowed: allowed == 1,
                remaining: if allowed == 1 { remaining } else { 0 },
                limit: max_requests,
                reset_secs,
            },
            Err(e) => {
                // Fail closed: an unreachable Redis must not become an
                // unmetered free tier.
                tracing::error!(error = %e, "redis rate-limit check failed; denying request");
                Allowance {
                    allowed: false,
                    remaining: 0,
                    limit: max_requests,
                    reset_secs,
                }
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
    /// Record a request from `ip` under `policy` and report the allowance.
    pub async fn check(
        &self,
        policy: &str,
        ip: IpAddr,
        max_requests: u64,
        window_secs: u64,
    ) -> Allowance {
        match self {
            RateLimiter::Memory(l) => l.check(policy, ip, max_requests, window_secs),
            RateLimiter::Redis(l) => {
                l.check_at(policy, ip, max_requests, window_secs, now_epoch_secs())
                    .await
            }
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
    /// Policy name for tests that are not about policy scoping.
    const P: &str = "graphql";

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    /// `check_at` reduced to the admit/deny bit, for the many tests that only
    /// care about the decision.
    fn ok(rl: &MemoryRateLimiter, ip: IpAddr, max: u64, now: u64) -> bool {
        rl.check_at(P, ip, max, 60, now).allowed
    }

    #[test]
    fn ipv6_clients_cannot_reset_the_free_tier_by_rotating_addresses() {
        // A typical IPv6 host is delegated a /64, so per-address metering lets
        // it iterate its way to an unlimited free tier.
        let rl = MemoryRateLimiter::new();
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::9999".parse().unwrap(); // same /64
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap(); // different /64

        assert!(ok(&rl, a, 2, NOW));
        assert!(ok(&rl, b, 2, NOW));
        assert!(
            !ok(&rl, b, 2, NOW),
            "a fresh address in the same /64 must not get a fresh allowance"
        );
        // A genuinely different network is a different bucket.
        assert!(ok(&rl, c, 2, NOW));
    }

    #[test]
    fn ipv4_is_still_metered_per_address() {
        let rl = MemoryRateLimiter::new();
        assert!(ok(&rl, ip(1), 1, NOW));
        assert!(!ok(&rl, ip(1), 1, NOW));
        assert!(ok(&rl, ip(2), 1, NOW));
    }

    #[test]
    fn allows_up_to_the_limit_then_denies() {
        let rl = MemoryRateLimiter::new();
        for i in 0..3 {
            assert!(ok(&rl, ip(1), 3, NOW), "request {i} should be allowed");
        }
        assert!(!ok(&rl, ip(1), 3, NOW), "4th request should be denied");
    }

    #[test]
    fn denied_requests_are_not_counted() {
        // A blocked client hammering the endpoint must not push its own
        // recovery further out.
        let rl = MemoryRateLimiter::new();
        assert!(ok(&rl, ip(1), 2, NOW));
        assert!(ok(&rl, ip(1), 2, NOW));
        for _ in 0..50 {
            assert!(!ok(&rl, ip(1), 2, NOW));
        }
        // A full two windows later the history is gone and it recovers.
        assert!(ok(&rl, ip(1), 2, NOW + 120));
    }

    #[test]
    fn limits_are_tracked_independently_per_ip() {
        let rl = MemoryRateLimiter::new();
        assert!(ok(&rl, ip(1), 1, NOW));
        assert!(!ok(&rl, ip(1), 1, NOW));
        // A different client is unaffected.
        assert!(ok(&rl, ip(2), 1, NOW));
    }

    #[test]
    fn spending_one_policys_allowance_does_not_touch_another() {
        // The whole point of per-policy buckets: a cheap route and an expensive
        // one are different products and must not share a free tier.
        let rl = MemoryRateLimiter::new();
        assert!(rl.check_at("graphql", ip(1), 1, 60, NOW).allowed);
        assert!(!rl.check_at("graphql", ip(1), 1, 60, NOW).allowed);
        assert!(
            rl.check_at("grpc", ip(1), 1, 60, NOW).allowed,
            "an unrelated policy must have its own allowance"
        );
    }

    #[test]
    fn policies_may_use_different_window_lengths() {
        // Windows are per policy, so a 10s bucket must roll over on its own
        // schedule without disturbing a 60s one.
        let rl = MemoryRateLimiter::new();
        assert!(rl.check_at("fast", ip(1), 1, 10, NOW).allowed);
        assert!(!rl.check_at("fast", ip(1), 1, 10, NOW).allowed);
        assert!(rl.check_at("slow", ip(1), 1, 60, NOW).allowed);

        // Two 10s windows on, the fast policy has recovered...
        assert!(rl.check_at("fast", ip(1), 1, 10, NOW + 20).allowed);
        // ...while the slow one is still inside its first window.
        assert!(!rl.check_at("slow", ip(1), 1, 60, NOW + 20).allowed);
    }

    #[test]
    fn remaining_counts_down_to_zero_and_reports_the_limit() {
        // This is what drives the client-side meter, so an off-by-one here is
        // visible on the page as a wall that arrives a request early or late.
        let rl = MemoryRateLimiter::new();
        let seen: Vec<u64> = (0..3)
            .map(|_| rl.check_at(P, ip(1), 3, 60, NOW).remaining)
            .collect();
        assert_eq!(seen, vec![2, 1, 0]);

        let denied = rl.check_at(P, ip(1), 3, 60, NOW);
        assert!(!denied.allowed);
        assert_eq!(denied.remaining, 0);
        assert_eq!(denied.limit, 3);
    }

    #[test]
    fn reset_reports_seconds_until_the_window_rolls() {
        let rl = MemoryRateLimiter::new();
        assert_eq!(rl.check_at(P, ip(1), 5, 60, NOW).reset_secs, 60);
        assert_eq!(rl.check_at(P, ip(1), 5, 60, NOW + 45).reset_secs, 15);
    }

    #[test]
    fn quota_recovers_after_two_full_windows() {
        let rl = MemoryRateLimiter::new();
        assert!(ok(&rl, ip(1), 2, NOW));
        assert!(ok(&rl, ip(1), 2, NOW));
        assert!(!ok(&rl, ip(1), 2, NOW));
        assert!(ok(&rl, ip(1), 2, NOW + 120));
    }

    #[test]
    fn sliding_window_smooths_the_boundary_burst() {
        // The property a fixed window lacks: spending the full limit at the end
        // of one window must not permit the full limit again immediately.
        let rl = MemoryRateLimiter::new();
        for _ in 0..10 {
            assert!(ok(&rl, ip(1), 10, NOW + 59));
        }
        // One second later a new window starts, but ~100% of the previous
        // window still overlaps, so the estimate stays at the cap.
        assert!(
            !ok(&rl, ip(1), 10, NOW + 60),
            "fixed-window burst should be suppressed"
        );
        // Halfway through the new window the carry has decayed to ~50%,
        // leaving room again.
        assert!(ok(&rl, ip(1), 10, NOW + 90));
    }

    #[test]
    fn stale_history_beyond_one_window_is_discarded_not_carried() {
        let rl = MemoryRateLimiter::new();
        for _ in 0..5 {
            assert!(ok(&rl, ip(1), 5, NOW));
        }
        // Skipping several windows must zero both counters, not carry them.
        assert!(ok(&rl, ip(1), 5, NOW + 600));
    }

    #[test]
    fn cleanup_reaps_idle_keys_but_keeps_active_ones() {
        let rl = MemoryRateLimiter::new();
        ok(&rl, ip(1), 5, NOW); // Will go idle.
        ok(&rl, ip(2), 5, NOW + 300); // Recently active.
        assert_eq!(rl.len(), 2);

        let reaped = rl.cleanup_idle_at(NOW + 300);
        assert_eq!(reaped, 1);
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn cleanup_uses_each_keys_own_window_length() {
        // A short-window key goes idle long before a long-window one, so a
        // single global cutoff would reap the wrong bucket.
        let rl = MemoryRateLimiter::new();
        rl.check_at("fast", ip(1), 5, 10, NOW);
        rl.check_at("slow", ip(1), 5, 3600, NOW);

        // 60s on: two 10s windows have passed, but not two 3600s ones.
        assert_eq!(rl.cleanup_idle_at(NOW + 60), 1);
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn zero_limit_denies_everything() {
        let rl = MemoryRateLimiter::new();
        assert!(!ok(&rl, ip(1), 0, NOW));
    }

    #[test]
    fn concurrent_checks_never_exceed_the_limit() {
        const LIMIT: u64 = 100;
        let rl = Arc::new(MemoryRateLimiter::new());

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let rl = Arc::clone(&rl);
                std::thread::spawn(move || {
                    (0..100)
                        .filter(|_| rl.check_at(P, ip(1), LIMIT, 60, NOW).allowed)
                        .count()
                })
            })
            .collect();

        let allowed: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(allowed, LIMIT as usize);
    }

    // ---- Redis backend ----------------------------------------------------
    // See the note in session.rs: these no-op without X402_TEST_REDIS_URL.

    /// Unique-per-test IP so parallel tests cannot share a Redis counter key.
    fn unique_ip(tag: u16) -> IpAddr {
        IpAddr::from([10, 9, (tag >> 8) as u8, tag as u8])
    }

    async fn redis_limiter() -> Option<RedisRateLimiter> {
        let url = std::env::var("X402_TEST_REDIS_URL").ok()?;
        Some(
            RedisRateLimiter::connect(&url)
                .await
                .expect("connecting to the test redis"),
        )
    }

    #[tokio::test]
    async fn redis_allows_up_to_the_limit_then_denies() {
        let Some(rl) = redis_limiter().await else {
            return;
        };
        let ip = unique_ip(1);
        for i in 0..3 {
            assert!(
                rl.check_at(P, ip, 3, 60, NOW).await.allowed,
                "request {i} should be allowed"
            );
        }
        assert!(
            !rl.check_at(P, ip, 3, 60, NOW).await.allowed,
            "4th request should be denied"
        );
    }

    #[tokio::test]
    async fn redis_tracks_limits_independently_per_ip() {
        let Some(rl) = redis_limiter().await else {
            return;
        };
        assert!(rl.check_at(P, unique_ip(2), 1, 60, NOW).await.allowed);
        assert!(!rl.check_at(P, unique_ip(2), 1, 60, NOW).await.allowed);
        assert!(rl.check_at(P, unique_ip(3), 1, 60, NOW).await.allowed);
    }

    #[tokio::test]
    async fn redis_scopes_buckets_per_policy_like_the_memory_backend() {
        let Some(rl) = redis_limiter().await else {
            return;
        };
        let ip = unique_ip(7);
        assert!(rl.check_at("graphql", ip, 1, 60, NOW).await.allowed);
        assert!(!rl.check_at("graphql", ip, 1, 60, NOW).await.allowed);
        assert!(rl.check_at("grpc", ip, 1, 60, NOW).await.allowed);
    }

    #[tokio::test]
    async fn redis_reports_the_same_remaining_counts_as_memory() {
        // The two backends drive the same client-side meter; if they disagree,
        // switching store backends silently changes what users see.
        let Some(rl) = redis_limiter().await else {
            return;
        };
        let ip = unique_ip(8);
        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(rl.check_at(P, ip, 3, 60, NOW).await.remaining);
        }
        assert_eq!(seen, vec![2, 1, 0]);

        let memory = MemoryRateLimiter::new();
        let expected: Vec<u64> = (0..3)
            .map(|_| memory.check_at(P, ip, 3, 60, NOW).remaining)
            .collect();
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn redis_smooths_the_boundary_burst_like_the_memory_backend() {
        // Same property asserted for MemoryRateLimiter, so the two backends
        // cannot silently diverge in behavior.
        let Some(rl) = redis_limiter().await else {
            return;
        };
        let ip = unique_ip(4);
        for _ in 0..10 {
            assert!(rl.check_at(P, ip, 10, 60, NOW + 59).await.allowed);
        }
        // New window, but ~100% of the previous one still overlaps.
        assert!(
            !rl.check_at(P, ip, 10, 60, NOW + 60).await.allowed,
            "fixed-window burst should be suppressed"
        );
        // Halfway through, the carry has decayed to ~50%.
        assert!(rl.check_at(P, ip, 10, 60, NOW + 90).await.allowed);
    }

    #[tokio::test]
    async fn redis_denied_requests_are_not_counted() {
        let Some(rl) = redis_limiter().await else {
            return;
        };
        let ip = unique_ip(5);
        assert!(rl.check_at(P, ip, 2, 60, NOW).await.allowed);
        assert!(rl.check_at(P, ip, 2, 60, NOW).await.allowed);
        for _ in 0..20 {
            assert!(!rl.check_at(P, ip, 2, 60, NOW).await.allowed);
        }
        // Two windows on, history is gone and the client recovers.
        assert!(rl.check_at(P, ip, 2, 60, NOW + 120).await.allowed);
    }

    #[tokio::test]
    async fn redis_concurrent_checks_never_exceed_the_limit() {
        const LIMIT: u64 = 100;
        let Some(rl) = redis_limiter().await else {
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
                        if rl.check_at(P, ip, LIMIT, 60, NOW).await.allowed {
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
}
