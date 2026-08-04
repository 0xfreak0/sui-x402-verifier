//! Paid-session tracking with stateless, HMAC-authenticated tokens.
//!
//! # Token format
//!
//! ```text
//! <payer>:<expires_epoch_secs>:<session_id>:<hmac_hex>
//! ```
//!
//! The MAC covers `<payer>:<expires>:<session_id>`. Colon is a safe delimiter
//! because every field is hex or decimal — no field can contain one, so a
//! client cannot shift bytes between fields to forge a different meaning.
//!
//! The token authenticates *who* and *until when*; the server-side map holds
//! the mutable quota. That split means a forged or tampered token is rejected
//! without a map lookup, while quota can still be spent atomically.

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::util::now_epoch_secs;

type HmacSha256 = Hmac<Sha256>;

/// Server-side state for one paid session.
#[derive(Debug)]
pub struct Session {
    /// Sui address that paid.
    pub payer: String,
    /// Absolute expiry, seconds since the Unix epoch.
    pub expires_at: u64,
    /// Requests still available. Atomic so concurrent requests on the same
    /// session can spend quota without a write lock on the map.
    pub quota_remaining: AtomicU64,
}

/// Why a presented session token was not honored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRejection {
    /// Wrong shape, bad hex, or a MAC that does not verify.
    Malformed,
    /// Well-formed and authentic, but past its expiry.
    Expired,
    /// Authentic and unexpired, but the server no longer has it (restart, or
    /// reaped after expiry).
    Unknown,
    /// Authentic and live, but all requests have been spent.
    QuotaExhausted,
    /// The store could not be reached. Treated as a rejection so an outage
    /// fails closed instead of handing out paid access.
    Backend,
}

/// Outcome of presenting a session token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Accepted; one request was deducted.
    Accepted {
        payer: String,
        remaining: u64,
    },
    Rejected(SessionRejection),
}

/// A session store operation failed against its backend.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
}

/// Claims carried by an authenticated session token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClaims {
    pub payer: String,
    pub expires_at: u64,
    pub session_id: String,
}

/// Mints and authenticates session tokens.
///
/// Backend-independent on purpose: the HMAC path is the security boundary, so
/// there is exactly one copy of it regardless of where session state lives.
#[derive(Debug, Clone)]
pub struct TokenCodec {
    hmac_key: Vec<u8>,
}

impl TokenCodec {
    pub fn new(hmac_key: Vec<u8>) -> Self {
        Self { hmac_key }
    }

    fn mac(&self, signed_part: &str) -> Vec<u8> {
        // `new_from_slice` only errors for key sizes HMAC cannot accept; HMAC
        // accepts any length, and Config already enforces a floor.
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC accepts keys of any length");
        mac.update(signed_part.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Produce a bearer token for a session.
    pub fn mint(&self, payer: &str, expires_at: u64, session_id: &str) -> String {
        let signed_part = format!("{payer}:{expires_at}:{session_id}");
        let mac = hex::encode(self.mac(&signed_part));
        format!("{signed_part}:{mac}")
    }

    /// Authenticate a token and extract its claims.
    ///
    /// Verifies the MAC *before* trusting any field, and compares in constant
    /// time so the MAC cannot be recovered byte-by-byte through timing.
    pub fn verify(&self, token: &str, now: u64) -> Result<TokenClaims, SessionRejection> {
        // Exactly four fields; splitn would let a stray colon smuggle data into
        // the last field, so require an exact split.
        let parts: Vec<&str> = token.trim().split(':').collect();
        if parts.len() != 4 {
            return Err(SessionRejection::Malformed);
        }
        let (payer, expires_raw, session_id, mac_hex) = (parts[0], parts[1], parts[2], parts[3]);

        let Ok(presented_mac) = hex::decode(mac_hex) else {
            return Err(SessionRejection::Malformed);
        };

        let signed_part = format!("{payer}:{expires_raw}:{session_id}");
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC accepts keys of any length");
        mac.update(signed_part.as_bytes());
        if mac.verify_slice(&presented_mac).is_err() {
            return Err(SessionRejection::Malformed);
        }

        let Ok(expires_at) = expires_raw.parse::<u64>() else {
            return Err(SessionRejection::Malformed);
        };
        if now >= expires_at {
            return Err(SessionRejection::Expired);
        }

        Ok(TokenClaims {
            payer: payer.to_string(),
            expires_at,
            session_id: session_id.to_string(),
        })
    }
}

/// Generate an unguessable session identifier.
fn new_session_id() -> String {
    let mut raw = [0u8; 16];
    rand::rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Redis key prefix for session state.
const REDIS_SESSION_PREFIX: &str = "x402:sess:";
/// Redis key prefix for the payment replay cache.
const REDIS_REPLAY_PREFIX: &str = "x402:seen:";

/// Atomically claim a payment, reporting whether it had already been used.
///
/// Must be a script: a GET-then-SET from Rust leaves a window in which two
/// replicas both observe "unused" and both mint a session for the same
/// payment. Redis runs this indivisibly.
///
/// Returns `{1, now}` on first use and `{0, first_seen}` on a replay.
const CLAIM_SCRIPT: &str = r#"
local existing = redis.call('GET', KEYS[1])
if existing then return {0, existing} end
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
return {1, ARGV[1]}
"#;

/// Outcome of claiming a payment against the replay cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentClaim {
    /// First time this payment has been seen; it is now recorded.
    Fresh,
    /// Already used, at this Unix timestamp.
    Replay { first_seen: u64 },
    /// The store could not be reached. Fails closed at the call site.
    Backend,
}

/// Atomically spend one request from a session.
///
/// Must be a script rather than GET-then-DECR from Rust: between those two
/// round trips another replica could spend the last request, and the quota
/// would go negative. Redis executes this indivisibly.
///
/// Returns `{remaining, payer}`, with negative sentinels for the failure modes
/// so one round trip distinguishes them:
///   -2 → no such session (expired via TTL, or minted by a since-restarted
///        deployment)
///   -1 → session exists but quota is spent
const SPEND_SCRIPT: &str = r#"
local payer = redis.call('HGET', KEYS[1], 'payer')
if not payer then return {-2, ''} end
local quota = tonumber(redis.call('HGET', KEYS[1], 'quota'))
if quota == nil or quota <= 0 then return {-1, payer} end
redis.call('HINCRBY', KEYS[1], 'quota', -1)
return {quota - 1, payer}
"#;

/// In-memory store of live paid sessions.
///
/// Per-process: correct for a single replica, wrong for several. See
/// [`RedisSessionStore`].
#[derive(Debug)]
pub struct MemorySessionStore {
    sessions: DashMap<String, Session>,
    /// Payment id -> first-seen Unix timestamp. See [`PaymentClaim`].
    seen_payments: DashMap<String, u64>,
    codec: TokenCodec,
    ttl_secs: u64,
    quota: u64,
}

impl MemorySessionStore {
    pub fn new(hmac_key: Vec<u8>, ttl_secs: u64, quota: u64) -> Self {
        Self {
            sessions: DashMap::new(),
            seen_payments: DashMap::new(),
            codec: TokenCodec::new(hmac_key),
            ttl_secs,
            quota,
        }
    }

    /// Number of sessions currently held. Test and metrics aid.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Present to satisfy `clippy::len_without_is_empty`; kept for the metrics
    /// endpoint that will land alongside the Redis-backed store.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Mint a session for `payer` and return the bearer token.
    pub fn create_session(&self, payer: &str) -> String {
        self.create_session_at(payer, now_epoch_secs())
    }

    /// Clock-injected variant so tests can drive expiry deterministically.
    fn create_session_at(&self, payer: &str, now: u64) -> String {
        let session_id = new_session_id();
        let expires_at = now.saturating_add(self.ttl_secs);

        self.sessions.insert(
            session_id.clone(),
            Session {
                payer: payer.to_string(),
                expires_at,
                quota_remaining: AtomicU64::new(self.quota),
            },
        );

        self.codec.mint(payer, expires_at, &session_id)
    }

    /// Authenticate `token` and, if everything checks out, spend one request.
    pub fn consume(&self, token: &str) -> SessionOutcome {
        self.consume_at(token, now_epoch_secs())
    }

    /// Clock-injected variant of [`Self::consume`].
    fn consume_at(&self, token: &str, now: u64) -> SessionOutcome {
        let claims = match self.codec.verify(token, now) {
            Ok(claims) => claims,
            Err(rejection) => return SessionOutcome::Rejected(rejection),
        };

        let Some(session) = self.sessions.get(&claims.session_id) else {
            return SessionOutcome::Rejected(SessionRejection::Unknown);
        };

        // Re-check expiry against server state. The token is authentic, but the
        // authoritative deadline is the one we stored.
        if now >= session.expires_at {
            return SessionOutcome::Rejected(SessionRejection::Expired);
        }

        match spend_one(&session.quota_remaining) {
            Some(remaining) => SessionOutcome::Accepted {
                payer: session.payer.clone(),
                remaining,
            },
            None => SessionOutcome::Rejected(SessionRejection::QuotaExhausted),
        }
    }

    /// Record first use of a payment, or report it as a replay.
    fn claim_payment_at(&self, payment_id: &str, ttl_secs: u64, now: u64) -> PaymentClaim {
        use dashmap::mapref::entry::Entry;
        match self.seen_payments.entry(payment_id.to_string()) {
            Entry::Occupied(entry) => {
                let first_seen = *entry.get();
                // Expired entries are indistinguishable from never-seen, which
                // is why the TTL must outlive settlement latency.
                if now.saturating_sub(first_seen) >= ttl_secs {
                    entry.replace_entry(now);
                    PaymentClaim::Fresh
                } else {
                    PaymentClaim::Replay { first_seen }
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(now);
                PaymentClaim::Fresh
            }
        }
    }

    /// Undo a claim, so an unspent payment can be retried.
    fn release_payment(&self, payment_id: &str) {
        self.seen_payments.remove(payment_id);
    }

    /// Drop sessions whose deadline has passed. Called by a background task.
    pub fn cleanup_expired(&self) -> usize {
        self.cleanup_expired_at(now_epoch_secs())
    }

    fn cleanup_expired_at(&self, now: u64) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, s| now < s.expires_at);
        let reaped = before - self.sessions.len();

        // Replay records are bounded by the same sweep; without this the map
        // grows once per distinct payment forever.
        self.seen_payments
            .retain(|_, first_seen| now.saturating_sub(*first_seen) < self.ttl_secs);

        reaped
    }
}

/// Atomically decrement a quota counter, refusing to go below zero.
///
/// A plain `fetch_sub` would wrap `0u64` to `u64::MAX` and hand out effectively
/// unlimited requests, so this uses a compare-exchange loop instead.
/// Returns the remaining count on success, or `None` if quota was exhausted.
fn spend_one(counter: &AtomicU64) -> Option<u64> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current == 0 {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(current - 1),
            // Lost the race; `current` now holds the observed value, retry.
            Err(observed) => current = observed,
        }
    }
}

/// Redis-backed session store, shared across replicas.
///
/// Expiry is delegated to Redis key TTLs rather than a sweeper task, so a
/// session disappears on schedule even if every verifier restarts.
#[derive(Debug, Clone)]
pub struct RedisSessionStore {
    conn: redis::aio::ConnectionManager,
    codec: TokenCodec,
    ttl_secs: u64,
    quota: u64,
}

impl RedisSessionStore {
    /// Connect and verify the server is reachable.
    ///
    /// `ConnectionManager` reconnects transparently, so a Redis blip degrades
    /// to failed operations rather than a permanently broken service.
    pub async fn connect(
        url: &str,
        hmac_key: Vec<u8>,
        ttl_secs: u64,
        quota: u64,
    ) -> Result<Self, StoreError> {
        let client = redis::Client::open(url)?;
        let conn = redis::aio::ConnectionManager::new(client).await?;
        Ok(Self {
            conn,
            codec: TokenCodec::new(hmac_key),
            ttl_secs,
            quota,
        })
    }

    fn key(session_id: &str) -> String {
        format!("{REDIS_SESSION_PREFIX}{session_id}")
    }

    async fn claim_payment(&self, payment_id: &str, ttl_secs: u64) -> PaymentClaim {
        let now = now_epoch_secs();
        let mut conn = self.conn.clone();
        let result: Result<(i64, u64), _> = redis::Script::new(CLAIM_SCRIPT)
            .key(format!("{REDIS_REPLAY_PREFIX}{payment_id}"))
            .arg(now)
            .arg(ttl_secs)
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok((1, _)) => PaymentClaim::Fresh,
            Ok((_, first_seen)) => PaymentClaim::Replay { first_seen },
            Err(e) => {
                tracing::error!(error = %e, "redis replay check failed; refusing the payment");
                PaymentClaim::Backend
            }
        }
    }

    async fn create_session(&self, payer: &str) -> Result<String, StoreError> {
        let session_id = new_session_id();
        let expires_at = now_epoch_secs().saturating_add(self.ttl_secs);
        let key = Self::key(&session_id);

        let mut conn = self.conn.clone();
        // Pipelined and atomic so a crash cannot leave a session with a payer
        // but no quota, or with no expiry at all.
        redis::pipe()
            .atomic()
            .hset(&key, "payer", payer)
            .ignore()
            .hset(&key, "quota", self.quota)
            .ignore()
            .expire(&key, self.ttl_secs as i64)
            .ignore()
            .query_async::<()>(&mut conn)
            .await?;

        Ok(self.codec.mint(payer, expires_at, &session_id))
    }

    async fn release_payment(&self, payment_id: &str) {
        let mut conn = self.conn.clone();
        let key = format!("{REDIS_REPLAY_PREFIX}{payment_id}");
        if let Err(e) = redis::cmd("DEL")
            .arg(&key)
            .query_async::<i64>(&mut conn)
            .await
        {
            // Not fatal: the claim simply expires on its own TTL, costing the
            // client a retry rather than any money.
            tracing::warn!(error = %e, "could not release an unsettled payment claim");
        }
    }

    async fn consume(&self, token: &str) -> SessionOutcome {
        let claims = match self.codec.verify(token, now_epoch_secs()) {
            Ok(claims) => claims,
            Err(rejection) => return SessionOutcome::Rejected(rejection),
        };

        let mut conn = self.conn.clone();
        let result: Result<(i64, String), _> = redis::Script::new(SPEND_SCRIPT)
            .key(Self::key(&claims.session_id))
            .invoke_async(&mut conn)
            .await;

        match result {
            Ok((-2, _)) => SessionOutcome::Rejected(SessionRejection::Unknown),
            Ok((-1, _)) => SessionOutcome::Rejected(SessionRejection::QuotaExhausted),
            Ok((remaining, payer)) => SessionOutcome::Accepted {
                payer,
                remaining: remaining.max(0) as u64,
            },
            Err(e) => {
                // Fail closed: an unreachable Redis must not grant paid access.
                tracing::error!(error = %e, "redis session lookup failed; denying paid tier");
                SessionOutcome::Rejected(SessionRejection::Backend)
            }
        }
    }
}

/// Session storage backend.
///
/// Enum dispatch rather than `dyn Trait`: there are exactly two backends, the
/// set is closed, and this keeps the async signatures free of boxing.
#[derive(Debug)]
pub enum SessionStore {
    Memory(MemorySessionStore),
    Redis(RedisSessionStore),
}

impl SessionStore {
    /// Mint a session for `payer`.
    pub async fn create_session(&self, payer: &str) -> Result<String, StoreError> {
        match self {
            SessionStore::Memory(s) => Ok(s.create_session(payer)),
            SessionStore::Redis(s) => s.create_session(payer).await,
        }
    }

    /// Authenticate a token and spend one request.
    pub async fn consume(&self, token: &str) -> SessionOutcome {
        match self {
            SessionStore::Memory(s) => s.consume(token),
            SessionStore::Redis(s) => s.consume(token).await,
        }
    }

    /// Claim a payment so it can only be spent once.
    ///
    /// Sui's own replay protection (object-version pinning) only binds once
    /// settlement lands on chain, which leaves two holes this closes: in stub
    /// mode nothing ever settles, so one signature would otherwise mint
    /// unlimited sessions; and even with real settlement, concurrent replays
    /// race to mint N sessions before the first transaction commits.
    ///
    /// `ttl_secs` therefore only needs to outlive settlement latency, not the
    /// life of the transaction — after it lapses the chain is the backstop.
    /// In stub mode there is no such backstop, which is one more reason not to
    /// run it anywhere real.
    pub async fn claim_payment(&self, payment_id: &str, ttl_secs: u64) -> PaymentClaim {
        match self {
            SessionStore::Memory(s) => s.claim_payment_at(payment_id, ttl_secs, now_epoch_secs()),
            SessionStore::Redis(s) => s.claim_payment(payment_id, ttl_secs).await,
        }
    }

    /// Release a claimed payment that was never settled.
    ///
    /// Called when the upstream fails: the authorization was verified but never
    /// spent, so holding the claim would burn a perfectly good payment and force
    /// the client to sign a fresh transaction to retry.
    pub async fn release_payment(&self, payment_id: &str) {
        match self {
            SessionStore::Memory(s) => s.release_payment(payment_id),
            SessionStore::Redis(s) => s.release_payment(payment_id).await,
        }
    }

    /// Reap expired sessions. Redis does this itself via key TTLs.
    pub async fn cleanup_expired(&self) -> usize {
        match self {
            SessionStore::Memory(s) => s.cleanup_expired(),
            SessionStore::Redis(_) => 0,
        }
    }

    /// Live session count. Redis is not scanned for this — reporting 0 is
    /// preferable to a `KEYS`/`SCAN` sweep on every cleanup tick.
    pub fn len(&self) -> usize {
        match self {
            SessionStore::Memory(s) => s.len(),
            SessionStore::Redis(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const PAYER: &str = "0xdeadbeef";
    const NOW: u64 = 1_700_000_000;

    fn store(ttl: u64, quota: u64) -> MemorySessionStore {
        MemorySessionStore::new(vec![7u8; 32], ttl, quota)
    }

    #[test]
    fn issued_token_is_accepted_and_spends_quota() {
        let s = store(3600, 3);
        let token = s.create_session_at(PAYER, NOW);

        match s.consume_at(&token, NOW + 1) {
            SessionOutcome::Accepted { payer, remaining } => {
                assert_eq!(payer, PAYER);
                assert_eq!(remaining, 2);
            }
            other => panic!("expected acceptance, got {other:?}"),
        }
    }

    #[test]
    fn quota_is_exhausted_after_the_configured_number_of_requests() {
        let s = store(3600, 2);
        let token = s.create_session_at(PAYER, NOW);

        assert!(matches!(
            s.consume_at(&token, NOW),
            SessionOutcome::Accepted { remaining: 1, .. }
        ));
        assert!(matches!(
            s.consume_at(&token, NOW),
            SessionOutcome::Accepted { remaining: 0, .. }
        ));
        assert_eq!(
            s.consume_at(&token, NOW),
            SessionOutcome::Rejected(SessionRejection::QuotaExhausted)
        );
    }

    #[test]
    fn tampering_with_any_field_invalidates_the_token() {
        let s = store(3600, 5);
        let token = s.create_session_at(PAYER, NOW);
        let parts: Vec<&str> = token.split(':').collect();

        // Extend the deadline.
        let forged = format!("{}:{}:{}:{}", parts[0], NOW + 999_999, parts[2], parts[3]);
        assert_eq!(
            s.consume_at(&forged, NOW),
            SessionOutcome::Rejected(SessionRejection::Malformed)
        );

        // Impersonate a different payer.
        let forged = format!("0xattacker:{}:{}:{}", parts[1], parts[2], parts[3]);
        assert_eq!(
            s.consume_at(&forged, NOW),
            SessionOutcome::Rejected(SessionRejection::Malformed)
        );

        // Point at a different session id.
        let forged = format!("{}:{}:{}:{}", parts[0], parts[1], "00".repeat(16), parts[3]);
        assert_eq!(
            s.consume_at(&forged, NOW),
            SessionOutcome::Rejected(SessionRejection::Malformed)
        );
    }

    #[test]
    fn token_signed_with_a_different_key_is_rejected() {
        let issuer = store(3600, 5);
        let token = issuer.create_session_at(PAYER, NOW);

        // Same session id exists here, but the key differs.
        let other = MemorySessionStore::new(vec![9u8; 32], 3600, 5);
        assert_eq!(
            other.consume_at(&token, NOW),
            SessionOutcome::Rejected(SessionRejection::Malformed)
        );
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let s = store(3600, 5);
        for bad in [
            "",
            "not-a-token",
            "a:b:c",                // too few fields
            "a:b:c:d:e",            // too many fields
            "0xa:123:abc:nothex..", // MAC is not hex
        ] {
            assert_eq!(
                s.consume_at(bad, NOW),
                SessionOutcome::Rejected(SessionRejection::Malformed),
                "should have rejected {bad:?}"
            );
        }
    }

    #[test]
    fn expired_token_is_rejected() {
        let s = store(60, 5);
        let token = s.create_session_at(PAYER, NOW);
        assert_eq!(
            s.consume_at(&token, NOW + 61),
            SessionOutcome::Rejected(SessionRejection::Expired)
        );
    }

    #[test]
    fn authentic_token_for_a_forgotten_session_is_unknown_not_accepted() {
        // Models a process restart: the MAC still verifies, but state is gone.
        let s = store(3600, 5);
        let token = s.create_session_at(PAYER, NOW);
        let session_id = token.split(':').nth(2).unwrap().to_string();
        s.sessions.remove(&session_id);

        assert_eq!(
            s.consume_at(&token, NOW),
            SessionOutcome::Rejected(SessionRejection::Unknown)
        );
    }

    #[test]
    fn cleanup_reaps_only_expired_sessions() {
        let s = store(60, 5);
        s.create_session_at("0xold", NOW);
        s.create_session_at("0xnew", NOW + 100);
        assert_eq!(s.len(), 2);

        let reaped = s.cleanup_expired_at(NOW + 61);
        assert_eq!(reaped, 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn concurrent_spending_never_exceeds_quota() {
        // The core reason quota uses compare-exchange rather than fetch_sub.
        const QUOTA: u64 = 500;
        const THREADS: usize = 8;

        let s = Arc::new(store(3600, QUOTA));
        let token = Arc::new(s.create_session_at(PAYER, NOW));

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let s = Arc::clone(&s);
                let token = Arc::clone(&token);
                std::thread::spawn(move || {
                    (0..200)
                        .filter(|_| {
                            matches!(s.consume_at(&token, NOW), SessionOutcome::Accepted { .. })
                        })
                        .count()
                })
            })
            .collect();

        let accepted: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            accepted, QUOTA as usize,
            "exactly the configured quota should ever be granted"
        );
    }

    // ---- Redis backend ----------------------------------------------------
    //
    // These need a live Redis. Point X402_TEST_REDIS_URL at one (the local
    // harness uses redis://127.0.0.1:6399). When unset the tests no-op so the
    // suite still passes on a machine without Redis.

    fn test_redis_url() -> Option<String> {
        std::env::var("X402_TEST_REDIS_URL").ok()
    }

    async fn redis_store(ttl: u64, quota: u64) -> Option<RedisSessionStore> {
        let url = test_redis_url()?;
        Some(
            RedisSessionStore::connect(&url, vec![7u8; 32], ttl, quota)
                .await
                .expect("connecting to the test redis"),
        )
    }

    #[tokio::test]
    async fn redis_issued_token_is_accepted_and_spends_quota() {
        let Some(s) = redis_store(3600, 3).await else {
            return;
        };
        let token = s.create_session(PAYER).await.unwrap();

        match s.consume(&token).await {
            SessionOutcome::Accepted { payer, remaining } => {
                assert_eq!(payer, PAYER);
                assert_eq!(remaining, 2);
            }
            other => panic!("expected acceptance, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redis_quota_is_exhausted_after_the_configured_number_of_requests() {
        let Some(s) = redis_store(3600, 2).await else {
            return;
        };
        let token = s.create_session(PAYER).await.unwrap();

        assert!(matches!(
            s.consume(&token).await,
            SessionOutcome::Accepted { remaining: 1, .. }
        ));
        assert!(matches!(
            s.consume(&token).await,
            SessionOutcome::Accepted { remaining: 0, .. }
        ));
        assert_eq!(
            s.consume(&token).await,
            SessionOutcome::Rejected(SessionRejection::QuotaExhausted)
        );
    }

    #[tokio::test]
    async fn redis_rejects_forged_and_foreign_tokens() {
        let Some(s) = redis_store(3600, 5).await else {
            return;
        };
        let token = s.create_session(PAYER).await.unwrap();
        let parts: Vec<&str> = token.split(':').collect();

        // Tampered payer.
        let forged = format!("0xattacker:{}:{}:{}", parts[1], parts[2], parts[3]);
        assert_eq!(
            s.consume(&forged).await,
            SessionOutcome::Rejected(SessionRejection::Malformed)
        );

        // Authentic shape, but signed with a different key.
        let Some(url) = test_redis_url() else { return };
        let other = RedisSessionStore::connect(&url, vec![9u8; 32], 3600, 5)
            .await
            .unwrap();
        assert_eq!(
            other.consume(&token).await,
            SessionOutcome::Rejected(SessionRejection::Malformed)
        );
    }

    #[tokio::test]
    async fn redis_reports_unknown_for_a_session_it_never_stored() {
        let Some(s) = redis_store(3600, 5).await else {
            return;
        };
        // Authentic token (right key) for a session id that was never written.
        let token = s
            .codec
            .mint(PAYER, now_epoch_secs() + 3600, &new_session_id());
        assert_eq!(
            s.consume(&token).await,
            SessionOutcome::Rejected(SessionRejection::Unknown)
        );
    }

    #[tokio::test]
    async fn redis_expires_sessions_via_key_ttl() {
        // 1s TTL: proves expiry is delegated to Redis, not a sweeper task.
        let Some(s) = redis_store(1, 5).await else {
            return;
        };
        let token = s.create_session(PAYER).await.unwrap();
        assert!(matches!(
            s.consume(&token).await,
            SessionOutcome::Accepted { .. }
        ));

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

        // The token's own deadline has also passed, so Expired is reported
        // before Redis is even consulted.
        assert_eq!(
            s.consume(&token).await,
            SessionOutcome::Rejected(SessionRejection::Expired)
        );
    }

    #[tokio::test]
    async fn redis_concurrent_spending_never_exceeds_quota() {
        // The reason the decrement is a Lua script: without atomicity,
        // concurrent spenders across replicas would each read the same
        // remaining count and all be admitted.
        const QUOTA: u64 = 200;
        let Some(s) = redis_store(3600, QUOTA).await else {
            return;
        };
        let token = Arc::new(s.create_session(PAYER).await.unwrap());
        let s = Arc::new(s);

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let s = Arc::clone(&s);
                let token = Arc::clone(&token);
                tokio::spawn(async move {
                    let mut accepted = 0usize;
                    for _ in 0..50 {
                        if matches!(s.consume(&token).await, SessionOutcome::Accepted { .. }) {
                            accepted += 1;
                        }
                    }
                    accepted
                })
            })
            .collect();

        let mut total = 0usize;
        for t in tasks {
            total += t.await.unwrap();
        }
        assert_eq!(
            total, QUOTA as usize,
            "exactly the configured quota should ever be granted"
        );
    }

    #[test]
    fn a_payment_can_only_be_claimed_once() {
        let s = store(3600, 5);
        assert_eq!(s.claim_payment_at("tx-a", 60, NOW), PaymentClaim::Fresh);
        assert_eq!(
            s.claim_payment_at("tx-a", 60, NOW),
            PaymentClaim::Replay { first_seen: NOW }
        );
        // Independent payments do not collide.
        assert_eq!(s.claim_payment_at("tx-b", 60, NOW), PaymentClaim::Fresh);
    }

    #[test]
    fn a_released_claim_can_be_used_again() {
        // An upstream failure must not burn a payment that was never spent.
        let s = store(3600, 5);
        assert_eq!(s.claim_payment_at("tx", 60, NOW), PaymentClaim::Fresh);
        assert_eq!(
            s.claim_payment_at("tx", 60, NOW),
            PaymentClaim::Replay { first_seen: NOW }
        );
        s.release_payment("tx");
        assert_eq!(
            s.claim_payment_at("tx", 60, NOW),
            PaymentClaim::Fresh,
            "a released payment is retryable"
        );
    }

    #[test]
    fn a_claim_lapses_once_its_ttl_passes() {
        // Documented consequence: after the TTL the chain is the only replay
        // backstop, and in stub mode there is none. The TTL must therefore
        // outlive settlement latency.
        let s = store(3600, 5);
        assert_eq!(s.claim_payment_at("tx", 60, NOW), PaymentClaim::Fresh);
        assert_eq!(
            s.claim_payment_at("tx", 60, NOW + 59),
            PaymentClaim::Replay { first_seen: NOW }
        );
        assert_eq!(s.claim_payment_at("tx", 60, NOW + 60), PaymentClaim::Fresh);
    }

    #[test]
    fn cleanup_bounds_the_replay_cache() {
        // Without this the map grows once per distinct payment forever.
        let s = store(60, 5);
        s.claim_payment_at("old", 60, NOW);
        s.claim_payment_at("new", 60, NOW + 100);
        assert_eq!(s.seen_payments.len(), 2);
        s.cleanup_expired_at(NOW + 100);
        assert_eq!(s.seen_payments.len(), 1);
    }

    #[tokio::test]
    async fn redis_payment_claim_is_atomic_across_concurrent_callers() {
        // The reason CLAIM_SCRIPT is Lua: a GET-then-SET from Rust lets two
        // replicas both observe "unused" and both mint a session.
        let Some(s) = redis_store(3600, 5).await else {
            return;
        };
        let s = Arc::new(s);
        let id = format!("concurrent-{}", now_epoch_secs());

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let s = Arc::clone(&s);
                let id = id.clone();
                tokio::spawn(async move { s.claim_payment(&id, 60).await })
            })
            .collect();

        let mut fresh = 0;
        for t in tasks {
            if matches!(t.await.unwrap(), PaymentClaim::Fresh) {
                fresh += 1;
            }
        }
        assert_eq!(fresh, 1, "exactly one caller may claim a given payment");
    }

    #[test]
    fn spend_one_refuses_to_underflow() {
        let counter = AtomicU64::new(1);
        assert_eq!(spend_one(&counter), Some(0));
        assert_eq!(spend_one(&counter), None);
        // Must not have wrapped to u64::MAX.
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }
}
