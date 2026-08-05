//! Circuit breaker for settlement.
//!
//! # The failure this exists for
//!
//! `ext_proc` settles on the response path, so a settlement that fails happens
//! *after* the resource was already served. One of those costs a single request
//! and is noise.
//!
//! The problem is correlated failure. If the fullnode is unreachable, **every**
//! settlement fails, and the gateway degrades into a free public proxy — serving
//! paid traffic and charging for none of it, precisely when that is least
//! affordable. Nothing about the per-request path notices that the failures are
//! systemic rather than incidental, because each request only sees its own
//! outcome.
//!
//! So this watches the outcomes across requests. Past a failure rate, it stops
//! accepting payments on that policy: the free tier keeps working, and paying
//! clients are told to come back rather than being served for free.
//!
//! # Why per policy
//!
//! Policies can settle against different chains or configurations, and one route
//! being broken says nothing about another. Tripping them all together would
//! turn a narrow outage into a wide one.

use dashmap::DashMap;
use std::collections::VecDeque;

use crate::util::now_epoch_secs;

/// Outcomes remembered per policy. Small on purpose: the breaker should react
/// within seconds of an outage, not average it away over an hour.
const WINDOW: usize = 20;

/// Minimum outcomes before the breaker may trip. Without this, one failure at
/// startup is a 100% failure rate and the gateway refuses payments it could
/// have taken.
const MIN_SAMPLES: usize = 5;

/// Failure fraction at which the breaker opens.
const FAILURE_THRESHOLD: f64 = 0.5;

/// How long the breaker stays open before letting one request through to test
/// whether settlement has recovered.
const COOLDOWN_SECS: u64 = 30;

/// What the breaker will allow right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Settlement is healthy. Accept payments.
    Closed,
    /// Too many recent settlements failed. Refuse payments; the free tier is
    /// unaffected.
    Open,
    /// Cooldown elapsed. Let exactly one payment through to find out whether
    /// settlement works again.
    HalfOpen,
}

impl BreakerState {
    /// Whether a payment should be accepted in this state.
    pub fn accepts_payment(self) -> bool {
        matches!(self, BreakerState::Closed | BreakerState::HalfOpen)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }
}

#[derive(Debug, Default)]
struct Window {
    /// `true` for a failure. Bounded to [`WINDOW`].
    outcomes: VecDeque<bool>,
    /// When the breaker opened, if it is open.
    opened_at: Option<u64>,
    /// Set while a half-open probe is in flight, so a burst of concurrent
    /// requests does not all get through as "the one probe".
    probing: bool,
}

/// Per-policy settlement health.
#[derive(Debug, Default)]
pub struct SettlementBreaker {
    policies: DashMap<String, Window>,
}

impl SettlementBreaker {
    pub fn new() -> Self {
        Self::default()
    }

    /// What this policy will allow right now.
    ///
    /// Calling this *claims* a half-open probe if one is available, so a caller
    /// that receives `HalfOpen` is the single request permitted through and must
    /// report its outcome.
    pub fn state(&self, policy: &str) -> BreakerState {
        self.state_at(policy, now_epoch_secs())
    }

    fn state_at(&self, policy: &str, now: u64) -> BreakerState {
        let mut window = self.policies.entry(policy.to_string()).or_default();
        let Some(opened_at) = window.opened_at else {
            return BreakerState::Closed;
        };

        if now.saturating_sub(opened_at) < COOLDOWN_SECS {
            return BreakerState::Open;
        }
        if window.probing {
            // Another request is already testing the water.
            return BreakerState::Open;
        }
        window.probing = true;
        BreakerState::HalfOpen
    }

    /// Record a settlement outcome.
    pub fn record(&self, policy: &str, failed: bool) {
        self.record_at(policy, failed, now_epoch_secs());
    }

    fn record_at(&self, policy: &str, failed: bool, now: u64) {
        let mut window = self.policies.entry(policy.to_string()).or_default();
        window.probing = false;

        if !failed {
            // A success closes the breaker outright rather than waiting for the
            // rate to decay. Recovery should be immediate; the whole point is to
            // stop refusing money the moment settlement works again.
            window.outcomes.clear();
            window.opened_at = None;
            return;
        }

        window.outcomes.push_back(true);
        while window.outcomes.len() > WINDOW {
            window.outcomes.pop_front();
        }

        if window.opened_at.is_some() {
            // A failed probe re-opens it for another cooldown.
            window.opened_at = Some(now);
            return;
        }

        let total = window.outcomes.len();
        let failures = window.outcomes.iter().filter(|f| **f).count();
        if total >= MIN_SAMPLES && failures as f64 / total as f64 >= FAILURE_THRESHOLD {
            window.opened_at = Some(now);
            tracing::error!(
                policy = %policy,
                failures,
                total,
                "SETTLEMENT CIRCUIT BREAKER OPEN: refusing payments on this policy. \
                 The free tier is unaffected. Serving paid traffic while settlement \
                 fails would give the resource away."
            );
        }
    }

    /// Record a success. Convenience for readability at call sites.
    pub fn record_success(&self, policy: &str) {
        self.record(policy, false);
    }

    /// Record a failure. Convenience for readability at call sites.
    pub fn record_failure(&self, policy: &str) {
        self.record(policy, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;
    const P: &str = "graphql";

    #[test]
    fn healthy_settlement_stays_closed() {
        let b = SettlementBreaker::new();
        for _ in 0..50 {
            b.record_at(P, false, NOW);
        }
        assert_eq!(b.state_at(P, NOW), BreakerState::Closed);
    }

    #[test]
    fn a_single_failure_does_not_trip_it() {
        // One failed settlement costs one request. Refusing every payment over
        // it would be a worse outage than the thing it is guarding against.
        let b = SettlementBreaker::new();
        b.record_at(P, true, NOW);
        assert_eq!(b.state_at(P, NOW), BreakerState::Closed);
    }

    #[test]
    fn sustained_failure_opens_it() {
        let b = SettlementBreaker::new();
        for _ in 0..MIN_SAMPLES {
            b.record_at(P, true, NOW);
        }
        assert_eq!(b.state_at(P, NOW), BreakerState::Open);
        assert!(!b.state_at(P, NOW).accepts_payment());
    }

    #[test]
    fn one_policy_tripping_does_not_affect_another() {
        // Policies can settle against different chains. A broken route says
        // nothing about an unrelated one, and tripping both would widen the
        // outage rather than contain it.
        let b = SettlementBreaker::new();
        for _ in 0..MIN_SAMPLES {
            b.record_at("grpc", true, NOW);
        }
        assert_eq!(b.state_at("grpc", NOW), BreakerState::Open);
        assert_eq!(b.state_at("graphql", NOW), BreakerState::Closed);
    }

    #[test]
    fn it_probes_once_after_the_cooldown() {
        let b = SettlementBreaker::new();
        for _ in 0..MIN_SAMPLES {
            b.record_at(P, true, NOW);
        }
        assert_eq!(b.state_at(P, NOW + COOLDOWN_SECS - 1), BreakerState::Open);

        // First caller past the cooldown gets the probe...
        assert_eq!(b.state_at(P, NOW + COOLDOWN_SECS), BreakerState::HalfOpen);
        // ...and concurrent callers do not, or a burst would all be let through
        // and all fail.
        assert_eq!(b.state_at(P, NOW + COOLDOWN_SECS), BreakerState::Open);
    }

    #[test]
    fn a_successful_probe_closes_it_immediately() {
        // Recovery must not wait for the failure rate to decay — that would keep
        // refusing money after settlement already works.
        let b = SettlementBreaker::new();
        for _ in 0..MIN_SAMPLES {
            b.record_at(P, true, NOW);
        }
        assert_eq!(b.state_at(P, NOW + COOLDOWN_SECS), BreakerState::HalfOpen);
        b.record_at(P, false, NOW + COOLDOWN_SECS);
        assert_eq!(b.state_at(P, NOW + COOLDOWN_SECS), BreakerState::Closed);
    }

    #[test]
    fn a_failed_probe_reopens_for_another_cooldown() {
        let b = SettlementBreaker::new();
        for _ in 0..MIN_SAMPLES {
            b.record_at(P, true, NOW);
        }
        let t = NOW + COOLDOWN_SECS;
        assert_eq!(b.state_at(P, t), BreakerState::HalfOpen);
        b.record_at(P, true, t);

        assert_eq!(b.state_at(P, t + 1), BreakerState::Open);
        // The cooldown restarts from the failed probe, not from the original trip.
        assert_eq!(b.state_at(P, t + COOLDOWN_SECS), BreakerState::HalfOpen);
    }

    #[test]
    fn intermittent_failure_below_the_threshold_stays_closed() {
        // A fullnode dropping one call in three is degraded, not down. Refusing
        // all payments there loses more than it saves.
        let b = SettlementBreaker::new();
        for i in 0..30 {
            b.record_at(P, i % 3 == 0, NOW);
        }
        assert_eq!(b.state_at(P, NOW), BreakerState::Closed);
    }

    #[test]
    fn the_window_is_bounded() {
        let b = SettlementBreaker::new();
        for _ in 0..1000 {
            b.record_at(P, true, NOW);
        }
        let window = b.policies.get(P).expect("policy recorded");
        assert_eq!(window.outcomes.len(), WINDOW);
    }
}
