//! Prometheus instrumentation.
//!
//! Every metric here answers a question an operator will actually ask. Two of
//! them are alerts rather than dashboards, and they are called out in
//! [`describe`] and in the README:
//!
//! - [`SETTLEMENT_AFTER_SERVE_FAILURES`] — a resource was delivered and then
//!   could not be charged for. Revenue is being lost right now.
//! - [`STORE_ERRORS`] — the session/replay store is unreachable, so requests are
//!   failing closed. Paying customers are being turned away.
//!
//! Cardinality is kept deliberately low: labels are closed sets (tier, outcome,
//! spec error code, policy name), never payer addresses, IPs, session ids or
//! transaction digests. Those belong in logs, which are sampled and expire;
//! putting them in a time series would make the label space unbounded.

use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;

/// Every authorization decision, by tier and outcome.
pub const REQUESTS: &str = "x402_requests_total";
/// Payment attempts, by outcome and standard §9 error code.
pub const PAYMENTS: &str = "x402_payments_total";
/// End-to-end verification latency, including fullnode RPC.
pub const VERIFICATION_SECONDS: &str = "x402_verification_seconds";
/// On-chain settlement latency.
pub const SETTLEMENT_SECONDS: &str = "x402_settlement_seconds";
/// Session lifecycle events.
pub const SESSIONS: &str = "x402_sessions_total";
/// Why presented session tokens were refused.
pub const SESSION_REJECTIONS: &str = "x402_session_rejections_total";
/// Replay-cache claim outcomes.
pub const REPLAY_CLAIMS: &str = "x402_replay_claims_total";
/// Free-tier decisions.
pub const RATE_LIMIT: &str = "x402_rate_limit_total";
/// **Alert.** Upstream served the request, then settlement failed.
pub const SETTLEMENT_AFTER_SERVE_FAILURES: &str = "x402_settlement_after_serve_failures_total";
/// **Alert.** The state store could not be reached.
pub const STORE_ERRORS: &str = "x402_store_errors_total";

/// Install the Prometheus exporter on `addr`, serving `/metrics`.
///
/// Returns an error rather than panicking so a busy port degrades to "no
/// metrics" instead of taking the gateway down with it — telemetry must never
/// be the reason payments stop working.
pub fn install(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        // Latency buckets chosen for what these operations actually cost: a
        // fullnode round trip is tens to hundreds of milliseconds, and Sui
        // finality is sub-second, so the interesting range is 10ms-5s. The
        // default buckets are too coarse at the bottom to see a regression.
        .set_buckets_for_metric(
            metrics_exporter_prometheus::Matcher::Suffix("_seconds".to_string()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ],
        )?
        .install()?;

    describe();
    Ok(())
}

/// Register descriptions, so `/metrics` is self-documenting.
fn describe() {
    use metrics::describe_counter;
    use metrics::describe_histogram;

    describe_counter!(
        REQUESTS,
        "Authorization decisions, by tier, decision and policy."
    );
    describe_counter!(
        PAYMENTS,
        "Payment attempts, by outcome, standard x402 error code and verification mode."
    );
    describe_histogram!(
        VERIFICATION_SECONDS,
        metrics::Unit::Seconds,
        "Time to verify a payment, including any fullnode RPC."
    );
    describe_histogram!(
        SETTLEMENT_SECONDS,
        metrics::Unit::Seconds,
        "Time to settle a payment on chain."
    );
    describe_counter!(SESSIONS, "Session lifecycle events (created, accepted).");
    describe_counter!(
        SESSION_REJECTIONS,
        "Presented session tokens that were refused, by reason."
    );
    describe_counter!(
        REPLAY_CLAIMS,
        "Replay-cache claims, by outcome (fresh, replay, backend error)."
    );
    describe_counter!(RATE_LIMIT, "Free-tier decisions, by outcome.");
    describe_counter!(
        SETTLEMENT_AFTER_SERVE_FAILURES,
        "ALERT: the upstream served the request but settlement then failed. \
         The resource was delivered unpaid."
    );
    describe_counter!(
        STORE_ERRORS,
        "ALERT: the session/replay store was unreachable. Requests are failing \
         closed, so paying clients are being turned away."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names_follow_prometheus_conventions() {
        // Counters end in _total, histograms carry a base unit. Getting this
        // wrong is invisible until someone writes a query that returns nothing.
        for counter in [
            REQUESTS,
            PAYMENTS,
            SESSIONS,
            SESSION_REJECTIONS,
            REPLAY_CLAIMS,
            RATE_LIMIT,
            SETTLEMENT_AFTER_SERVE_FAILURES,
            STORE_ERRORS,
        ] {
            assert!(
                counter.ends_with("_total"),
                "{counter} should end in _total"
            );
            assert!(
                counter.starts_with("x402_"),
                "{counter} should be namespaced"
            );
        }
        for histogram in [VERIFICATION_SECONDS, SETTLEMENT_SECONDS] {
            assert!(
                histogram.ends_with("_seconds"),
                "{histogram} should carry its unit"
            );
        }
    }
}
