//! Facilitator HTTP interface (spec §7).
//!
//! `POST /verify`, `POST /settle`, `GET /supported` — the standard endpoints a
//! *resource server* calls to delegate blockchain work. Plus `GET /policies`,
//! which is not in the spec; see below. This runs on its own listener, separate
//! from the filter gRPC service, and shares the same [`Facilitator`] — and the
//! same replay claim, so a payment spent through the gateway cannot be spent
//! again through `/settle`.
//!
//! # Why this exists
//!
//! Without it, this project is only a gateway with verification welded inside:
//! no other x402 resource server could use it, which is precisely what the name
//! "verifier" promises. Exposing §7 makes the same logic reusable by anything
//! that speaks x402.
//!
//! `GET /policies` is a local addition. It reports the resolved policy table —
//! what each route costs, where it pays, and what it gives away — because the
//! only other way to learn a price is to spend a free-tier request getting
//! challenged. It exposes nothing a client could not obtain from one 402 per
//! route.
//!
//! # Exposure
//!
//! **These endpoints are unauthenticated and must not face the internet.**
//!
//! `POST /settle` broadcasts a signed transaction to the chain. In `sui-grpc`
//! mode that is not hypothetical and not deferred — it moves money on the call.
//! Anyone who can reach this port can make this service broadcast any payment
//! authorization they hold, which is not theft (they signed it, and the payee is
//! fixed by the transaction) but is a way to force settlement the resource
//! server never asked for, and to spend its fullnode quota.
//!
//! `GET /policies` also names every receiving wallet in one response, which is
//! public information but convenient reconnaissance.
//!
//! So: bind loopback or a private interface, or put auth in front. The listener
//! is disabled entirely unless `facilitator_api_listen_addr` is set, and the
//! shipped configs bind `127.0.0.1`. Under the deploy stack this port lives
//! inside a private container network namespace and is not published to the
//! host at all — see `deploy/docker-compose.yml`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};

use crate::config::Config;
use crate::session::{PaymentClaim, SessionStore};
use crate::x402::{
    self, Facilitator, FacilitatorRequest, SettlementResponse, SupportedResponse, VerifyResponse,
    X402_VERSION,
};

/// State shared by the §7 handlers.
#[derive(Clone)]
pub struct ApiState {
    pub facilitator: Arc<Facilitator>,
    /// Shared with the gateway path so a payment spent through one surface
    /// cannot be spent again through the other.
    pub sessions: Arc<SessionStore>,
    /// Read-only, for `/policies`.
    pub config: Arc<Config>,
}

/// Build the router. Kept separate from serving so tests can exercise it
/// without binding a port.
pub fn router(
    facilitator: Arc<Facilitator>,
    sessions: Arc<SessionStore>,
    config: Arc<Config>,
) -> Router {
    Router::new()
        .route("/verify", post(verify))
        .route("/settle", post(settle))
        .route("/supported", get(supported))
        .route("/policies", get(policies))
        .with_state(ApiState {
            facilitator,
            sessions,
            config,
        })
}

/// One row of the effective policy table.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyView {
    pub name: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub network: String,
    pub description: String,
    pub free_requests: u64,
    pub free_window_secs: u64,
    pub session_quota: u64,
    pub session_duration_secs: u64,
}

/// The resolved policy table: what each named policy costs, where it pays, and
/// what it gives away.
///
/// Not part of the x402 spec — operator and client introspection. It exposes
/// nothing a client cannot already learn by triggering one 402 per route, but
/// **without spending a free-tier request to find out**, which matters for any
/// client that wants to render prices before it starts consuming its allowance.
async fn policies(State(state): State<ApiState>) -> Json<Vec<PolicyView>> {
    let mut rows: Vec<PolicyView> = state
        .config
        .policies
        .keys()
        .map(|name| {
            let resolved = state.config.policy_for("", Some(name));
            PolicyView {
                name: name.clone(),
                amount: resolved.payment.amount.clone(),
                asset: resolved.payment.asset.clone(),
                pay_to: resolved.payment.pay_to.clone(),
                network: resolved.payment.network.clone(),
                description: resolved.payment.description.clone(),
                free_requests: resolved.free_tier.max_requests,
                free_window_secs: resolved.free_tier.window_secs,
                session_quota: resolved.paid_tier.quota,
                session_duration_secs: resolved.paid_tier.duration_secs,
            }
        })
        .collect();
    // Stable order: a HashMap would otherwise reshuffle the table every call.
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Json(rows)
}

/// A request whose envelope is wrong before any payment logic runs.
struct BadRequest(&'static str, String);

impl IntoResponse for BadRequest {
    fn into_response(self) -> Response {
        // §7 has no envelope-level error schema, so mirror the VerifyResponse
        // shape: a client parsing `invalidReason` gets a usable answer either
        // way, rather than an untyped error string.
        (
            StatusCode::BAD_REQUEST,
            Json(VerifyResponse {
                is_valid: false,
                invalid_reason: Some(self.0.to_string()),
                payer: None,
            }),
        )
            .chain_detail(self.1)
    }
}

/// Attach a human-readable detail without disturbing the typed body.
trait ChainDetail {
    fn chain_detail(self, detail: String) -> Response;
}

impl<T: IntoResponse> ChainDetail for T {
    fn chain_detail(self, detail: String) -> Response {
        let mut response = self.into_response();
        if let Ok(value) = detail.parse::<axum::http::HeaderValue>() {
            response.headers_mut().insert("x-x402-detail", value);
        }
        response
    }
}

/// Reject a request whose `x402Version` is not the one we speak.
fn check_version(request: &FacilitatorRequest) -> Result<(), BadRequest> {
    if request.x402_version != X402_VERSION {
        return Err(BadRequest(
            "invalid_x402_version",
            format!(
                "request declares x402Version {}, this facilitator speaks {X402_VERSION}",
                request.x402_version
            ),
        ));
    }
    Ok(())
}

/// `POST /verify` — validate an authorization without executing it (§7.1).
///
/// Always returns 200: a *well-formed request about an invalid payment* is a
/// successful verification that answered "no". Only a malformed envelope is a
/// 4xx.
async fn verify(
    State(state): State<ApiState>,
    Json(request): Json<FacilitatorRequest>,
) -> Result<Json<VerifyResponse>, BadRequest> {
    check_version(&request)?;

    // Deliberately does NOT claim the payment: verification is non-mutating,
    // and burning the authorization here would make the spec's
    // verify-then-settle sequence impossible.
    match state
        .facilitator
        .verify(&request.payment_payload, &request.payment_requirements)
        .await
    {
        Ok(payer) => Ok(Json(VerifyResponse {
            is_valid: true,
            invalid_reason: None,
            payer: Some(payer),
        })),
        Err(e) => {
            tracing::debug!(error = %e, "verify rejected a payment");
            Ok(Json(VerifyResponse {
                is_valid: false,
                invalid_reason: Some(e.code().to_string()),
                // Unknown: the payer is recovered *during* verification, which
                // is exactly what did not complete.
                payer: None,
            }))
        }
    }
}

/// `POST /settle` — execute a verified payment (§7.2).
async fn settle(
    State(state): State<ApiState>,
    Json(request): Json<FacilitatorRequest>,
) -> Result<Json<SettlementResponse>, BadRequest> {
    check_version(&request)?;

    // Claim before broadcasting. Without this a caller could POST the same
    // payload repeatedly: the chain would reject the duplicate on its own, but
    // only after the race, and with an error that says nothing about replay.
    // The claim is shared with the gateway path, so a payment spent through
    // one surface cannot be spent again through the other.
    if let Some(id) = x402::payment_id(&request.payment_payload) {
        let ttl = crate::auth::replay_ttl(request.payment_requirements.max_timeout_seconds);
        match state.sessions.claim_payment(&id, ttl).await {
            PaymentClaim::Fresh => {}
            PaymentClaim::Replay { first_seen } => {
                let error = x402::FacilitatorError::Replay { first_seen };
                tracing::warn!(error = %error, "settle refused a replayed payment");
                return Ok(Json(state.facilitator.failure_receipt(error.code())));
            }
            PaymentClaim::Backend => {
                let error = x402::FacilitatorError::ReplayCacheUnavailable;
                tracing::error!(error = %error, "settle refused: replay cache unavailable");
                return Ok(Json(state.facilitator.failure_receipt(error.code())));
            }
        }
    }

    match state
        .facilitator
        .settle(&request.payment_payload, &request.payment_requirements)
        .await
    {
        Ok(receipt) => Ok(Json(receipt)),
        Err(e) => {
            tracing::debug!(error = %e, "settle rejected a payment");
            // The authorization was never spent, so release it: the caller can
            // retry rather than being forced to sign a fresh transaction.
            if let Some(id) = x402::payment_id(&request.payment_payload) {
                state.sessions.release_payment(&id).await;
            }
            // Per §7.2's error example this is still a SettlementResponse, with
            // success:false and an empty transaction — not an HTTP error.
            Ok(Json(state.facilitator.failure_receipt(e.code())))
        }
    }
}

/// `GET /supported` — schemes, networks and extensions on offer (§7.3).
async fn supported(State(state): State<ApiState>) -> Json<SupportedResponse> {
    Json(state.facilitator.supported())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VerificationMode;
    use crate::x402::{PaymentPayload, PaymentRequirements};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for `oneshot`

    fn sessions() -> Arc<SessionStore> {
        use crate::session::MemorySessionStore;
        Arc::new(SessionStore::Memory(MemorySessionStore::new(
            vec![7u8; 32],
            3600,
        )))
    }

    /// A config with two policies that differ in every dimension, so
    /// `/policies` cannot pass by echoing one row twice.
    fn test_config() -> Arc<Config> {
        use crate::config::{FreeTierConfig, PaidTierConfig, PaymentOverride};
        let mut policies = std::collections::HashMap::new();
        policies.insert(
            "cheap".to_string(),
            PaymentOverride {
                amount: Some("10".into()),
                free_tier: Some(FreeTierConfig {
                    max_requests: 5,
                    window_secs: 60,
                }),
                ..Default::default()
            },
        );
        policies.insert(
            "pricey".to_string(),
            PaymentOverride {
                amount: Some("5000".into()),
                pay_to: Some(format!("0x{}", "2".repeat(64))),
                paid_tier: Some(PaidTierConfig {
                    quota: 50,
                    duration_secs: 900,
                }),
                ..Default::default()
            },
        );
        let mut config = crate::auth::test_support::app_state_with_policies(9, 77, policies)
            .config
            .clone();
        config.payment.pay_to = format!("0x{}", "1".repeat(64));
        Arc::new(config)
    }

    fn facilitator() -> Arc<Facilitator> {
        Arc::new(
            Facilitator::new(
                VerificationMode::StubAcceptAll,
                "https://fullnode.testnet.sui.io:443".into(),
                "sui:testnet".into(),
            )
            .expect("stub mode never connects"),
        )
    }

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            amount: "1000".into(),
            asset: "0xa1::usdc::USDC".into(),
            pay_to: "0xabc".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    fn payload() -> PaymentPayload {
        PaymentPayload {
            x402_version: X402_VERSION,
            resource: None,
            accepted: requirements(),
            payload: serde_json::json!({ "signature": "c2ln", "transaction": "dHg=" }),
            extensions: None,
        }
    }

    fn request_body(payload: PaymentPayload, requirements: PaymentRequirements) -> String {
        serde_json::to_string(&FacilitatorRequest {
            x402_version: X402_VERSION,
            payment_payload: payload,
            payment_requirements: requirements,
        })
        .unwrap()
    }

    /// POST against a router whose state persists across calls, so replay
    /// behaviour is observable.
    async fn post_twice(path: &str, body: String) -> Vec<serde_json::Value> {
        let app = router(facilitator(), sessions(), test_config());
        let mut out = Vec::new();
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from(body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            out.push(serde_json::from_slice(&bytes).unwrap());
        }
        out
    }

    async fn post(path: &str, body: String) -> (StatusCode, serde_json::Value) {
        let response = router(facilitator(), sessions(), test_config())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn verify_accepts_a_conformant_payment() {
        let (status, body) = post("/verify", request_body(payload(), requirements())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["isValid"], serde_json::json!(true));
        assert!(body["payer"].is_string());
        assert!(body.get("invalidReason").is_none());
    }

    #[tokio::test]
    async fn verify_reports_invalid_with_a_spec_code_but_still_returns_200() {
        // A well-formed question about a bad payment is a successful
        // verification that answered "no" — not an HTTP error.
        let mut p = payload();
        p.accepted.amount = "1".into();
        let (status, body) = post("/verify", request_body(p, requirements())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["isValid"], serde_json::json!(false));
        assert_eq!(
            body["invalidReason"],
            serde_json::json!("invalid_payment_requirements")
        );
    }

    #[tokio::test]
    async fn settle_returns_a_receipt_on_success() {
        let (status, body) = post("/settle", request_body(payload(), requirements())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], serde_json::json!(true));
        assert_eq!(body["network"], serde_json::json!("sui:testnet"));
        // Stub receipts must never look like a real digest.
        assert_eq!(
            body["transaction"],
            serde_json::json!("stub-not-settled-on-chain")
        );
    }

    #[tokio::test]
    async fn settle_failure_is_a_receipt_not_an_http_error() {
        // §7.2's error example: success:false, an errorReason, empty transaction.
        let mut p = payload();
        p.accepted.pay_to = "0xattacker".into();
        let (status, body) = post("/settle", request_body(p, requirements())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["success"], serde_json::json!(false));
        assert_eq!(
            body["errorReason"],
            serde_json::json!("invalid_payment_requirements")
        );
        assert_eq!(body["transaction"], serde_json::json!(""));
    }

    #[tokio::test]
    async fn a_mismatched_envelope_version_is_a_400() {
        let mut body: serde_json::Value =
            serde_json::from_str(&request_body(payload(), requirements())).unwrap();
        body["x402Version"] = serde_json::json!(1);
        let (status, body) = post("/verify", body.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["invalidReason"],
            serde_json::json!("invalid_x402_version")
        );
    }

    #[tokio::test]
    async fn settle_refuses_to_spend_the_same_payment_twice() {
        // /settle bypassed the replay cache entirely: a caller could POST the
        // same payload repeatedly. The chain rejects the duplicate on its own,
        // but only after the race and with an error that says nothing about
        // replay.
        let results = post_twice("/settle", request_body(payload(), requirements())).await;
        assert_eq!(results[0]["success"], serde_json::json!(true));
        assert_eq!(results[1]["success"], serde_json::json!(false));
        assert_eq!(
            results[1]["errorReason"],
            serde_json::json!("invalid_transaction_state")
        );
    }

    #[tokio::test]
    async fn verify_does_not_burn_the_authorization() {
        // Verification is non-mutating; claiming here would make the spec's
        // verify-then-settle sequence impossible.
        let results = post_twice("/verify", request_body(payload(), requirements())).await;
        assert_eq!(results[0]["isValid"], serde_json::json!(true));
        assert_eq!(
            results[1]["isValid"],
            serde_json::json!(true),
            "verifying twice must stay valid"
        );
    }

    #[tokio::test]
    async fn policies_reports_the_resolved_table_not_the_raw_overrides() {
        let response = router(facilitator(), sessions(), test_config())
            .oneshot(
                Request::builder()
                    .uri("/policies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Sorted, so a HashMap cannot reshuffle the table between calls.
        assert_eq!(rows[0]["name"], "cheap");
        assert_eq!(rows[1]["name"], "pricey");

        // Every field is the *resolved* value: `cheap` sets no pay_to and no
        // paid_tier, so it must show the inherited ones rather than nulls.
        assert_eq!(rows[0]["amount"], "10");
        assert_eq!(rows[0]["payTo"], format!("0x{}", "1".repeat(64)));
        assert_eq!(rows[0]["freeRequests"], 5);
        assert_eq!(rows[0]["sessionQuota"], 77);

        // And `pricey` overrides exactly what it declared, inheriting the rest.
        assert_eq!(rows[1]["amount"], "5000");
        assert_eq!(rows[1]["payTo"], format!("0x{}", "2".repeat(64)));
        assert_eq!(rows[1]["freeRequests"], 9);
        assert_eq!(rows[1]["sessionQuota"], 50);
        assert_eq!(rows[1]["sessionDurationSecs"], 900);
    }

    #[tokio::test]
    async fn policies_costs_no_free_tier_request_to_read() {
        // The whole reason this endpoint exists: a client can render prices
        // without spending the allowance it is about to display.
        let sessions = sessions();
        let app = router(facilitator(), Arc::clone(&sessions), test_config());
        for _ in 0..50 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/policies")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        // Nothing was minted, spent or claimed by reading the table.
        assert_eq!(sessions.len(), 0);
    }

    #[tokio::test]
    async fn supported_lists_scheme_network_and_extensions() {
        let response = router(facilitator(), sessions(), test_config())
            .oneshot(
                Request::builder()
                    .uri("/supported")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(body["kinds"][0]["scheme"], serde_json::json!("exact"));
        assert_eq!(
            body["kinds"][0]["network"],
            serde_json::json!("sui:testnet")
        );
        assert_eq!(body["kinds"][0]["x402Version"], serde_json::json!(2));
        assert_eq!(
            body["extensions"][0],
            serde_json::json!("sui-x402-verifier.session.v1")
        );
        // No signing keys: this facilitator has custody of nothing, and says so
        // in a way a client can check.
        assert_eq!(body["signers"], serde_json::json!({}));
    }

    #[tokio::test]
    async fn sui_grpc_mode_reports_invalid_rather_than_verifying() {
        let facilitator = Arc::new(
            Facilitator::new(
                VerificationMode::SuiGrpc,
                "https://fullnode.testnet.sui.io:443".into(),
                "sui:testnet".into(),
            )
            .expect("connecting is lazy; the channel is not dialed until first use"),
        );
        let response = router(facilitator, sessions(), test_config())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body(payload(), requirements())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["isValid"], serde_json::json!(false));
    }
}
