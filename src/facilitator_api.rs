//! Facilitator HTTP interface (spec §7).
//!
//! `POST /verify`, `POST /settle`, `GET /supported` — the standard endpoints a
//! *resource server* calls to delegate blockchain work. This runs on its own
//! listener, separate from the ext_authz gRPC service, and shares the same
//! [`Facilitator`].
//!
//! # Why this exists
//!
//! Without it, this project is only a gateway with verification welded inside:
//! no other x402 resource server could use it, which is precisely what the name
//! "verifier" promises. Exposing §7 makes the same logic reusable by anything
//! that speaks x402.
//!
//! # Exposure
//!
//! These endpoints are unauthenticated and must not face the internet. `/settle`
//! is the one that moves money once real settlement lands, so it belongs on a
//! private interface (the default binds loopback) or behind its own auth.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};

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
}

/// Build the router. Kept separate from serving so tests can exercise it
/// without binding a port.
pub fn router(facilitator: Arc<Facilitator>, sessions: Arc<SessionStore>) -> Router {
    Router::new()
        .route("/verify", post(verify))
        .route("/settle", post(settle))
        .route("/supported", get(supported))
        .with_state(ApiState {
            facilitator,
            sessions,
        })
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
            100,
        )))
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
        let app = router(facilitator(), sessions());
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
        let response = router(facilitator(), sessions())
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
    async fn supported_lists_scheme_network_and_extensions() {
        let response = router(facilitator(), sessions())
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
        let response = router(facilitator, sessions())
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
