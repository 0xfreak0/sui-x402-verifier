//! Envoy `ext_authz` service implementation.
//!
//! # Decision flow
//!
//! 1. A valid `x-payment-session` token → paid tier, spend one request.
//! 2. Otherwise a `payment-signature` header → verify + settle, mint a session.
//! 3. Otherwise the anonymous free tier, rate limited per source IP.
//!
//! A *failed* payment attempt is denied outright rather than quietly demoted to
//! the free tier, so clients get an actionable error instead of a confusing
//! rate limit later. A merely exhausted or unknown session token does fall
//! through, since that is the normal end-of-session path.

use std::net::IpAddr;
use std::sync::Arc;

use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse, HeaderAppendAction, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckRequestExt, CheckResponseExt, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};
use tonic::{Request, Response, Status};

use crate::config::{Config, POLICY_CONTEXT_KEY};
use crate::ratelimit::RateLimiter;
use crate::session::{SessionOutcome, SessionStore};
use crate::x402::{
    self, Facilitator, HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SESSION,
    HEADER_PAYMENT_SIGNATURE, PaymentPayload, PaymentRequired, PaymentRequirements,
    SettlementResponse,
};

/// Request header carrying the resolved tier to downstream filters/backends.
///
/// Set with `OverwriteIfExistsOrAdd` — see [`AUTHORITATIVE_APPEND`].
pub const HEADER_TIER: &str = "x-x402-tier";
/// Request header carrying the resolved payer identity.
pub const HEADER_PAYER: &str = "x-x402-payer";

/// Header append action for every header this service asserts about identity.
///
/// **Security critical.** These headers are what Envoy's ratelimit filter keys
/// its descriptors on. Appending would let a client send its own
/// `x-x402-tier: paid` and have ours merely added alongside it, self-promoting
/// into the paid bucket. Overwriting makes the verifier the sole authority.
const AUTHORITATIVE_APPEND: HeaderAppendAction = HeaderAppendAction::OverwriteIfExistsOrAdd;

/// Which tier a request resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Free,
    Paid,
}

impl Tier {
    /// Descriptor value used by Envoy ratelimit actions.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Free => "free",
            Tier::Paid => "paid",
        }
    }
}

/// The authorization outcome, independent of Envoy's protobuf types.
///
/// Kept separate from [`CheckResponse`] construction so the policy logic can be
/// tested without building protobufs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow {
        tier: Tier,
        payer: Option<String>,
        /// Present only when a payment minted a *new* session this request.
        session_token: Option<String>,
        /// Present only when a payment settled this request.
        settlement: Option<SettlementResponse>,
    },
    Deny {
        challenge: PaymentRequired,
    },
}

/// Shared service state.
#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub sessions: SessionStore,
    pub limiter: RateLimiter,
    pub facilitator: Facilitator,
}

/// ext_authz service.
#[derive(Debug, Clone)]
pub struct X402Auth {
    state: Arc<AppState>,
}

impl X402Auth {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// Apply the tier policy to one request.
    ///
    /// `policy` is the name Envoy attached to the matched route via
    /// `context_extensions`. When present it selects the payment terms
    /// directly, so the verifier never re-derives which route this is.
    pub async fn decide(
        &self,
        headers: &HeaderView<'_>,
        client_ip: Option<IpAddr>,
        path: &str,
        policy: Option<&str>,
    ) -> Decision {
        // A policy name Envoy sent but this config does not define almost
        // always means the two configs have drifted. Serve the defaults, but
        // make the drift loud.
        if let Some(name) = policy
            && self.state.config.is_unknown_policy(name)
        {
            tracing::warn!(
                policy = %name,
                "Envoy referenced an x402 policy this config does not define; \
                 falling back to default payment terms"
            );
        }

        // Terms are resolved per request so different routes can advertise
        // different prices and receiving wallets.
        let requirements =
            PaymentRequirements::from_config(&self.state.config.payment_for(path, policy), path);

        // ---- 1. Existing paid session -------------------------------------
        if let Some(token) = headers.get(HEADER_PAYMENT_SESSION) {
            match self.state.sessions.consume(token).await {
                SessionOutcome::Accepted { payer, remaining } => {
                    tracing::debug!(%payer, remaining, "paid request served from session");
                    return Decision::Allow {
                        tier: Tier::Paid,
                        payer: Some(payer),
                        session_token: None,
                        settlement: None,
                    };
                }
                SessionOutcome::Rejected(reason) => {
                    // Not fatal: fall through so the client can pay again.
                    tracing::debug!(?reason, "session token not honored");
                }
            }
        }

        // ---- 2. New payment ------------------------------------------------
        if let Some(raw) = headers.get(HEADER_PAYMENT_SIGNATURE) {
            let payload: PaymentPayload = match x402::decode_header(raw) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "malformed payment-signature header");
                    return Decision::Deny {
                        challenge: PaymentRequired::new(
                            format!("malformed payment-signature header: {e}"),
                            vec![requirements],
                        ),
                    };
                }
            };

            return match self
                .state
                .facilitator
                .verify_and_settle(&payload, &requirements)
                .await
            {
                Ok(settlement) => {
                    // The payment has already settled by this point. If the
                    // session cannot be persisted we must still serve THIS
                    // request — the client paid for it — and simply hand back
                    // no token, so they pay again next time rather than being
                    // charged and refused.
                    let token = match self.state.sessions.create_session(&settlement.payer).await {
                        Ok(token) => Some(token),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                payer = %settlement.payer,
                                transaction = %settlement.transaction,
                                "payment settled but the session could not be stored; \
                                 serving this request without issuing a session"
                            );
                            None
                        }
                    };

                    tracing::info!(
                        payer = %settlement.payer,
                        transaction = %settlement.transaction,
                        sessioned = token.is_some(),
                        "payment settled"
                    );
                    Decision::Allow {
                        tier: Tier::Paid,
                        payer: Some(settlement.payer.clone()),
                        session_token: token,
                        settlement: Some(settlement),
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "payment rejected");
                    Decision::Deny {
                        challenge: PaymentRequired::new(
                            format!("payment rejected: {e}"),
                            vec![requirements],
                        ),
                    }
                }
            };
        }

        // ---- 3. Anonymous free tier ----------------------------------------
        let Some(ip) = client_ip else {
            // Without a source address the free tier cannot be metered, so fail
            // closed rather than granting unmetered access.
            tracing::warn!("no client address on CheckRequest; denying free-tier access");
            return Decision::Deny {
                challenge: PaymentRequired::new(
                    "client address unavailable; free tier cannot be metered",
                    vec![requirements],
                ),
            };
        };

        if self.state.limiter.check(ip).await {
            Decision::Allow {
                tier: Tier::Free,
                payer: None,
                session_token: None,
                settlement: None,
            }
        } else {
            tracing::debug!(%ip, "free tier exhausted; returning payment challenge");
            Decision::Deny {
                challenge: PaymentRequired::new(
                    "free tier rate limit exceeded; pay to unlock a higher limit",
                    vec![requirements],
                ),
            }
        }
    }
}

/// gRPC status code for a refused payment.
///
/// gRPC has no "payment required" code. `RESOURCE_EXHAUSTED` (8) is the closest
/// canonical fit — it is what gRPC maps HTTP 429 to, and free-tier exhaustion is
/// exactly a quota condition. `PERMISSION_DENIED` would imply the caller can
/// never proceed; a payment is a retry the client can actually act on.
const GRPC_STATUS_RESOURCE_EXHAUSTED: &str = "8";

/// Does this request come from a gRPC client?
///
/// gRPC clients collapse any non-200 HTTP status into an opaque transport error,
/// so a plain `402` reaches them as `code = Unknown` with the challenge buried in
/// a string. They must instead be answered in gRPC's own error model.
fn is_grpc_request(headers: &HeaderView<'_>) -> bool {
    headers
        .get("content-type")
        .is_some_and(|ct| ct.starts_with("application/grpc"))
}

/// Convert a [`Decision`] into the response Envoy expects.
///
/// `grpc` selects how a denial is framed: gRPC clients get a trailers-only
/// response carrying `grpc-status`, everyone else gets HTTP 402.
pub fn decision_to_response(
    decision: Decision,
    client_ip: Option<IpAddr>,
    grpc: bool,
) -> CheckResponse {
    match decision {
        Decision::Allow {
            tier,
            payer,
            session_token,
            settlement,
        } => {
            let mut ok = OkHttpResponseBuilder::new();

            // Overwrite, never append — this is the ratelimit descriptor source.
            ok.add_header(
                HEADER_TIER,
                tier.as_str(),
                Some(AUTHORITATIVE_APPEND),
                false,
            );
            ok.add_header(
                HEADER_PAYER,
                payer.clone().unwrap_or_default(),
                Some(AUTHORITATIVE_APPEND),
                // Free-tier requests have no payer; drop the empty header
                // rather than forwarding a blank identity.
                false,
            );

            // The client's own payment headers have served their purpose and
            // should not reach the backend.
            ok.remove_header(HEADER_PAYMENT_SIGNATURE);
            ok.remove_header(HEADER_PAYMENT_SESSION);

            if let Some(token) = session_token {
                ok.add_response_header(
                    HEADER_PAYMENT_SESSION,
                    token,
                    Some(AUTHORITATIVE_APPEND),
                    false,
                );
            }
            if let Some(settlement) = settlement
                && let Ok(encoded) = x402::encode_header(&settlement)
            {
                ok.add_response_header(
                    HEADER_PAYMENT_RESPONSE,
                    encoded,
                    Some(AUTHORITATIVE_APPEND),
                    false,
                );
            }

            let mut response = CheckResponse::with_status(Status::ok(""));
            response.set_http_response(ok);
            response.set_dynamic_metadata(Some(rate_limit_metadata(tier, payer, client_ip)));
            response
        }

        Decision::Deny { challenge } => {
            let mut denied = DeniedHttpResponseBuilder::new();

            // The challenge itself is identical either way; only its framing
            // differs. base64 keeps it valid as gRPC ASCII metadata too.
            let encoded = match x402::encode_header(&challenge) {
                Ok(encoded) => Some(encoded),
                Err(e) => {
                    tracing::error!(error = %e, "failed to encode payment challenge header");
                    None
                }
            };
            if let Some(encoded) = &encoded {
                denied.add_header(HEADER_PAYMENT_REQUIRED, encoded.clone(), None, false);
            }

            if grpc {
                // A gRPC "trailers-only" response: HTTP 200 carrying grpc-status
                // in the header frame. Clients surface this as a real status
                // code rather than an opaque transport failure, and can read the
                // challenge straight out of the response metadata.
                denied.set_http_status(HttpStatusCode::Ok);
                denied.add_header("content-type", "application/grpc", None, false);
                denied.add_header("grpc-status", GRPC_STATUS_RESOURCE_EXHAUSTED, None, false);
                denied.add_header("grpc-message", grpc_message(&challenge.error), None, false);
            } else {
                denied.set_http_status(HttpStatusCode::PaymentRequired);
                // Also send the challenge as a JSON body; header-only 402s are
                // hard to debug with ordinary HTTP clients.
                match serde_json::to_string(&challenge) {
                    Ok(body) => {
                        denied.add_header("content-type", "application/json", None, false);
                        denied.set_body(body);
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to encode payment challenge body")
                    }
                }
            }

            let mut response =
                CheckResponse::with_status(Status::permission_denied(challenge.error.clone()));
            response.set_http_response(denied);
            response
        }
    }
}

/// Percent-encode a `grpc-message` value.
///
/// The gRPC spec restricts this header to printable ASCII with `%` escaped;
/// anything else must be percent-encoded or clients may reject the frame.
fn grpc_message(reason: &str) -> String {
    reason
        .bytes()
        .map(|b| match b {
            b' '..=b'~' if b != b'%' => (b as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// Build the dynamic metadata Envoy's ratelimit filter can read descriptors from.
fn rate_limit_metadata(tier: Tier, payer: Option<String>, client_ip: Option<IpAddr>) -> Struct {
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("tier".to_string(), string_value(tier.as_str()));
    if let Some(payer) = payer {
        fields.insert("payer".to_string(), string_value(payer));
    }
    if let Some(ip) = client_ip {
        fields.insert("source_ip".to_string(), string_value(ip.to_string()));
    }
    Struct {
        fields: fields.into_iter().collect(),
    }
}

fn string_value(s: impl Into<String>) -> Value {
    Value {
        kind: Some(Kind::StringValue(s.into())),
    }
}

/// Borrowed view over the request headers Envoy supplied.
///
/// Envoy lowercases header names before sending them, but this normalizes the
/// lookup key anyway so callers cannot be tripped up by a differently-behaved
/// gateway.
#[derive(Debug, Default)]
pub struct HeaderView<'a> {
    inner: Option<&'a std::collections::HashMap<String, String>>,
}

impl<'a> HeaderView<'a> {
    pub fn new(inner: Option<&'a std::collections::HashMap<String, String>>) -> Self {
        Self { inner }
    }

    /// Fetch a header value, ignoring empty values (Envoy may forward those).
    ///
    /// `name` is expected to already be lowercase, matching Envoy's
    /// normalization; the fallback scan exists for gateways that preserve the
    /// client's original casing. Header maps are small, so the linear scan on
    /// the miss path is cheaper than allocating a normalized copy per lookup.
    pub fn get(&self, name: &str) -> Option<&'a str> {
        let map = self.inner?;
        let value = map.get(name).map(|v| v.as_str()).or_else(|| {
            map.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        })?;
        (!value.trim().is_empty()).then_some(value)
    }
}

#[tonic::async_trait]
impl Authorization for X402Auth {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let check_request = request.into_inner();

        let headers = HeaderView::new(check_request.get_client_headers());

        // Envoy reports the peer address as a string; a proxy in front of Envoy
        // means this is the proxy's IP unless XFF handling is configured.
        let client_ip = check_request
            .get_client_address()
            .and_then(|addr| addr.parse::<IpAddr>().ok());

        let path = check_request
            .attributes
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .and_then(|r| r.http.as_ref())
            .map(|h| h.path.as_str())
            .unwrap_or("");

        // Per-route metadata Envoy attached via ExtAuthzPerRoute. This is how
        // the gateway tells us which pricing policy the matched route uses,
        // avoiding a second copy of the route table in this service.
        let policy = check_request
            .attributes
            .as_ref()
            .and_then(|a| a.context_extensions.get(POLICY_CONTEXT_KEY))
            .map(|s| s.as_str());

        let grpc = is_grpc_request(&headers);
        let decision = self.decide(&headers, client_ip, path, policy).await;
        Ok(Response::new(decision_to_response(
            decision, client_ip, grpc,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FreeTierConfig, PaidTierConfig, PaymentConfig, VerificationMode};
    use crate::ratelimit::MemoryRateLimiter;
    use crate::session::MemorySessionStore;
    use crate::x402::{SuiExactPayload, X402_VERSION};
    use envoy_types::ext_authz::v3::pb::HttpResponse;
    use std::collections::HashMap;

    const PAYER: &str = "0xdeadbeef";
    const PATH: &str = "/sui.rpc.v2.LedgerService/GetServiceInfo";

    fn test_config(free_limit: u64, quota: u64) -> Config {
        Config {
            listen_addr: "127.0.0.1:50051".parse().unwrap(),
            sui_grpc_url: "https://fullnode.testnet.sui.io:443".into(),
            sui_chain: "testnet".into(),
            verification_mode: VerificationMode::StubAcceptAll,
            payment: PaymentConfig {
                scheme: "exact".into(),
                network: "sui:testnet".into(),
                max_amount_required: "1000".into(),
                asset: "0xa1::usdc::USDC".into(),
                pay_to: "0xmerchant".into(),
                max_timeout_seconds: 60,
                description: "test".into(),
            },
            free_tier: FreeTierConfig {
                max_requests: free_limit,
                window_secs: 60,
            },
            paid_tier: PaidTierConfig {
                quota,
                duration_secs: 3600,
            },
            policies: std::collections::HashMap::new(),
            routes: Vec::new(),
            store: crate::config::StoreConfig::default(),
            session_hmac_secret: "ab".repeat(32),
        }
    }

    fn auth(free_limit: u64, quota: u64) -> X402Auth {
        let config = test_config(free_limit, quota);
        let facilitator = Facilitator::new(
            config.verification_mode,
            config.sui_grpc_url.clone(),
            config.payment.network.clone(),
        );
        let sessions = SessionStore::Memory(MemorySessionStore::new(
            config.hmac_key().unwrap(),
            config.paid_tier.duration_secs,
            config.paid_tier.quota,
        ));
        let limiter = RateLimiter::Memory(MemoryRateLimiter::new(
            config.free_tier.max_requests,
            config.free_tier.window_secs,
        ));
        X402Auth::new(Arc::new(AppState {
            config,
            sessions,
            limiter,
            facilitator,
        }))
    }

    fn ip() -> Option<IpAddr> {
        Some(IpAddr::from([10, 0, 0, 1]))
    }

    fn payment_header() -> String {
        x402::encode_header(&PaymentPayload {
            x402_version: X402_VERSION,
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            payload: SuiExactPayload {
                transaction_bytes: "AAAA".into(),
                signatures: vec!["BBBB".into()],
                payer: Some(PAYER.into()),
            },
        })
        .unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn anonymous_request_under_the_limit_is_free_tier() {
        let a = auth(5, 10);
        let map = headers(&[]);
        let decision = a
            .decide(&HeaderView::new(Some(&map)), ip(), PATH, None)
            .await;
        assert!(matches!(
            decision,
            Decision::Allow {
                tier: Tier::Free,
                payer: None,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn exhausting_the_free_tier_yields_a_402_challenge_not_a_429() {
        let a = auth(1, 10);
        let map = headers(&[]);
        let view = HeaderView::new(Some(&map));

        assert!(matches!(
            a.decide(&view, ip(), PATH, None).await,
            Decision::Allow {
                tier: Tier::Free,
                ..
            }
        ));

        let decision = a.decide(&view, ip(), PATH, None).await;
        let Decision::Deny { challenge } = decision else {
            panic!("expected denial once the free tier was spent");
        };
        assert_eq!(challenge.x402_version, X402_VERSION);
        assert_eq!(challenge.accepts.len(), 1);
        // The challenge must advertise terms the client can actually act on.
        assert_eq!(challenge.accepts[0].pay_to, "0xmerchant");
        assert_eq!(challenge.accepts[0].network, "sui:testnet");
        assert_eq!(challenge.accepts[0].resource, PATH);
    }

    #[tokio::test]
    async fn payment_unlocks_the_paid_tier_and_mints_a_session() {
        // Free tier is zero, so success can only come from the payment path.
        let a = auth(0, 10);
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);

        let decision = a
            .decide(&HeaderView::new(Some(&map)), ip(), PATH, None)
            .await;
        let Decision::Allow {
            tier,
            payer,
            session_token,
            settlement,
        } = decision
        else {
            panic!("payment should have been accepted");
        };
        assert_eq!(tier, Tier::Paid);
        assert_eq!(payer.as_deref(), Some(PAYER));
        assert!(session_token.is_some(), "a session token should be issued");
        assert_eq!(settlement.unwrap().payer, PAYER);
    }

    #[tokio::test]
    async fn issued_session_token_is_accepted_on_the_next_request() {
        let a = auth(0, 10);
        let pay_map = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);
        let Decision::Allow {
            session_token: Some(token),
            ..
        } = a
            .decide(&HeaderView::new(Some(&pay_map)), ip(), PATH, None)
            .await
        else {
            panic!("expected a session token");
        };

        // Second request presents only the session token — no payment.
        let session_map = headers(&[(HEADER_PAYMENT_SESSION, &token)]);
        let decision = a
            .decide(&HeaderView::new(Some(&session_map)), ip(), PATH, None)
            .await;
        assert!(
            matches!(
                decision,
                Decision::Allow {
                    tier: Tier::Paid,
                    session_token: None,
                    ..
                }
            ),
            "reused session should be paid tier and mint no new token, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn session_falls_back_to_free_tier_once_quota_is_spent() {
        let a = auth(5, 1); // 1 paid request, then free tier still available.
        let pay_map = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);
        let Decision::Allow {
            session_token: Some(token),
            ..
        } = a
            .decide(&HeaderView::new(Some(&pay_map)), ip(), PATH, None)
            .await
        else {
            panic!("expected a session token");
        };

        let session_map = headers(&[(HEADER_PAYMENT_SESSION, &token)]);
        let view = HeaderView::new(Some(&session_map));

        // Spend the single paid request.
        assert!(matches!(
            a.decide(&view, ip(), PATH, None).await,
            Decision::Allow {
                tier: Tier::Paid,
                ..
            }
        ));
        // Quota gone: degrade to free rather than erroring.
        assert!(matches!(
            a.decide(&view, ip(), PATH, None).await,
            Decision::Allow {
                tier: Tier::Free,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn forged_session_token_does_not_grant_paid_tier() {
        let a = auth(5, 10);
        let forged = format!(
            "{PAYER}:99999999999:{}:{}",
            "aa".repeat(16),
            "bb".repeat(32)
        );
        let map = headers(&[(HEADER_PAYMENT_SESSION, &forged)]);

        let decision = a
            .decide(&HeaderView::new(Some(&map)), ip(), PATH, None)
            .await;
        assert!(
            matches!(
                decision,
                Decision::Allow {
                    tier: Tier::Free,
                    ..
                }
            ),
            "forged token must not escalate, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn malformed_payment_header_is_denied_with_a_challenge() {
        let a = auth(5, 10);
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, "!!!not-base64!!!")]);
        let decision = a
            .decide(&HeaderView::new(Some(&map)), ip(), PATH, None)
            .await;

        let Decision::Deny { challenge } = decision else {
            panic!("malformed payment should be denied, not silently demoted");
        };
        assert!(challenge.error.contains("malformed"), "{}", challenge.error);
    }

    #[tokio::test]
    async fn payment_for_the_wrong_network_is_denied() {
        let a = auth(5, 10);
        let wrong = x402::encode_header(&PaymentPayload {
            x402_version: X402_VERSION,
            scheme: "exact".into(),
            network: "sui:mainnet".into(),
            payload: SuiExactPayload {
                transaction_bytes: "AAAA".into(),
                signatures: vec!["BBBB".into()],
                payer: Some(PAYER.into()),
            },
        })
        .unwrap();
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &wrong)]);

        let Decision::Deny { challenge } = a
            .decide(&HeaderView::new(Some(&map)), ip(), PATH, None)
            .await
        else {
            panic!("cross-network payment must be denied");
        };
        assert!(challenge.error.contains("network"), "{}", challenge.error);
    }

    #[tokio::test]
    async fn missing_client_address_fails_closed() {
        let a = auth(100, 10);
        let map = headers(&[]);
        let decision = a
            .decide(&HeaderView::new(Some(&map)), None, PATH, None)
            .await;
        assert!(
            matches!(decision, Decision::Deny { .. }),
            "unmeterable request must not be allowed, got {decision:?}"
        );
    }

    // ---- Response construction -------------------------------------------

    fn ok_response(decision: Decision) -> envoy_types::ext_authz::v3::pb::OkHttpResponse {
        match decision_to_response(decision, ip(), false).http_response {
            Some(HttpResponse::OkResponse(ok)) => ok,
            other => panic!("expected an OK response, got {other:?}"),
        }
    }

    #[test]
    fn tier_and_payer_headers_overwrite_client_supplied_values() {
        // The core anti-self-promotion property.
        let ok = ok_response(Decision::Allow {
            tier: Tier::Paid,
            payer: Some(PAYER.into()),
            session_token: None,
            settlement: None,
        });

        let tier = ok
            .headers
            .iter()
            .find(|h| h.header.as_ref().unwrap().key == HEADER_TIER)
            .expect("tier header must be set");
        assert_eq!(
            tier.append_action,
            HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
            "tier header must overwrite, or clients can self-promote to paid"
        );

        let payer = ok
            .headers
            .iter()
            .find(|h| h.header.as_ref().unwrap().key == HEADER_PAYER)
            .expect("payer header must be set");
        assert_eq!(
            payer.append_action,
            HeaderAppendAction::OverwriteIfExistsOrAdd as i32
        );
    }

    #[test]
    fn client_payment_headers_are_stripped_before_the_backend() {
        let ok = ok_response(Decision::Allow {
            tier: Tier::Free,
            payer: None,
            session_token: None,
            settlement: None,
        });
        assert!(
            ok.headers_to_remove
                .iter()
                .any(|h| h == HEADER_PAYMENT_SIGNATURE)
        );
        assert!(
            ok.headers_to_remove
                .iter()
                .any(|h| h == HEADER_PAYMENT_SESSION)
        );
    }

    #[test]
    fn new_session_is_returned_to_the_client_as_a_response_header() {
        let ok = ok_response(Decision::Allow {
            tier: Tier::Paid,
            payer: Some(PAYER.into()),
            session_token: Some("token-value".into()),
            settlement: Some(SettlementResponse {
                success: true,
                transaction: "0xdigest".into(),
                network: "sui:testnet".into(),
                payer: PAYER.into(),
            }),
        });

        let names: Vec<&str> = ok
            .response_headers_to_add
            .iter()
            .map(|h| h.header.as_ref().unwrap().key.as_str())
            .collect();
        assert!(names.contains(&HEADER_PAYMENT_SESSION), "{names:?}");
        assert!(names.contains(&HEADER_PAYMENT_RESPONSE), "{names:?}");
    }

    #[test]
    fn denial_uses_http_402_and_carries_the_challenge_header() {
        let challenge = PaymentRequired::new("nope", vec![]);
        let response = decision_to_response(Decision::Deny { challenge }, ip(), false);

        // Non-zero gRPC status is what makes Envoy treat this as a denial.
        assert_ne!(response.status.as_ref().unwrap().code, 0);

        let Some(HttpResponse::DeniedResponse(denied)) = response.http_response else {
            panic!("expected a denied response");
        };
        assert_eq!(
            denied.status.unwrap().code,
            HttpStatusCode::PaymentRequired as i32,
            "must be 402, not 403/429"
        );
        assert!(
            denied
                .headers
                .iter()
                .any(|h| h.header.as_ref().unwrap().key == HEADER_PAYMENT_REQUIRED),
            "challenge header must be present"
        );
        assert!(!denied.body.is_empty(), "challenge body aids debugging");
    }

    #[test]
    fn grpc_denial_uses_a_trailers_only_response_not_http_402() {
        // gRPC clients turn any non-200 HTTP status into an opaque transport
        // error, so a denial must be spoken in gRPC's own error model.
        let challenge = PaymentRequired::new("free tier exhausted", vec![]);
        let response = decision_to_response(Decision::Deny { challenge }, ip(), true);

        let Some(HttpResponse::DeniedResponse(denied)) = response.http_response else {
            panic!("expected a denied response");
        };

        assert_eq!(
            denied.status.unwrap().code,
            HttpStatusCode::Ok as i32,
            "gRPC denials must be HTTP 200 trailers-only, not 402"
        );

        let header = |name: &str| {
            denied
                .headers
                .iter()
                .map(|h| h.header.as_ref().unwrap())
                .find(|h| h.key == name)
                .map(|h| h.value.clone())
        };

        assert_eq!(header("grpc-status").as_deref(), Some("8")); // RESOURCE_EXHAUSTED
        // Space is legal unescaped per the spec's Percent-Byte-Unescaped range.
        assert_eq!(
            header("grpc-message").as_deref(),
            Some("free tier exhausted")
        );
        assert_eq!(header("content-type").as_deref(), Some("application/grpc"));
        // The machine-readable challenge must still be reachable as metadata.
        assert!(header(HEADER_PAYMENT_REQUIRED).is_some());
        // A body would corrupt a trailers-only frame.
        assert!(
            denied.body.is_empty(),
            "trailers-only response carries no body"
        );
    }

    #[test]
    fn http_denial_is_unchanged_by_the_grpc_path() {
        let challenge = PaymentRequired::new("nope", vec![]);
        let response = decision_to_response(Decision::Deny { challenge }, ip(), false);
        let Some(HttpResponse::DeniedResponse(denied)) = response.http_response else {
            panic!("expected a denied response");
        };
        assert_eq!(
            denied.status.unwrap().code,
            HttpStatusCode::PaymentRequired as i32
        );
        assert!(!denied.body.is_empty());
    }

    #[test]
    fn grpc_requests_are_detected_by_content_type() {
        let grpc = headers(&[("content-type", "application/grpc")]);
        assert!(is_grpc_request(&HeaderView::new(Some(&grpc))));

        // grpc-web and +proto suffixes are still gRPC.
        let proto = headers(&[("content-type", "application/grpc+proto")]);
        assert!(is_grpc_request(&HeaderView::new(Some(&proto))));

        let json = headers(&[("content-type", "application/json")]);
        assert!(!is_grpc_request(&HeaderView::new(Some(&json))));

        let none = headers(&[]);
        assert!(!is_grpc_request(&HeaderView::new(Some(&none))));
    }

    #[test]
    fn grpc_message_escapes_non_ascii_and_percent() {
        // Per the gRPC spec, Percent-Byte-Unescaped is %x20-%x24 / %x26-%x7E:
        // space and printable ASCII pass through, only `%` and bytes outside
        // that range are escaped.
        assert_eq!(grpc_message("plain text"), "plain text");
        assert_eq!(grpc_message("100%"), "100%25");
        assert_eq!(grpc_message("café"), "caf%C3%A9");
        // Control characters are outside the unescaped range.
        assert_eq!(grpc_message("a\nb"), "a%0Ab");
    }

    #[test]
    fn allow_sets_rate_limit_metadata_for_envoy_descriptors() {
        let response = decision_to_response(
            Decision::Allow {
                tier: Tier::Paid,
                payer: Some(PAYER.into()),
                session_token: None,
                settlement: None,
            },
            ip(),
            false,
        );
        let fields = response
            .dynamic_metadata
            .expect("metadata must be set")
            .fields;
        assert_eq!(
            fields.get("tier").unwrap().kind,
            Some(Kind::StringValue("paid".into()))
        );
        assert_eq!(
            fields.get("payer").unwrap().kind,
            Some(Kind::StringValue(PAYER.into()))
        );
        assert!(fields.contains_key("source_ip"));
    }

    #[test]
    fn header_lookup_is_case_insensitive_and_ignores_blanks() {
        let map = headers(&[("X-Payment-Session", "abc"), ("x-x402-payer", "   ")]);
        let view = HeaderView::new(Some(&map));
        assert_eq!(view.get("x-payment-session"), Some("abc"));
        assert_eq!(
            view.get("x-x402-payer"),
            None,
            "blank values are not values"
        );
        assert_eq!(view.get("absent"), None);
    }
}
