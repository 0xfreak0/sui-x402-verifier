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
use crate::session::{PaymentClaim, SessionOutcome, SessionStore};
use crate::x402::{
    self, Facilitator, HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SESSION,
    HEADER_PAYMENT_SIGNATURE, PaymentPayload, PaymentRequired, PaymentRequirements, ResourceInfo,
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

/// When settlement happens relative to serving the request.
///
/// The x402 Sui scheme sequences this as verify -> resource server does the
/// work -> settle, so a client is only charged once the resource has actually
/// been produced. Which of these is achievable depends entirely on the filter:
/// `ext_authz` runs before the upstream and cannot see the response, so it can
/// only settle early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlePolicy {
    /// Settle during authorization, before the upstream is called.
    ///
    /// The only option for `ext_authz`. A paying client is charged even if the
    /// upstream then fails.
    Immediate,
    /// Verify during authorization, settle after the upstream succeeds.
    ///
    /// Matches the spec's sequencing. Requires a filter that can act on the
    /// response path — see [`crate::ext_proc`].
    Deferred,
}

/// A payment that verified but has not been settled yet.
///
/// Carried across the request/response boundary by the ext_proc stream so the
/// charge can happen only after the upstream has actually delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPayment {
    pub payload: PaymentPayload,
    pub requirements: PaymentRequirements,
    /// Replay-cache key, so an unsettled payment can be released for retry.
    pub payment_id: Option<String>,
}

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
        /// Present only under [`SettlePolicy::Deferred`]: verified, not yet
        /// charged. The caller must settle it once the upstream succeeds.
        pending: Option<Box<PendingPayment>>,
    },
    Deny {
        challenge: PaymentRequired,
        /// Present only when a payment was *attempted* and refused.
        ///
        /// This is what distinguishes "your payment was rejected, here is the
        /// machine-readable reason" from "you never paid" — two situations that
        /// were previously indistinguishable to a client, both arriving as a
        /// bare 402 with only a challenge.
        receipt: Option<SettlementResponse>,
    },
}

/// Shared service state.
#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub sessions: Arc<SessionStore>,
    pub limiter: RateLimiter,
    /// Shared with the optional facilitator HTTP API so both surfaces enforce
    /// identical rules.
    pub facilitator: Arc<Facilitator>,
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
        resource_url: &str,
        settle: SettlePolicy,
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
        let payment = self.state.config.payment_for(path, policy);
        let requirements = PaymentRequirements::from_config(&payment);

        // In v2 the resource is a top-level object on PaymentRequired, not a
        // field repeated inside every accepts[] entry.
        let resource = ResourceInfo {
            url: resource_url.to_string(),
            description: Some(payment.description.clone()),
            mime_type: Some("application/json".to_string()),
        };

        // Advertise that a settled payment buys a reusable session, using the
        // §5.1.2 extensions mechanism rather than an undocumented header.
        let mut challenge_extensions = Some(x402::session_extension_advertisement(
            self.state.config.paid_tier.quota,
            self.state.config.paid_tier.duration_secs,
            HEADER_PAYMENT_SESSION,
        ));

        // Decode any payment up front: it may carry a session token echoed in
        // its extensions, which must be honoured before charging again.
        let presented_payment: Option<Result<PaymentPayload, _>> = headers
            .get(HEADER_PAYMENT_SIGNATURE)
            .map(x402::decode_header::<PaymentPayload>);

        // A session token may arrive two ways: echoed in a payment's
        // `extensions` (the spec-sanctioned route), or in the raw header, kept
        // working as a deprecated alias so existing clients do not break.
        let echoed_token = presented_payment
            .as_ref()
            .and_then(|p| p.as_ref().ok())
            .and_then(|p| x402::session_token_from_extensions(p.extensions.as_ref()))
            .map(str::to_string);
        let session_token =
            echoed_token.or_else(|| headers.get(HEADER_PAYMENT_SESSION).map(String::from));

        // ---- 1. Existing paid session -------------------------------------
        if let Some(token) = &session_token {
            match self.state.sessions.consume(token, policy).await {
                SessionOutcome::Accepted { payer, remaining } => {
                    tracing::debug!(%payer, remaining, "paid request served from session");
                    return Decision::Allow {
                        tier: Tier::Paid,
                        payer: Some(payer),
                        session_token: None,
                        settlement: None,
                        pending: None,
                    };
                }
                SessionOutcome::Rejected(reason) => {
                    // Not fatal: fall through so the client can pay again.
                    tracing::debug!(?reason, "session token not honored");
                }
            }
        }

        // ---- 2. New payment ------------------------------------------------
        if let Some(decoded) = presented_payment {
            let payload = match decoded {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "malformed payment-signature header");
                    let mut challenge = PaymentRequired::new(
                        format!("malformed payment-signature header: {e}"),
                        resource,
                        vec![requirements],
                    );
                    challenge.extensions = challenge_extensions.take();
                    return Decision::Deny {
                        challenge,
                        // A payment WAS attempted; it just could not be parsed.
                        receipt: Some(self.state.facilitator.failure_receipt("invalid_payload")),
                    };
                }
            };

            // Claim the payment before doing anything with it. Sui's own
            // replay protection only binds once settlement lands on chain, so
            // without this one signature mints unlimited sessions in stub mode,
            // and races to mint several even with real settlement.
            if let Some(id) = x402::payment_id(&payload) {
                // Hold the claim for longer than the advertised window, so the
                // authorization stays blocked after it has also expired. With
                // ttl == window the record would lapse at exactly the moment
                // the payment became replayable again.
                let ttl = replay_ttl(requirements.max_timeout_seconds);
                let claim = self.state.sessions.claim_payment(&id, ttl).await;
                if let Some(error) = match claim {
                    PaymentClaim::Fresh => None,
                    PaymentClaim::Replay { first_seen } => {
                        // Distinguish the two reasons a second sighting is
                        // refused: still inside the window it is a replay,
                        // past it the authorization has simply expired.
                        let age = crate::util::now_epoch_secs().saturating_sub(first_seen);
                        if age > requirements.max_timeout_seconds {
                            Some(x402::FacilitatorError::AuthorizationExpired {
                                first_seen,
                                window: requirements.max_timeout_seconds,
                            })
                        } else {
                            Some(x402::FacilitatorError::Replay { first_seen })
                        }
                    }
                    // Fail closed: an unreachable cache must not become an
                    // unlimited-replay window.
                    PaymentClaim::Backend => Some(x402::FacilitatorError::ReplayCacheUnavailable),
                } {
                    tracing::warn!(error = %error, code = error.code(), "payment refused");
                    let mut challenge = PaymentRequired::new(
                        format!("payment rejected: {error}"),
                        resource,
                        vec![requirements],
                    );
                    challenge.extensions = challenge_extensions.take();
                    return Decision::Deny {
                        challenge,
                        receipt: Some(self.state.facilitator.failure_receipt(error.code())),
                    };
                }
            }

            // Under Deferred we only VERIFY here; the charge happens once the
            // upstream has actually served the request.
            if settle == SettlePolicy::Deferred {
                return match self.state.facilitator.verify(&payload, &requirements).await {
                    Ok(payer) => {
                        tracing::debug!(%payer, "payment verified; settlement deferred until the upstream succeeds");
                        Decision::Allow {
                            tier: Tier::Paid,
                            payer: Some(payer),
                            // No session yet: it is minted when the payment
                            // actually settles.
                            session_token: None,
                            settlement: None,
                            pending: Some(Box::new(PendingPayment {
                                payment_id: x402::payment_id(&payload),
                                payload,
                                requirements,
                            })),
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, code = e.code(), "payment rejected");
                        let mut challenge = PaymentRequired::new(
                            format!("payment rejected: {e}"),
                            resource,
                            vec![requirements],
                        );
                        challenge.extensions = challenge_extensions.take();
                        Decision::Deny {
                            challenge,
                            receipt: Some(self.state.facilitator.failure_receipt(e.code())),
                        }
                    }
                };
            }

            return match self
                .state
                .facilitator
                .verify_and_settle(&payload, &requirements)
                .await
            {
                Ok(mut settlement) => {
                    // The payment has already settled by this point. If the
                    // session cannot be persisted we must still serve THIS
                    // request — the client paid for it — and simply hand back
                    // no token, so they pay again next time rather than being
                    // charged and refused.
                    //
                    // `payer` is optional in v2: with no identity there is
                    // nothing to bind a session to, so we serve the request
                    // unsessioned rather than inventing an owner for it.
                    let token = match &settlement.payer {
                        None => {
                            tracing::warn!(
                                "settlement returned no payer; serving this request \
                                 without issuing a session"
                            );
                            None
                        }
                        Some(payer) => {
                            match self.state.sessions.create_session(payer, policy).await {
                                Ok(token) => Some(token),
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        %payer,
                                        transaction = %settlement.transaction,
                                        "payment settled but the session could not be stored; \
                                         serving this request without issuing a session"
                                    );
                                    None
                                }
                            }
                        }
                    };

                    // Return the token through the receipt's `extensions`, the
                    // sanctioned channel, alongside the raw response header.
                    if let Some(token) = &token {
                        settlement.extensions = Some(x402::session_extension_grant(
                            token,
                            self.state.config.paid_tier.quota,
                            self.state.config.paid_tier.duration_secs,
                        ));
                    }

                    tracing::info!(
                        payer = settlement.payer.as_deref().unwrap_or("<unknown>"),
                        transaction = %settlement.transaction,
                        sessioned = token.is_some(),
                        "payment settled"
                    );
                    Decision::Allow {
                        tier: Tier::Paid,
                        payer: settlement.payer.clone(),
                        session_token: token,
                        settlement: Some(settlement),
                        pending: None,
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, code = e.code(), "payment rejected");
                    let mut challenge = PaymentRequired::new(
                        // The human string stays here; the machine-readable
                        // §9 code goes in the receipt's errorReason.
                        format!("payment rejected: {e}"),
                        resource,
                        vec![requirements],
                    );
                    challenge.extensions = challenge_extensions.take();
                    Decision::Deny {
                        challenge,
                        receipt: Some(self.state.facilitator.failure_receipt(e.code())),
                    }
                }
            };
        }

        // ---- 3. Anonymous free tier ----------------------------------------
        let Some(ip) = client_ip else {
            // Without a source address the free tier cannot be metered, so fail
            // closed rather than granting unmetered access.
            tracing::warn!("no client address on CheckRequest; denying free-tier access");
            let mut challenge = PaymentRequired::new(
                "client address unavailable; free tier cannot be metered",
                resource,
                vec![requirements],
            );
            challenge.extensions = challenge_extensions.take();
            // No receipt: no payment was attempted, so there is nothing to
            // report the outcome of.
            return Decision::Deny {
                challenge,
                receipt: None,
            };
        };

        if self.state.limiter.check(ip).await {
            Decision::Allow {
                tier: Tier::Free,
                payer: None,
                session_token: None,
                settlement: None,
                pending: None,
            }
        } else {
            tracing::debug!(%ip, "free tier exhausted; returning payment challenge");
            let mut challenge = PaymentRequired::new(
                "free tier rate limit exceeded; pay to unlock a higher limit",
                resource,
                vec![requirements],
            );
            challenge.extensions = challenge_extensions.take();
            Decision::Deny {
                challenge,
                receipt: None,
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
            ..
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

        Decision::Deny { challenge, receipt } => {
            let mut denied = DeniedHttpResponseBuilder::new();

            // A refused payment reports its outcome exactly like a successful
            // one: same header, same schema, success:false. Without this, "your
            // payment was rejected" and "you never paid" are the same response.
            if let Some(receipt) = &receipt {
                match x402::encode_header(receipt) {
                    Ok(encoded) => denied.add_header(HEADER_PAYMENT_RESPONSE, encoded, None, false),
                    Err(e) => {
                        tracing::error!(error = %e, "failed to encode failure receipt");
                        &mut denied
                    }
                };
            }

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
                denied.add_header(
                    "grpc-message",
                    grpc_message(challenge.error.as_deref().unwrap_or_default()),
                    None,
                    false,
                );
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

            let mut response = CheckResponse::with_status(Status::permission_denied(
                challenge.error.clone().unwrap_or_default(),
            ));
            response.set_http_response(denied);
            response
        }
    }
}

/// Reconstruct the full URL of the requested resource.
///
/// `PaymentRequired.resource.url` must be a complete URL (§5.1.2), not the bare
/// path this service previously emitted — a client cannot resolve a path back
/// to a resource it can address.
///
/// If the authority is missing we fall back to the path and log, rather than
/// emitting something like `https:///graphql` that merely looks like a URL.
fn resource_url(
    http: Option<&envoy_types::pb::envoy::service::auth::v3::attribute_context::HttpRequest>,
) -> String {
    let Some(http) = http else {
        return String::new();
    };

    if http.host.is_empty() {
        // Envoy populates `host` from :authority; empty means a malformed or
        // synthetic request.
        tracing::warn!(
            path = %http.path,
            "request has no authority; emitting a path-only resource url, which is \
             not spec-conformant but is better than a malformed absolute url"
        );
        return http.path.clone();
    }

    // Envoy leaves `scheme` empty on some paths; https is the safer assumption
    // for a public gateway than downgrading to http.
    let scheme = if http.scheme.is_empty() {
        "https"
    } else {
        &http.scheme
    };

    format!("{scheme}://{}{}", http.host, http.path)
}

/// How long a payment stays claimed, given the advertised timeout.
///
/// Longer than the window on purpose, and never shorter than a floor: the claim
/// is what actually prevents a signed authorization being spent twice, and
/// `maxTimeoutSeconds` can be advertised as low as a second or two.
///
/// This is single-use enforcement, which is *stricter* than the time window the
/// spec describes — and it has to be, because Sui cannot enforce a
/// second-granularity expiry on chain at all (see `docs/spec-gaps.md`). The
/// chain's own object-version replay protection only binds once settlement
/// lands, so before that this cache is the only thing standing between one
/// signature and N sessions.
pub fn replay_ttl(max_timeout_seconds: u64) -> u64 {
    const FLOOR: u64 = 300;
    const MULTIPLIER: u64 = 10;
    max_timeout_seconds.saturating_mul(MULTIPLIER).max(FLOOR)
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

        let http = check_request
            .attributes
            .as_ref()
            .and_then(|a| a.request.as_ref())
            .and_then(|r| r.http.as_ref());

        let path = http.map(|h| h.path.as_str()).unwrap_or("");
        let resource_url = resource_url(http);

        // Per-route metadata Envoy attached via ExtAuthzPerRoute. This is how
        // the gateway tells us which pricing policy the matched route uses,
        // avoiding a second copy of the route table in this service.
        let policy = check_request
            .attributes
            .as_ref()
            .and_then(|a| a.context_extensions.get(POLICY_CONTEXT_KEY))
            .map(|s| s.as_str());

        let grpc = is_grpc_request(&headers);
        // ext_authz is a pre-upstream filter: it cannot observe the response,
        // so settlement can only happen here. See `ext_proc` for the ordering
        // the spec actually asks for.
        let decision = self
            .decide(
                &headers,
                client_ip,
                path,
                policy,
                &resource_url,
                SettlePolicy::Immediate,
            )
            .await;
        Ok(Response::new(decision_to_response(
            decision, client_ip, grpc,
        )))
    }
}

/// Shared test scaffolding, used by this module and `ext_proc`.
#[cfg(test)]
pub mod test_support {
    use super::*;
    use crate::config::{
        FreeTierConfig, PaidTierConfig, PaymentConfig, StoreConfig, VerificationMode,
    };
    use crate::ratelimit::{MemoryRateLimiter, RateLimiter};
    use crate::session::{MemorySessionStore, SessionStore};

    /// An in-memory `AppState` in stub mode, with the given tier limits.
    pub fn app_state(free_limit: u64, quota: u64) -> Arc<AppState> {
        let config = Config {
            listen_addr: "127.0.0.1:50051".parse().unwrap(),
            facilitator_api_listen_addr: None,
            sui_grpc_url: "https://fullnode.testnet.sui.io:443".into(),
            sui_chain: "testnet".into(),
            verification_mode: VerificationMode::StubAcceptAll,
            payment: PaymentConfig {
                scheme: "exact".into(),
                network: "sui:testnet".into(),
                amount: "1000".into(),
                asset: "0xa1::usdc::USDC".into(),
                pay_to: "0xmerchant".into(),
                max_timeout_seconds: 60,
                description: "test".into(),
                gas_station: None,
            },
            policies: std::collections::HashMap::new(),
            routes: Vec::new(),
            free_tier: FreeTierConfig {
                max_requests: free_limit,
                window_secs: 60,
            },
            paid_tier: PaidTierConfig {
                quota,
                duration_secs: 3600,
            },
            store: StoreConfig::default(),
            session_hmac_secret: "ab".repeat(32),
        };
        let facilitator = Arc::new(
            Facilitator::new(
                config.verification_mode,
                config.sui_grpc_url.clone(),
                config.payment.network.clone(),
            )
            .expect("stub mode never connects"),
        );
        let sessions = Arc::new(SessionStore::Memory(MemorySessionStore::new(
            config.hmac_key().unwrap(),
            config.paid_tier.duration_secs,
            config.paid_tier.quota,
        )));
        let limiter = RateLimiter::Memory(MemoryRateLimiter::new(
            config.free_tier.max_requests,
            config.free_tier.window_secs,
        ));
        Arc::new(AppState {
            config,
            sessions,
            limiter,
            facilitator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::SESSION_EXTENSION;
    use crate::x402::X402_VERSION;
    use envoy_types::ext_authz::v3::pb::HttpResponse;
    use std::collections::HashMap;

    const PAYER: &str = "0xdeadbeef";
    const PATH: &str = "/sui.rpc.v2.LedgerService/GetServiceInfo";
    const RESOURCE_URL: &str = "https://api.example.com/sui.rpc.v2.LedgerService/GetServiceInfo";

    fn auth(free_limit: u64, quota: u64) -> X402Auth {
        X402Auth::new(test_support::app_state(free_limit, quota))
    }

    fn test_resource() -> ResourceInfo {
        ResourceInfo {
            url: RESOURCE_URL.into(),
            description: Some("test".into()),
            mime_type: Some("application/json".into()),
        }
    }

    fn ip() -> Option<IpAddr> {
        Some(IpAddr::from([10, 0, 0, 1]))
    }

    /// A conformant v2 payment payload echoing the advertised terms.
    fn payment_header() -> String {
        payment_header_with(|_| {})
    }

    /// As [`payment_header`], with the payload mutated before encoding.
    fn payment_header_with(mutate: impl FnOnce(&mut PaymentPayload)) -> String {
        let mut payload = PaymentPayload {
            x402_version: X402_VERSION,
            resource: Some(test_resource()),
            accepted: PaymentRequirements {
                scheme: "exact".into(),
                network: "sui:testnet".into(),
                amount: "1000".into(),
                asset: "0xa1::usdc::USDC".into(),
                pay_to: "0xmerchant".into(),
                max_timeout_seconds: 60,
                extra: None,
            },
            payload: serde_json::json!({ "signature": "c2ln", "transaction": "dHg=" }),
            extensions: None,
        };
        mutate(&mut payload);
        x402::encode_header(&payload).unwrap()
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
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
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
            a.decide(
                &view,
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate
            )
            .await,
            Decision::Allow {
                tier: Tier::Free,
                ..
            }
        ));

        let decision = a
            .decide(
                &view,
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await;
        let Decision::Deny { challenge, .. } = decision else {
            panic!("expected denial once the free tier was spent");
        };
        assert_eq!(challenge.x402_version, X402_VERSION);
        assert_eq!(challenge.accepts.len(), 1);
        // The challenge must advertise terms the client can actually act on.
        assert_eq!(challenge.accepts[0].pay_to, "0xmerchant");
        assert_eq!(challenge.accepts[0].network, "sui:testnet");
        // v2: the resource is a top-level object carrying a FULL url, not a
        // path repeated inside every accepts[] entry.
        assert_eq!(challenge.resource.url, RESOURCE_URL);
    }

    #[tokio::test]
    async fn payment_unlocks_the_paid_tier_and_mints_a_session() {
        // Free tier is zero, so success can only come from the payment path.
        let a = auth(0, 10);
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);

        let decision = a
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await;
        let Decision::Allow {
            tier,
            payer,
            session_token,
            settlement,
            ..
        } = decision
        else {
            panic!("payment should have been accepted");
        };
        assert_eq!(tier, Tier::Paid);
        assert!(payer.is_some(), "a payer should be recovered");
        assert!(session_token.is_some(), "a session token should be issued");
        assert!(settlement.unwrap().payer.is_some());
    }

    #[tokio::test]
    async fn issued_session_token_is_accepted_on_the_next_request() {
        let a = auth(0, 10);
        let pay_map = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);
        let Decision::Allow {
            session_token: Some(token),
            ..
        } = a
            .decide(
                &HeaderView::new(Some(&pay_map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected a session token");
        };

        // Second request presents only the session token — no payment.
        let session_map = headers(&[(HEADER_PAYMENT_SESSION, &token)]);
        let decision = a
            .decide(
                &HeaderView::new(Some(&session_map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
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
            .decide(
                &HeaderView::new(Some(&pay_map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected a session token");
        };

        let session_map = headers(&[(HEADER_PAYMENT_SESSION, &token)]);
        let view = HeaderView::new(Some(&session_map));

        // Spend the single paid request.
        assert!(matches!(
            a.decide(
                &view,
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate
            )
            .await,
            Decision::Allow {
                tier: Tier::Paid,
                ..
            }
        ));
        // Quota gone: degrade to free rather than erroring.
        assert!(matches!(
            a.decide(
                &view,
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate
            )
            .await,
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
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
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
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await;

        let Decision::Deny { challenge, .. } = decision else {
            panic!("malformed payment should be denied, not silently demoted");
        };
        let err = challenge.error.unwrap_or_default();
        assert!(err.contains("malformed"), "{err}");
    }

    #[tokio::test]
    async fn payment_for_the_wrong_network_is_denied() {
        let a = auth(5, 10);
        let wrong = payment_header_with(|p| p.accepted.network = "sui:mainnet".into());
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &wrong)]);

        let Decision::Deny { challenge, .. } = a
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("cross-network payment must be denied");
        };
        let err = challenge.error.unwrap_or_default();
        assert!(err.contains("network"), "{err}");
    }

    #[tokio::test]
    async fn a_session_bought_on_one_policy_does_not_unlock_another() {
        // The pricing bypass this closes: policies price routes differently,
        // so an unscoped session lets you pay the cheap route's price and use
        // the expensive route.
        let a = auth(0, 10);
        let pay = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);
        let Decision::Allow {
            session_token: Some(token),
            ..
        } = a
            .decide(
                &HeaderView::new(Some(&pay)),
                ip(),
                PATH,
                Some("cheap"),
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected a session token");
        };

        let map = headers(&[(HEADER_PAYMENT_SESSION, &token)]);
        let view = HeaderView::new(Some(&map));

        // Works on the policy it was bought for.
        assert!(matches!(
            a.decide(
                &view,
                ip(),
                PATH,
                Some("cheap"),
                RESOURCE_URL,
                SettlePolicy::Immediate
            )
            .await,
            Decision::Allow {
                tier: Tier::Paid,
                ..
            }
        ));
        // Not on a different one — falls through to the (exhausted) free tier.
        assert!(
            matches!(
                a.decide(
                    &view,
                    ip(),
                    PATH,
                    Some("expensive"),
                    RESOURCE_URL,
                    SettlePolicy::Immediate
                )
                .await,
                Decision::Deny { .. }
            ),
            "a session must not cross policies"
        );
    }

    #[tokio::test]
    async fn the_same_payment_cannot_mint_two_sessions() {
        // The hole this closes: in stub mode nothing ever settles, so without a
        // replay cache one PAYMENT-SIGNATURE was worth unlimited sessions.
        let a = auth(0, 10);
        let header = payment_header();
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &header)]);
        let view = HeaderView::new(Some(&map));

        assert!(
            matches!(
                a.decide(
                    &view,
                    ip(),
                    PATH,
                    None,
                    RESOURCE_URL,
                    SettlePolicy::Immediate
                )
                .await,
                Decision::Allow {
                    tier: Tier::Paid,
                    ..
                }
            ),
            "first use should be accepted"
        );

        let Decision::Deny { receipt, .. } = a
            .decide(
                &view,
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("replaying the same payment must be refused");
        };
        assert_eq!(
            receipt.unwrap().error_reason.as_deref(),
            Some("invalid_transaction_state")
        );
    }

    #[test]
    fn the_replay_claim_outlives_the_advertised_window() {
        // If the claim lapsed exactly when the window did, the authorization
        // would become replayable at the same instant it expired.
        assert!(replay_ttl(60) > 60);
        // And a very short advertised timeout must not produce a useless TTL.
        assert!(replay_ttl(1) >= 300);
        assert!(replay_ttl(0) >= 300);
    }

    #[tokio::test]
    async fn a_different_payment_is_not_treated_as_a_replay() {
        let a = auth(0, 10);
        let first = payment_header();
        let second = payment_header_with(|p| {
            p.payload = serde_json::json!({ "signature": "c2ln", "transaction": "b3RoZXI=" });
        });

        for header in [&first, &second] {
            let map = headers(&[(HEADER_PAYMENT_SIGNATURE, header)]);
            assert!(
                matches!(
                    a.decide(
                        &HeaderView::new(Some(&map)),
                        ip(),
                        PATH,
                        None,
                        RESOURCE_URL,
                        SettlePolicy::Immediate
                    )
                    .await,
                    Decision::Allow {
                        tier: Tier::Paid,
                        ..
                    }
                ),
                "distinct transactions are distinct payments"
            );
        }
    }

    #[tokio::test]
    async fn a_rejected_payment_is_distinguishable_from_never_having_paid() {
        // The single most client-hostile thing about the old behavior: both
        // arrived as a bare 402 with only a challenge.
        let a = auth(0, 10);

        // Never paid: challenge only, no receipt.
        let none = headers(&[]);
        let Decision::Deny { receipt, .. } = a
            .decide(
                &HeaderView::new(Some(&none)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected denial");
        };
        assert!(
            receipt.is_none(),
            "no payment was attempted, so there is no settlement outcome to report"
        );

        // Paid, but with tampered terms: challenge AND a failure receipt.
        let bad = payment_header_with(|p| p.accepted.amount = "1".into());
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &bad)]);
        let Decision::Deny { receipt, .. } = a
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected denial");
        };
        let receipt = receipt.expect("an attempted payment must report its outcome");
        assert!(!receipt.success);
        assert_eq!(
            receipt.error_reason.as_deref(),
            Some("invalid_payment_requirements"),
            "errorReason must be a machine-readable §9 code, not prose"
        );
        assert_eq!(receipt.transaction, "", "a failed payment has no digest");
    }

    #[tokio::test]
    async fn a_malformed_payment_still_reports_an_outcome() {
        let a = auth(0, 10);
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, "!!!not-base64!!!")]);
        let Decision::Deny { receipt, .. } = a
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected denial");
        };
        assert_eq!(
            receipt.unwrap().error_reason.as_deref(),
            Some("invalid_payload")
        );
    }

    #[test]
    fn denial_with_a_receipt_carries_payment_response() {
        let challenge = PaymentRequired::new("nope", test_resource(), vec![]);
        let receipt = SettlementResponse {
            success: false,
            error_reason: Some("invalid_payload".into()),
            payer: None,
            transaction: String::new(),
            network: "sui:testnet".into(),
            amount: None,
            extensions: None,
        };
        let response = decision_to_response(
            Decision::Deny {
                challenge,
                receipt: Some(receipt),
            },
            ip(),
            false,
        );
        let Some(HttpResponse::DeniedResponse(denied)) = response.http_response else {
            panic!("expected a denied response");
        };
        let names: Vec<&str> = denied
            .headers
            .iter()
            .map(|h| h.header.as_ref().unwrap().key.as_str())
            .collect();
        assert!(names.contains(&HEADER_PAYMENT_RESPONSE), "{names:?}");
        assert!(names.contains(&HEADER_PAYMENT_REQUIRED), "{names:?}");
    }

    #[tokio::test]
    async fn the_challenge_advertises_the_session_extension() {
        let a = auth(0, 10);
        let map = headers(&[]);
        let Decision::Deny { challenge, .. } = a
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected denial");
        };
        let ext = challenge.extensions.expect("sessions must be advertised");
        let entry = &ext[SESSION_EXTENSION];
        // §5.1.2 requires both an `info` and a `schema` per extension.
        assert!(entry["info"].is_object(), "missing info: {entry}");
        assert!(entry["schema"].is_object(), "missing schema: {entry}");
        assert_eq!(
            entry["info"]["header"],
            serde_json::json!(HEADER_PAYMENT_SESSION)
        );
        assert_eq!(entry["info"]["quota"], serde_json::json!(10));
    }

    #[tokio::test]
    async fn a_settled_payment_returns_the_session_through_extensions() {
        let a = auth(0, 10);
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);
        let Decision::Allow {
            settlement,
            session_token,
            ..
        } = a
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("payment should have been accepted");
        };
        let token = session_token.expect("a session should be issued");
        let ext = settlement
            .expect("a settled payment has a receipt")
            .extensions
            .expect("the receipt should carry the session grant");
        assert_eq!(
            ext[SESSION_EXTENSION]["info"]["token"],
            serde_json::json!(token)
        );
    }

    #[tokio::test]
    async fn a_session_echoed_through_extensions_is_honored() {
        // The spec-sanctioned route: the client echoes the extension rather
        // than relying on the proprietary raw header.
        let a = auth(0, 10);
        let pay = headers(&[(HEADER_PAYMENT_SIGNATURE, &payment_header())]);
        let Decision::Allow {
            session_token: Some(token),
            ..
        } = a
            .decide(
                &HeaderView::new(Some(&pay)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
            .await
        else {
            panic!("expected a session token");
        };

        // Second request: a payload carrying ONLY the echoed session extension.
        let echoed = payment_header_with(|p| {
            p.extensions = Some(x402::session_extension_grant(&token, 10, 3600));
        });
        let map = headers(&[(HEADER_PAYMENT_SIGNATURE, &echoed)]);
        let decision = a
            .decide(
                &HeaderView::new(Some(&map)),
                ip(),
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
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
            "the echoed session should be spent, not charged again: {decision:?}"
        );
    }

    #[tokio::test]
    async fn missing_client_address_fails_closed() {
        let a = auth(100, 10);
        let map = headers(&[]);
        let decision = a
            .decide(
                &HeaderView::new(Some(&map)),
                None,
                PATH,
                None,
                RESOURCE_URL,
                SettlePolicy::Immediate,
            )
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
            pending: None,
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
            pending: None,
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
                error_reason: None,
                payer: Some(PAYER.into()),
                transaction: "0xdigest".into(),
                network: "sui:testnet".into(),
                amount: Some("1000".into()),
                extensions: None,
            }),
            pending: None,
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
        let challenge = PaymentRequired::new("nope", test_resource(), vec![]);
        let response = decision_to_response(
            Decision::Deny {
                challenge,
                receipt: None,
            },
            ip(),
            false,
        );

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
        let challenge = PaymentRequired::new("free tier exhausted", test_resource(), vec![]);
        let response = decision_to_response(
            Decision::Deny {
                challenge,
                receipt: None,
            },
            ip(),
            true,
        );

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
        let challenge = PaymentRequired::new("nope", test_resource(), vec![]);
        let response = decision_to_response(
            Decision::Deny {
                challenge,
                receipt: None,
            },
            ip(),
            false,
        );
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

        // Suffixed variants are still gRPC and must get gRPC-shaped denials.
        for ct in [
            "application/grpc+proto",
            // grpc-web is what browsers actually use — they cannot speak native
            // gRPC. The prefix match covers it deliberately.
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/grpc-web-text",
        ] {
            let h = headers(&[("content-type", ct)]);
            assert!(
                is_grpc_request(&HeaderView::new(Some(&h))),
                "{ct} should be treated as gRPC"
            );
        }

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
                pending: None,
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
