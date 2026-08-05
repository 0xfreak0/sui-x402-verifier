//! Envoy `ext_proc` service — the spec-correct settlement ordering.
//!
//! # Why this exists alongside `ext_authz`
//!
//! `scheme_exact_sui.md` sequences the flow as **verify → the resource server
//! does the work → settle**, so a client is only charged once the resource has
//! actually been produced.
//!
//! `ext_authz` cannot do that. It is a *pre-upstream* filter: it runs on the
//! request path, never sees the response, and must answer allow/deny before
//! Envoy proxies anything. Settling there charges a client even when the
//! upstream then returns a 500.
//!
//! `ext_proc` can. Envoy opens **one bidirectional gRPC stream per HTTP
//! request** and sends the request headers, then later the response headers, on
//! that same stream. So this service can verify on the way in, hold the
//! verified-but-unsettled payment as ordinary stream-local state, and settle on
//! the way out — but only after seeing a successful status.
//!
//! ```text
//!   request headers  ──▶ verify payment, do NOT charge ──▶ CONTINUE
//!                            (or ImmediateResponse 402)
//!   upstream serves the request
//!   response headers ──▶ 2xx? settle now, attach receipt + session
//!                        5xx? discard; the client is never charged
//! ```
//!
//! # The residual risk, stated plainly
//!
//! Deferring settlement moves the failure, it does not remove it. If the
//! upstream succeeds but settlement then fails, the resource has already been
//! delivered unpaid. That is the opposite exposure to `ext_authz`'s, and it is
//! the better one to carry: it costs the operator a request rather than
//! charging a user for something they did not receive.

use std::net::IpAddr;
use std::sync::Arc;

use envoy_types::pb::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    CommonResponse, HeaderMutation, HeadersResponse, ImmediateResponse, ProcessingRequest,
    ProcessingResponse, external_processor_server::ExternalProcessor, processing_request,
    processing_response,
};
use envoy_types::pb::envoy::r#type::v3::{HttpStatus, StatusCode as HttpStatusCode};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::auth::{
    AppState, Decision, HEADER_PAYER, HEADER_TIER, HeaderView, Meter, PendingPayment, SettlePolicy,
};
use crate::metrics as m;
use crate::x402::{self, HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SESSION};

/// Envoy `ext_proc` implementation.
#[derive(Debug, Clone)]
pub struct X402ExtProc {
    state: Arc<AppState>,
}

impl X402ExtProc {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

/// Everything the response phase needs from the request phase.
///
/// Lives for exactly one HTTP request because Envoy gives each request its own
/// stream — no shared map, no correlation id, no eviction policy.
#[derive(Debug, Default)]
struct StreamState {
    pending: Option<Box<PendingPayment>>,
    /// Policy the request phase resolved, so the session minted on the response
    /// path is scoped to what was actually paid for.
    policy: Option<String>,
    /// Request path, kept so the response phase can re-resolve the same policy
    /// and mint a session with that policy's quota rather than the global one.
    path: String,
    /// What the request phase measured. Emitted on the response so the client
    /// sees its own meter; a settlement on the response path replaces it.
    meter: Meter,
    /// How long the request-phase decision took, in milliseconds.
    ///
    /// Reported back as `Server-Timing`. The gateway is the only party that
    /// knows how much of a request's latency it was responsible for, so
    /// without this a client can only measure the total and guess.
    decide_ms: f64,
}

/// Standard header for server-side phase timings, readable in browser devtools.
const HEADER_SERVER_TIMING: &str = "server-timing";

/// Format phase timings as a `Server-Timing` value.
fn server_timing(phases: &[(&str, f64)]) -> String {
    phases
        .iter()
        .map(|(name, ms)| format!("{name};dur={ms:.1}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Build a `HeaderValueOption` for a mutation.
///
/// **Security critical: OVERWRITE, never append.** These headers are what a
/// backend (or a ratelimit filter keying on descriptors) trusts to say who the
/// caller is. Appending leaves a client-supplied `x-x402-tier: paid` in place
/// alongside ours, which is self-promotion into the paid tier. The ext_authz
/// path has always overwritten; this path did not, and it is the default.
fn header(key: &str, value: impl Into<String>) -> HeaderValueOption {
    const OVERWRITE_IF_EXISTS_OR_ADD: i32 = 2;
    #[allow(deprecated)]
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_string(),
            value: String::new(),
            // ext_proc prefers raw_value; setting both is an error.
            raw_value: value.into().into_bytes(),
        }),
        append: None,
        append_action: OVERWRITE_IF_EXISTS_OR_ADD,
        keep_empty_value: false,
    }
}

/// A `CONTINUE` response for a headers phase, optionally mutating headers.
fn continue_with(headers: Vec<HeaderValueOption>) -> HeadersResponse {
    continue_with_removals(headers, Vec::new())
}

/// As [`continue_with`], also removing headers before the request continues.
fn continue_with_removals(headers: Vec<HeaderValueOption>, remove: Vec<String>) -> HeadersResponse {
    let mutate = !headers.is_empty() || !remove.is_empty();
    HeadersResponse {
        response: Some(CommonResponse {
            header_mutation: mutate.then_some(HeaderMutation {
                set_headers: headers,
                remove_headers: remove,
            }),
            ..Default::default()
        }),
    }
}

/// Extract the request headers Envoy sent as a lookup map.
fn header_map(
    headers: Option<&envoy_types::pb::envoy::config::core::v3::HeaderMap>,
) -> std::collections::HashMap<String, String> {
    headers
        .map(|map| {
            map.headers
                .iter()
                .map(|h| {
                    // Envoy sends the value in `raw_value` on this path.
                    let value = if h.raw_value.is_empty() {
                        h.value.clone()
                    } else {
                        String::from_utf8_lossy(&h.raw_value).into_owned()
                    };
                    (h.key.to_ascii_lowercase(), value)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Refuse a payment because settlement is currently failing.
///
/// 503 rather than 402: a 402 invites the client to pay again, and the problem
/// is that we cannot take their money right now. `Retry-After` gives them
/// something better to do than hammer it.
fn settlement_unavailable(path: &str) -> ProcessingResponse {
    let grpc = path.starts_with("/sui.rpc.v2.") || path.starts_with("/grpc.");
    let body = serde_json::json!({
        "error": "settlement_unavailable",
        "message": "Payments are temporarily refused because settlement is failing. \
                    The free tier is unaffected. Try again shortly.",
    });

    let mut headers = vec![
        header("retry-after", "30"),
        header(
            "content-type",
            if grpc {
                "application/grpc"
            } else {
                "application/json"
            },
        ),
    ];
    if grpc {
        // 14 UNAVAILABLE is the gRPC status a client will retry on.
        headers.push(header("grpc-status", "14"));
        headers.push(header("grpc-message", "settlement%20unavailable"));
    }

    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus {
                    // A gRPC denial is a trailers-only 200; see auth.rs.
                    code: if grpc {
                        HttpStatusCode::Ok as i32
                    } else {
                        HttpStatusCode::ServiceUnavailable as i32
                    },
                }),
                headers: Some(HeaderMutation {
                    set_headers: headers,
                    remove_headers: Vec::new(),
                }),
                body: serde_json::to_vec(&body).unwrap_or_default(),
                grpc_status: None,
                details: String::new(),
            },
        )),
        ..Default::default()
    }
}

/// How long a gRPC stream may run, expressed as a `grpc-timeout` value.
///
/// Streaming is sold by duration: a payment buys a window, and the stream must
/// end when the window does. Envoy already enforces this if the request carries
/// `grpc-timeout`, so no new machinery is needed — the gateway simply has to be
/// the one that sets it.
///
/// **Overwritten, never appended.** `grpc-timeout` is an ordinary request header
/// a client can send, so honouring the client's value would let anyone grant
/// themselves an arbitrarily long stream. Same reasoning as [`HEADER_TIER`].
///
/// Only the paid tier gets one. A free-tier stream is bounded by the route's own
/// timeout, and a `None` here leaves that untouched rather than silently
/// shortening it.
///
/// The route should also set `max_stream_duration.grpc_timeout_header_max` as a
/// ceiling; this value is what the payment bought, that is what the operator is
/// willing to sell.
fn grpc_timeout_for(meter: &Meter, view: &HeaderView<'_>) -> Option<String> {
    let Meter::Session {
        expires_in_secs, ..
    } = meter
    else {
        return None;
    };
    if !view
        .get("content-type")
        .is_some_and(|ct| ct.starts_with("application/grpc"))
    {
        return None;
    }
    // gRPC durations are `<value><unit>`; `S` is seconds. A session with no
    // time left should not open a stream at all, so clamp to at least one
    // second and let the session check refuse the next request.
    Some(format!("{}S", (*expires_in_secs).max(1)))
}

/// Build the absolute URL of the requested resource, as the client addresses it.
///
/// `:authority` is the host Envoy was *reached* on, which behind a reverse proxy
/// is an internal address — deployed, that produced challenges advertising
/// `https://127.0.0.1:10000/graphql`, a resource no client can reach. §5.1.2
/// requires a complete URL, and a wrong one is worse than a path.
///
/// So prefer what the edge proxy recorded about the original request.
/// `x-forwarded-host` and `x-forwarded-proto` are set by Caddy and, like
/// `x-forwarded-for`, are only trustworthy because the edge replaces rather than
/// appends them. With no proxy in front, neither header exists and `:authority`
/// is the right answer.
fn resource_url(map: &std::collections::HashMap<String, String>, path: &str) -> String {
    let authority = map
        .get("x-forwarded-host")
        .or_else(|| map.get(":authority"))
        .cloned()
        .unwrap_or_default();

    if authority.is_empty() {
        return path.to_string();
    }

    // https is the safer assumption for a public gateway than downgrading.
    let scheme = map
        .get("x-forwarded-proto")
        .or_else(|| map.get(":scheme"))
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "https".to_string());

    format!("{scheme}://{authority}{path}")
}

/// Pull the peer IP out of Envoy's requested attributes.
///
/// Envoy groups these by the *filter name*, storing the full dotted CEL path as
/// a single flat field key — verified against Envoy 1.39:
///
/// ```text
/// attributes["envoy.filters.http.ext_proc"].fields["source.address"] = "127.0.0.1:59118"
/// ```
///
/// This is the **only** accepted source for the client address. In particular
/// `x-forwarded-for` is deliberately NOT consulted: it is attacker-controlled,
/// so honouring it would let any client rotate the header and bypass the
/// free-tier limit outright. `source.address` comes from the real TCP peer and
/// cannot be forged by the client.
///
/// If Envoy itself sits behind another proxy, configure `use_remote_address`
/// and `xff_num_trusted_hops` on the HTTP connection manager so Envoy resolves
/// the true peer *before* it computes this attribute — that keeps the trust
/// decision in the proxy, where it belongs, rather than in this service.
///
/// Returns `None` if absent or malformed; `decide` then fails closed rather
/// than serving an unmeterable request.
fn client_ip_from_attributes(
    attributes: &std::collections::HashMap<String, envoy_types::pb::google::protobuf::Struct>,
) -> Option<IpAddr> {
    use envoy_types::pb::google::protobuf::value::Kind;

    let address = attributes.values().find_map(|s| {
        match s.fields.get("source.address").and_then(|v| v.kind.as_ref()) {
            Some(Kind::StringValue(address)) => Some(address.clone()),
            _ => None,
        }
    })?;

    parse_host(&address)
}

/// Split `host:port` and parse the host. Splits from the right because IPv6
/// hosts contain colons, and strips the brackets IPv6 arrives with.
fn parse_host(address: &str) -> Option<IpAddr> {
    let host = address.rsplit_once(':').map(|(h, _)| h).unwrap_or(address);
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

/// Extract the x402 policy name Envoy attached to the matched route.
///
/// `ext_authz` has `context_extensions` for exactly this; `ext_proc` does not —
/// `ExtProcPerRoute` can only override the processing mode, and its
/// `request_attributes` override is marked not-implemented upstream. The
/// available channel is route metadata, requested as the `xds.route_metadata`
/// attribute.
///
/// Envoy delivers it as a protobuf **TextFormat string**, not a structured
/// value, so it has to be parsed:
///
/// ```text
/// filter_metadata { key: "envoy.filters.http.ext_proc" value {
///   fields { key: "x402_policy" value { string_value: "graphql" } } } }
/// ```
///
/// Returning `None` falls back to the default payment terms, which is safe (the
/// resource is still paid for) but may under-price a route, so the caller logs
/// when a policy was expected. Getting this wrong is not hypothetical: this
/// function exists because per-route pricing silently regressed to the base
/// price when ext_proc replaced ext_authz as the default filter.
fn policy_from_attributes(
    attributes: &std::collections::HashMap<String, envoy_types::pb::google::protobuf::Struct>,
) -> Option<String> {
    use envoy_types::pb::google::protobuf::value::Kind;

    let metadata = attributes.values().find_map(|s| {
        match s
            .fields
            .get("xds.route_metadata")
            .and_then(|v| v.kind.as_ref())
        {
            Some(Kind::StringValue(text)) => Some(text.as_str()),
            _ => None,
        }
    })?;

    parse_policy_from_text_format(metadata)
}

/// Pull `x402_policy`'s string value out of Envoy's TextFormat metadata dump.
///
/// Deliberately narrow: it looks for the `x402_policy` key and takes the next
/// `string_value`, rather than attempting to parse TextFormat in general.
fn parse_policy_from_text_format(text: &str) -> Option<String> {
    let after_key = text.split("key: \"x402_policy\"").nth(1)?;
    let after_marker = after_key.split("string_value:").nth(1)?;
    let opening = after_marker.find('"')? + 1;
    let rest = &after_marker[opening..];
    let closing = rest.find('"')?;
    let value = &rest[..closing];
    (!value.is_empty()).then(|| value.to_string())
}

/// Was the upstream response a success?
///
/// Only a 2xx justifies charging: the client got what they paid for. Anything
/// else — including a 4xx the upstream produced — means the resource was not
/// delivered, so the payment is discarded unsettled.
fn is_success(status: &str) -> bool {
    status
        .parse::<u16>()
        .map(|code| (200..300).contains(&code))
        .unwrap_or(false)
}

#[tonic::async_trait]
impl ExternalProcessor for X402ExtProc {
    type ProcessStream = ReceiverStream<Result<ProcessingResponse, Status>>;

    async fn process(
        &self,
        request: Request<Streaming<ProcessingRequest>>,
    ) -> Result<Response<Self::ProcessStream>, Status> {
        let mut inbound = request.into_inner();
        let state = Arc::clone(&self.state);
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            // Stream-local, so it is inherently scoped to this one HTTP request.
            let mut stream_state = StreamState::default();

            while let Ok(Some(message)) = inbound.message().await {
                // Attributes ride on the ProcessingRequest, not on the header
                // message, so capture them before matching.
                let client_ip = client_ip_from_attributes(&message.attributes);
                let policy = policy_from_attributes(&message.attributes);

                let reply = match message.request {
                    Some(processing_request::Request::RequestHeaders(headers)) => {
                        handle_request_headers(
                            &state,
                            &mut stream_state,
                            headers,
                            client_ip,
                            policy.clone(),
                        )
                        .await
                    }
                    Some(processing_request::Request::ResponseHeaders(headers)) => {
                        handle_response_headers(&state, &mut stream_state, headers).await
                    }
                    // Any other phase (bodies, trailers) is not configured for
                    // this filter; acknowledge so the stream keeps moving.
                    _ => ProcessingResponse::default(),
                };

                if tx.send(Ok(reply)).await.is_err() {
                    // Envoy hung up — the client disconnected mid-request.
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Request phase: decide the tier, and verify (but do not charge) any payment.
async fn handle_request_headers(
    state: &Arc<AppState>,
    stream_state: &mut StreamState,
    headers: envoy_types::pb::envoy::service::ext_proc::v3::HttpHeaders,
    client_ip: Option<IpAddr>,
    policy: Option<String>,
) -> ProcessingResponse {
    let map = header_map(headers.headers.as_ref());
    let view = HeaderView::new(Some(&map));

    // ext_proc delivers pseudo-headers in the same map as ordinary ones.
    let path = map.get(":path").cloned().unwrap_or_default();
    let resource_url = resource_url(&map, &path);

    // Check before verifying: accepting a payment we cannot settle means
    // serving the resource and never being paid for it. The free tier is
    // deliberately left alone — an outage should degrade the paid tier, not
    // take the whole gateway down.
    let breaker_policy = policy
        .clone()
        .unwrap_or_else(|| crate::config::DEFAULT_POLICY_LABEL.to_string());
    let breaker = state.breaker.state(&breaker_policy);
    if !breaker.accepts_payment() && view.get(x402::HEADER_PAYMENT_SIGNATURE).is_some() {
        // The state is the label so an operator can tell a tripped breaker
        // from a half-open probe that lost the race, which look identical from
        // the client's side.
        metrics::counter!(
            m::PAYMENTS,
            "outcome" => "breaker_open",
            "code" => breaker.as_str(),
            "mode" => "deferred",
        )
        .increment(1);
        tracing::warn!(
            policy = %breaker_policy,
            "refusing a payment: the settlement circuit breaker is open"
        );
        return settlement_unavailable(&path);
    }

    let started = std::time::Instant::now();
    let decision = X402Decider { state }
        .decide(&view, client_ip, &path, policy.as_deref(), &resource_url)
        .await;
    // Covers everything the gateway does before the upstream is touched:
    // session lookup or free-tier check, and for a payment, on-chain
    // verification against the fullnode.
    let decide_ms = started.elapsed().as_secs_f64() * 1000.0;

    match decision {
        Decision::Allow {
            tier,
            payer,
            pending,
            meter,
            ..
        } => {
            // Hold the verified payment for the response phase.
            stream_state.pending = pending;
            stream_state.policy = policy;
            stream_state.path = path.clone();
            stream_state.meter = meter;
            stream_state.decide_ms = decide_ms;

            let mut mutations = vec![header(HEADER_TIER, tier.as_str())];
            if let Some(payer) = payer {
                mutations.push(header(HEADER_PAYER, payer));
            }
            // Bound a stream to what was actually paid for.
            if let Some(timeout) = grpc_timeout_for(&meter, &view) {
                tracing::debug!(%timeout, "bounding the stream to the paid window");
                mutations.push(header("grpc-timeout", timeout));
            }

            ProcessingResponse {
                response: Some(processing_response::Response::RequestHeaders(
                    // The client's payment credentials have served their
                    // purpose; the upstream has no business seeing them.
                    continue_with_removals(
                        mutations,
                        vec![
                            x402::HEADER_PAYMENT_SIGNATURE.to_string(),
                            HEADER_PAYMENT_SESSION.to_string(),
                        ],
                    ),
                )),
                ..Default::default()
            }
        }
        Decision::Deny {
            challenge,
            receipt,
            meter,
        } => {
            let mut headers = Vec::new();
            if let Ok(encoded) = x402::encode_header(&challenge) {
                headers.push(header(HEADER_PAYMENT_REQUIRED, encoded));
            }
            if let Some(receipt) = &receipt
                && let Ok(encoded) = x402::encode_header(receipt)
            {
                headers.push(header(HEADER_PAYMENT_RESPONSE, encoded));
            }
            // The 402 carries the meter too: the useful part of "you are out"
            // is when it comes back.
            for (name, value) in meter.headers() {
                headers.push(header(name, value));
            }
            // A challenge short-circuits the upstream, so this is the only
            // chance to report what the decision cost.
            headers.push(header(
                HEADER_SERVER_TIMING,
                server_timing(&[("x402-decide", decide_ms)]),
            ));
            headers.push(header("content-type", "application/json"));

            ProcessingResponse {
                response: Some(processing_response::Response::ImmediateResponse(
                    ImmediateResponse {
                        status: Some(HttpStatus {
                            code: HttpStatusCode::PaymentRequired as i32,
                        }),
                        headers: Some(HeaderMutation {
                            set_headers: headers,
                            remove_headers: Vec::new(),
                        }),
                        body: serde_json::to_vec(&challenge).unwrap_or_default(),
                        grpc_status: None,
                        details: String::new(),
                    },
                )),
                ..Default::default()
            }
        }
    }
}

/// Response phase: settle, but only if the upstream actually delivered.
async fn handle_response_headers(
    state: &Arc<AppState>,
    stream_state: &mut StreamState,
    headers: envoy_types::pb::envoy::service::ext_proc::v3::HttpHeaders,
) -> ProcessingResponse {
    // Whatever the request phase measured travels back to the client. Only a
    // settlement below can supersede it.
    let meter_headers: Vec<_> = stream_state
        .meter
        .headers()
        .into_iter()
        .map(|(name, value)| header(name, value))
        .collect();

    let Some(pending) = stream_state.pending.take() else {
        // Nothing was paid on this request (free tier or an existing session).
        let mut headers = meter_headers;
        headers.push(header(
            HEADER_SERVER_TIMING,
            server_timing(&[("x402-decide", stream_state.decide_ms)]),
        ));
        return ProcessingResponse {
            response: Some(processing_response::Response::ResponseHeaders(
                continue_with(headers),
            )),
            ..Default::default()
        };
    };

    let map = header_map(headers.headers.as_ref());
    let status = map.get(":status").cloned().unwrap_or_default();

    if !is_success(&status) {
        // This is the entire point of ext_proc: the upstream failed, so the
        // verified payment is discarded and the client is never charged.
        tracing::info!(
            %status,
            "upstream did not succeed; discarding the verified payment unsettled"
        );
        // The authorization was verified but never spent, so free it up: the
        // client can retry with the same signed transaction instead of having
        // to produce a new one for a failure that was not theirs.
        if let Some(id) = &pending.payment_id {
            state.sessions.release_payment(id).await;
        }
        let mut headers = meter_headers;
        headers.push(header(
            HEADER_SERVER_TIMING,
            server_timing(&[("x402-decide", stream_state.decide_ms)]),
        ));
        return ProcessingResponse {
            response: Some(processing_response::Response::ResponseHeaders(
                continue_with(headers),
            )),
            ..Default::default()
        };
    }

    let mut mutations = meter_headers;

    // Re-resolve the policy so the session is minted with the tier this route
    // sells, not the global default.
    let resolved = state
        .config
        .policy_for(&stream_state.path, stream_state.policy.as_deref());

    let started = std::time::Instant::now();
    let settled = state
        .facilitator
        .settle(&pending.payload, &pending.requirements)
        .await;
    let settle_ms = started.elapsed().as_secs_f64() * 1000.0;
    metrics::histogram!(m::SETTLEMENT_SECONDS).record(started.elapsed().as_secs_f64());

    // Both phases, so a client can see how the gateway's share of its latency
    // splits between verifying on the way in and broadcasting on the way out.
    mutations.push(header(
        HEADER_SERVER_TIMING,
        server_timing(&[
            ("x402-decide", stream_state.decide_ms),
            ("x402-settle", settle_ms),
        ]),
    ));

    let policy_label = stream_state
        .policy
        .clone()
        .unwrap_or_else(|| crate::config::DEFAULT_POLICY_LABEL.to_string());

    match settled {
        Ok(mut settlement) => {
            state.breaker.record_success(&policy_label);
            let token = match &settlement.payer {
                None => None,
                Some(payer) => state
                    .sessions
                    .create_session(
                        payer,
                        stream_state.policy.as_deref(),
                        resolved.paid_tier.quota,
                        resolved.paid_tier.duration_secs,
                    )
                    .await
                    .ok(),
            };
            metrics::counter!(m::PAYMENTS, "outcome" => "settled", "code" => "ok", "mode" => "deferred")
                .increment(1);
            if token.is_some() {
                metrics::counter!(m::SESSIONS, "event" => "created").increment(1);
            }
            if let Some(token) = &token {
                settlement.extensions = Some(x402::session_extension_grant(
                    token,
                    resolved.paid_tier.quota,
                    resolved.paid_tier.duration_secs,
                ));
                mutations.push(header(HEADER_PAYMENT_SESSION, token.clone()));

                // A payment just bought a session, so the free-tier meter the
                // request phase measured is no longer what this client is
                // spending against. Replace it wholesale.
                mutations.retain(|h| {
                    !h.header
                        .as_ref()
                        .is_some_and(|h| h.key.starts_with("x-x402-free-"))
                });
                let fresh = Meter::Session {
                    remaining: resolved.paid_tier.quota,
                    quota: resolved.paid_tier.quota,
                    expires_in_secs: resolved.paid_tier.duration_secs,
                };
                for (name, value) in fresh.headers() {
                    mutations.push(header(name, value));
                }
            }

            tracing::info!(
                payer = settlement.payer.as_deref().unwrap_or("<unknown>"),
                transaction = %settlement.transaction,
                "payment settled after the upstream succeeded"
            );

            if let Ok(encoded) = x402::encode_header(&settlement) {
                mutations.push(header(HEADER_PAYMENT_RESPONSE, encoded));
            }
        }
        Err(e) => {
            // The resource has already been delivered. We cannot un-serve it,
            // so the operator eats this one — which is the better failure than
            // charging for something the client never received.
            // The alert-worthy counter: revenue is being lost right now.
            // Feeds the breaker. One of these is noise; a run of them means
            // the gateway is giving the resource away and must stop taking
            // payments it cannot settle.
            state.breaker.record_failure(&policy_label);
            metrics::counter!(m::SETTLEMENT_AFTER_SERVE_FAILURES, "code" => e.code()).increment(1);
            metrics::counter!(
                m::PAYMENTS,
                "outcome" => "settle_failed_after_serve",
                "code" => e.code(),
                "mode" => "deferred",
            )
            .increment(1);
            tracing::error!(
                error = %e,
                code = e.code(),
                "SETTLEMENT FAILED AFTER THE RESOURCE WAS SERVED; this request was not paid for"
            );
            let receipt = state.facilitator.failure_receipt(e.code());
            if let Ok(encoded) = x402::encode_header(&receipt) {
                mutations.push(header(HEADER_PAYMENT_RESPONSE, encoded));
            }
        }
    }

    ProcessingResponse {
        response: Some(processing_response::Response::ResponseHeaders(
            continue_with(mutations),
        )),
        ..Default::default()
    }
}

/// Thin wrapper so this module can reuse the tier policy without depending on
/// the ext_authz service type.
struct X402Decider<'a> {
    state: &'a Arc<AppState>,
}

impl X402Decider<'_> {
    async fn decide(
        &self,
        headers: &HeaderView<'_>,
        client_ip: Option<IpAddr>,
        path: &str,
        policy: Option<&str>,
        resource_url: &str,
    ) -> Decision {
        crate::auth::X402Auth::new(Arc::clone(self.state))
            .decide(
                headers,
                client_ip,
                path,
                policy,
                resource_url,
                // The whole reason this filter exists.
                SettlePolicy::Deferred,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn view_of(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        headers(pairs)
    }

    #[test]
    fn a_paid_grpc_stream_is_bounded_by_what_the_session_has_left() {
        // Streaming is sold by duration, so the stream must end when the window
        // does. Envoy enforces grpc-timeout; the gateway only has to set it.
        let map = view_of(&[("content-type", "application/grpc")]);
        let meter = Meter::Session {
            remaining: 10,
            quota: 100,
            expires_in_secs: 42,
        };
        assert_eq!(
            grpc_timeout_for(&meter, &HeaderView::new(Some(&map))),
            Some("42S".to_string())
        );
    }

    #[test]
    fn a_non_grpc_request_gets_no_timeout() {
        let map = view_of(&[("content-type", "application/json")]);
        let meter = Meter::Session {
            remaining: 10,
            quota: 100,
            expires_in_secs: 42,
        };
        assert_eq!(grpc_timeout_for(&meter, &HeaderView::new(Some(&map))), None);
    }

    #[test]
    fn a_free_tier_stream_keeps_the_routes_own_timeout() {
        // Emitting a timeout here would silently shorten a stream nobody paid
        // to extend. Leaving it absent lets the route decide.
        let map = view_of(&[("content-type", "application/grpc")]);
        let meter = Meter::Free {
            remaining: 4,
            limit: 5,
            reset_secs: 30,
        };
        assert_eq!(grpc_timeout_for(&meter, &HeaderView::new(Some(&map))), None);
    }

    #[test]
    fn an_exhausted_session_still_yields_a_positive_timeout() {
        // A zero would be rejected by Envoy as malformed. The session check
        // refuses the next request anyway, so one second is the safe floor.
        let map = view_of(&[("content-type", "application/grpc")]);
        let meter = Meter::Session {
            remaining: 0,
            quota: 100,
            expires_in_secs: 0,
        };
        assert_eq!(
            grpc_timeout_for(&meter, &HeaderView::new(Some(&map))),
            Some("1S".to_string())
        );
    }

    #[test]
    fn resource_url_prefers_what_the_edge_proxy_saw() {
        // Deployed behind Caddy, :authority is the internal address Envoy was
        // reached on. Advertising that in a challenge tells a client to pay for
        // a resource it cannot address.
        let map = headers(&[
            (":authority", "127.0.0.1:10000"),
            (":scheme", "http"),
            ("x-forwarded-host", "x402.suisonar.dev"),
            ("x-forwarded-proto", "https"),
        ]);
        assert_eq!(
            resource_url(&map, "/graphql"),
            "https://x402.suisonar.dev/graphql"
        );
    }

    #[test]
    fn resource_url_falls_back_to_authority_with_no_proxy_in_front() {
        let map = headers(&[(":authority", "localhost:10000"), (":scheme", "http")]);
        assert_eq!(
            resource_url(&map, "/graphql"),
            "http://localhost:10000/graphql"
        );
    }

    #[test]
    fn resource_url_assumes_https_when_no_scheme_is_given() {
        // Envoy leaves :scheme empty on some paths; downgrading a public
        // gateway to http in an advertised URL is the worse guess.
        let map = headers(&[(":authority", "example.com")]);
        assert_eq!(resource_url(&map, "/x"), "https://example.com/x");
    }

    #[test]
    fn resource_url_degrades_to_a_path_rather_than_a_malformed_url() {
        // "https:///graphql" merely looks like a URL. A bare path is at least
        // honestly incomplete.
        assert_eq!(resource_url(&headers(&[]), "/graphql"), "/graphql");
    }

    #[test]
    fn identity_headers_overwrite_rather_than_append() {
        // A client sending its own `x-x402-tier: paid` must have it replaced,
        // not merely accompanied by ours. This is the whole security boundary
        // for tier assertion, and ext_proc is the default filter.
        const OVERWRITE_IF_EXISTS_OR_ADD: i32 = 2;
        let h = header(HEADER_TIER, "free");
        assert_eq!(
            h.append_action, OVERWRITE_IF_EXISTS_OR_ADD,
            "appending lets a client self-promote into the paid tier"
        );
    }

    #[test]
    fn client_payment_headers_are_removed_before_the_upstream() {
        let response = continue_with_removals(
            vec![header(HEADER_TIER, "paid")],
            vec![
                x402::HEADER_PAYMENT_SIGNATURE.to_string(),
                HEADER_PAYMENT_SESSION.to_string(),
            ],
        );
        let mutation = response.response.unwrap().header_mutation.unwrap();
        assert!(
            mutation
                .remove_headers
                .contains(&x402::HEADER_PAYMENT_SIGNATURE.to_string())
        );
        assert!(
            mutation
                .remove_headers
                .contains(&HEADER_PAYMENT_SESSION.to_string())
        );
    }

    #[test]
    fn policy_is_parsed_out_of_envoy_text_format_metadata() {
        // The exact shape Envoy 1.39 sends for xds.route_metadata.
        let text = r#"filter_metadata { key: "envoy.filters.http.ext_proc" value { fields { key: "x402_policy" value { string_value: "graphql" } } } } "#;
        assert_eq!(
            parse_policy_from_text_format(text).as_deref(),
            Some("graphql")
        );

        let grpc = text.replace("graphql", "grpc");
        assert_eq!(
            parse_policy_from_text_format(&grpc).as_deref(),
            Some("grpc")
        );

        // Absent, empty, or unrelated metadata must fall back to None rather
        // than inventing a policy name.
        assert_eq!(parse_policy_from_text_format(""), None);
        assert_eq!(
            parse_policy_from_text_format(r#"filter_metadata { key: "other" }"#),
            None
        );
        assert_eq!(
            parse_policy_from_text_format(r#"key: "x402_policy" value { string_value: "" }"#),
            None
        );
    }
    #[test]
    fn only_2xx_justifies_charging() {
        assert!(is_success("200"));
        assert!(is_success("204"));
        assert!(is_success("299"));
        // A 4xx the upstream produced still means the resource was not
        // delivered, so the payment must not be taken.
        assert!(!is_success("404"));
        assert!(!is_success("500"));
        assert!(!is_success("302"));
        assert!(!is_success(""));
        assert!(!is_success("not-a-status"));
    }

    #[test]
    fn client_ip_is_read_from_the_source_address_attribute() {
        use envoy_types::pb::google::protobuf::{Struct, Value, value::Kind};

        // The shape Envoy 1.39 actually sends: keyed by filter name, with the
        // full dotted attribute path as the field key.
        let attrs = |addr: &str| {
            let mut fields = std::collections::BTreeMap::new();
            fields.insert(
                "source.address".to_string(),
                Value {
                    kind: Some(Kind::StringValue(addr.to_string())),
                },
            );
            std::collections::HashMap::from([(
                "envoy.filters.http.ext_proc".to_string(),
                Struct {
                    fields: fields.into_iter().collect(),
                },
            )])
        };

        assert_eq!(
            client_ip_from_attributes(&attrs("10.0.0.1:54321")),
            Some("10.0.0.1".parse().unwrap())
        );
        // IPv6 arrives bracketed, and its host contains colons.
        assert_eq!(
            client_ip_from_attributes(&attrs("[::1]:54321")),
            Some("::1".parse().unwrap())
        );
        // Missing or malformed must be None so the caller fails closed.
        assert_eq!(client_ip_from_attributes(&Default::default()), None);
        assert_eq!(client_ip_from_attributes(&attrs("not-an-address")), None);
    }

    #[tokio::test]
    async fn a_spoofed_x_forwarded_for_cannot_set_the_client_address() {
        // x-forwarded-for is attacker-controlled. If it were honoured, any
        // client could rotate it and bypass the free-tier limit entirely, so
        // the address must come only from Envoy's source.address attribute.
        use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
        use envoy_types::pb::envoy::service::ext_proc::v3::HttpHeaders;

        #[allow(deprecated)]
        let headers = HttpHeaders {
            headers: Some(HeaderMap {
                headers: vec![
                    HeaderValue {
                        key: ":path".into(),
                        value: "/graphql".into(),
                        raw_value: Vec::new(),
                    },
                    HeaderValue {
                        key: "x-forwarded-for".into(),
                        value: "203.0.113.9".into(),
                        raw_value: Vec::new(),
                    },
                ],
            }),
            ..Default::default()
        };

        // No attributes supplied => no client address => must fail closed,
        // regardless of what the client claimed in XFF.
        let state = crate::auth::test_support::app_state(100, 10);
        let mut stream_state = StreamState::default();
        let reply = handle_request_headers(&state, &mut stream_state, headers, None, None).await;

        assert!(
            matches!(
                reply.response,
                Some(processing_response::Response::ImmediateResponse(_))
            ),
            "an unmeterable request must be denied, not served on a spoofable header"
        );
    }

    #[test]
    fn header_map_reads_raw_values_and_lowercases_keys() {
        use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
        #[allow(deprecated)]
        let map = HeaderMap {
            headers: vec![
                HeaderValue {
                    key: "X-Payment-Session".into(),
                    value: String::new(),
                    raw_value: b"tok".to_vec(),
                },
                HeaderValue {
                    key: ":status".into(),
                    value: "200".into(),
                    raw_value: Vec::new(),
                },
            ],
        };
        let parsed = header_map(Some(&map));
        assert_eq!(
            parsed.get("x-payment-session").map(String::as_str),
            Some("tok")
        );
        assert_eq!(parsed.get(":status").map(String::as_str), Some("200"));
    }
}
