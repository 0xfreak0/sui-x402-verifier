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
    AppState, Decision, HEADER_PAYER, HEADER_TIER, HeaderView, PendingPayment, SettlePolicy,
};
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
}

/// Build a `HeaderValueOption` for a response mutation.
fn header(key: &str, value: impl Into<String>) -> HeaderValueOption {
    #[allow(deprecated)]
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_string(),
            value: String::new(),
            // ext_proc prefers raw_value; setting both is an error.
            raw_value: value.into().into_bytes(),
        }),
        append: None,
        append_action: 0, // APPEND_IF_EXISTS_OR_ADD
        keep_empty_value: false,
    }
}

/// A `CONTINUE` response for a headers phase, optionally mutating headers.
fn continue_with(headers: Vec<HeaderValueOption>) -> HeadersResponse {
    HeadersResponse {
        response: Some(CommonResponse {
            header_mutation: (!headers.is_empty()).then(|| HeaderMutation {
                set_headers: headers,
                remove_headers: Vec::new(),
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

                let reply = match message.request {
                    Some(processing_request::Request::RequestHeaders(headers)) => {
                        handle_request_headers(&state, &mut stream_state, headers, client_ip).await
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
) -> ProcessingResponse {
    let map = header_map(headers.headers.as_ref());
    let view = HeaderView::new(Some(&map));

    // ext_proc delivers pseudo-headers in the same map as ordinary ones.
    let path = map.get(":path").cloned().unwrap_or_default();
    let authority = map.get(":authority").cloned().unwrap_or_default();
    let scheme = map
        .get(":scheme")
        .cloned()
        .unwrap_or_else(|| "https".to_string());
    let resource_url = if authority.is_empty() {
        path.clone()
    } else {
        format!("{scheme}://{authority}{path}")
    };

    let policy = None; // context_extensions are an ext_authz concept.

    let decision = X402Decider { state }
        .decide(&view, client_ip, &path, policy, &resource_url)
        .await;

    match decision {
        Decision::Allow {
            tier,
            payer,
            pending,
            ..
        } => {
            // Hold the verified payment for the response phase.
            stream_state.pending = pending;

            let mut mutations = vec![header(HEADER_TIER, tier.as_str())];
            if let Some(payer) = payer {
                mutations.push(header(HEADER_PAYER, payer));
            }

            ProcessingResponse {
                response: Some(processing_response::Response::RequestHeaders(
                    continue_with(mutations),
                )),
                ..Default::default()
            }
        }
        Decision::Deny { challenge, receipt } => {
            let mut headers = Vec::new();
            if let Ok(encoded) = x402::encode_header(&challenge) {
                headers.push(header(HEADER_PAYMENT_REQUIRED, encoded));
            }
            if let Some(receipt) = &receipt
                && let Ok(encoded) = x402::encode_header(receipt)
            {
                headers.push(header(HEADER_PAYMENT_RESPONSE, encoded));
            }
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
    let Some(pending) = stream_state.pending.take() else {
        // Nothing was paid on this request (free tier or an existing session).
        return ProcessingResponse {
            response: Some(processing_response::Response::ResponseHeaders(
                continue_with(Vec::new()),
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
        return ProcessingResponse {
            response: Some(processing_response::Response::ResponseHeaders(
                continue_with(Vec::new()),
            )),
            ..Default::default()
        };
    }

    let mut mutations = Vec::new();

    match state
        .facilitator
        .settle(&pending.payload, &pending.requirements)
        .await
    {
        Ok(mut settlement) => {
            let token = match &settlement.payer {
                None => None,
                Some(payer) => state.sessions.create_session(payer).await.ok(),
            };
            if let Some(token) = &token {
                settlement.extensions = Some(x402::session_extension_grant(
                    token,
                    state.config.paid_tier.quota,
                    state.config.paid_tier.duration_secs,
                ));
                mutations.push(header(HEADER_PAYMENT_SESSION, token.clone()));
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
        let reply = handle_request_headers(&state, &mut stream_state, headers, None).await;

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
