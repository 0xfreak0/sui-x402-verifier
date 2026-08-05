//! `x402-demo` — the console behind the public demo.
//!
//! The thing being demonstrated is not a payment. It is a **meter**: a free
//! allowance that runs out, a 402 that names a price, and a session that
//! replaces the allowance once you pay for it. This service drives that loop
//! from a browser.
//!
//! ```text
//!   browser ──POST /send {target}──▶ x402-demo ──▶ gateway ──▶ upstream
//!                                        │  402? pay, retry, keep the session
//!                                        ▼
//!             { firstStatus, paidStatus, meter, challenge, payment, receipt }
//! ```
//!
//! # Four targets, four products
//!
//! Every target is a real route through the same Envoy, differing in price,
//! receiving wallet, free allowance and what one payment buys. One of them is
//! free, one is an ordinary HTTP application with no payment code of its own,
//! and one speaks a binary protocol. That spread is the argument: the gateway
//! does not care what is behind it.
//!
//! # This holds a key
//!
//! Everything else in this repo has custody of nothing — the client signs, and
//! the verifier only re-broadcasts. This binary is the exception: it is a hot
//! wallet on a public box, so a visitor can try the flow without installing a
//! wallet first. That is a deliberate, scoped tradeoff for a testnet demo, and
//! it is why the spend controls below are not optional.
//!
//! Fund it with trivial amounts. Testnet SUI is free from `sui client faucet`
//! and testnet USDC from faucet.circle.com; neither is worth stealing.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use clap::Parser;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use x402_verifier::payclient;

#[derive(Parser, Debug)]
#[command(name = "x402-demo", about = "Console backend for the x402 demo")]
struct Args {
    /// Address to serve on.
    #[arg(long, default_value = "127.0.0.1:8402")]
    listen: SocketAddr,

    /// Sui fullnode, for building payments and reading balances.
    #[arg(long, default_value = "https://fullnode.testnet.sui.io:443")]
    rpc: String,

    /// Hard ceiling on paid requests for the lifetime of this process.
    ///
    /// Gas is the binding constraint — roughly 0.00234 SUI per settlement, so
    /// ~2 SUI is ~850 payments. A Slack link can burn that in an afternoon.
    #[arg(long, default_value_t = 500)]
    max_plays: u64,

    /// Paid requests allowed per source IP per hour.
    #[arg(long, default_value_t = 20)]
    plays_per_ip_hourly: u64,

    /// Directory holding the demo page, served at `/`.
    #[arg(long, default_value = "demo")]
    static_dir: String,

    /// Gateway origin every target is requested through.
    ///
    /// Serving the page and proxying from one origin means the browser sees a
    /// single host, so there is no CORS to configure and no port juggling on a
    /// phone. In production Caddy does this instead.
    #[arg(long, default_value = "http://127.0.0.1:10000")]
    gateway: String,

    /// Verifier metrics endpoint, proxied to `/metrics`.
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    metrics: String,

    /// Verifier facilitator API, used to read the policy table.
    ///
    /// Payees come from here rather than from a 402, because triggering a
    /// challenge to discover a wallet would spend the free-tier request the
    /// page is trying to display.
    #[arg(long, default_value = "http://127.0.0.1:50052")]
    facilitator_api: String,

    /// Coin type balances are reported in. Must match the gateway's `asset`.
    #[arg(
        long,
        default_value = "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC"
    )]
    asset: String,
}

/// One thing the gateway sells, as the page renders it.
///
/// The list lives here rather than in the page so the demo cannot advertise a
/// route the gateway does not actually serve.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Target {
    /// Stable id the page sends back to `/send`.
    id: &'static str,
    label: &'static str,
    /// Where the request really goes, for display.
    upstream: &'static str,
    /// What this proves, in one line.
    detail: &'static str,
    /// Path on the gateway.
    path: &'static str,
    method: &'static str,
    content_type: &'static str,
    /// Request body, sent verbatim.
    body: &'static str,
    /// True for the one target that is not for sale.
    free: bool,
}

/// Every target is a real Envoy route; see `envoy.yaml` and `config.demo.yaml`.
const TARGETS: &[Target] = &[
    Target {
        id: "free",
        label: "GraphQL · chain identity",
        upstream: "graphql.testnet.sui.io",
        detail: "Free. Metered and passed straight through — the gate is not a paywall by default.",
        path: "/free/graphql",
        method: "POST",
        content_type: "application/json",
        body: r#"{"query":"{ chainIdentifier }"}"#,
        free: true,
    },
    Target {
        id: "graphql",
        label: "GraphQL · latest checkpoint",
        upstream: "graphql.testnet.sui.io",
        detail: "Small free allowance, then a price. This is the wall the demo is about.",
        path: "/graphql",
        method: "POST",
        content_type: "application/json",
        body: r#"{"query":"{ checkpoint { sequenceNumber digest } epoch { epochId } }"}"#,
        free: false,
    },
    Target {
        id: "grpc",
        label: "gRPC · LedgerService",
        upstream: "fullnode.testnet.sui.io",
        detail: "A binary protocol, a higher price, and a different receiving wallet.",
        path: "/sui.rpc.v2.LedgerService/GetServiceInfo",
        // grpc-web, because a browser cannot speak native gRPC: fetch gives no
        // control over HTTP/2 frames and trailers are unreadable from JS.
        // Envoy's grpc_web filter translates it, so the fullnode sees ordinary
        // gRPC. GetServiceInfoRequest is empty, so the body is just the 5-byte
        // length-prefixed frame header with a zero-length payload.
        content_type: "application/grpc-web+proto",
        method: "POST",
        body: "",
        free: false,
    },
    Target {
        id: "fail",
        label: "An upstream that always fails",
        upstream: "this box, port 8402",
        detail: "Verified, served a 503, and NOT charged. Settlement happens on the response path.",
        path: "/boom",
        method: "POST",
        content_type: "application/json",
        body: "{}",
        free: false,
    },
    Target {
        id: "spin",
        label: "Spin the wheel",
        upstream: "this box, port 8402",
        detail: "An ordinary HTTP app with no payment code of its own, sold by the gateway.",
        path: "/spin",
        method: "POST",
        content_type: "application/json",
        body: "{}",
        free: false,
    },
];

fn target(id: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|t| t.id == id)
}

#[derive(Clone)]
struct AppState {
    args: Arc<Args>,
    /// Total paid requests so far, against `max_plays`.
    spent: Arc<Mutex<u64>>,
    /// Per-IP hourly counters, so one enthusiast cannot drain the wallet.
    per_ip: Arc<DashMap<IpAddr, (u64, u64)>>,
}

/// The actual x402 exchange, surfaced so the page can show the wire rather
/// than asking anyone to take it on trust.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct Wire {
    /// Decoded PAYMENT-REQUIRED from the 402.
    challenge: Option<serde_json::Value>,
    /// Decoded PAYMENT-SIGNATURE we sent back.
    payment: Option<serde_json::Value>,
    /// Decoded PAYMENT-RESPONSE receipt.
    receipt: Option<serde_json::Value>,
    /// Status of the first attempt and, if we paid, the second one.
    first_status: u16,
    paid_status: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendRequest {
    target: String,
    /// Session token the page is holding for this target, if any. Presenting
    /// it is what makes the paid meter drain instead of paying again.
    #[serde(default)]
    session: Option<String>,
}

/// One measured step of the exchange.
///
/// Every span is a real measurement reported by whoever did the work: this
/// service times its own phases, the gateway reports its decide/settle split
/// via `Server-Timing`, and Envoy reports the upstream call via
/// `x-envoy-upstream-service-time`. Nothing here is estimated.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Span {
    name: String,
    /// Who performed this step.
    actor: String,
    /// Milliseconds from the start of the exchange.
    start_ms: f64,
    dur_ms: f64,
    /// 0 for a step this service performed; 1 for a step reported from inside
    /// one of those by a downstream service.
    depth: u8,
    /// `ok`, `pay`, `err`, or `skip`.
    outcome: String,
    detail: String,
}

impl Span {
    fn new(
        name: &str,
        actor: &str,
        start_ms: f64,
        dur_ms: f64,
        depth: u8,
        outcome: &str,
        detail: String,
    ) -> Self {
        Self {
            name: name.to_string(),
            actor: actor.to_string(),
            start_ms,
            dur_ms,
            depth,
            outcome: outcome.to_string(),
            detail,
        }
    }
}

/// Expand one gateway round trip into the phases the gateway and Envoy report.
///
/// Ordering is the real one rather than a guess: the gateway decides before the
/// upstream is called, and settles after it returns, so `decide` anchors to the
/// start of the attempt and `settle` to the end.
fn attempt_spans(attempt: &payclient::Attempt, start_ms: f64, paid: bool) -> Vec<Span> {
    let timing = |name: &str| {
        attempt
            .server_timing
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, ms)| *ms)
    };
    let mut spans = Vec::new();

    if let Some(decide) = timing("x402-decide") {
        spans.push(Span::new(
            if paid { "verify payment" } else { "check the meter" },
            "verifier",
            start_ms,
            decide,
            1,
            "ok",
            if paid {
                "signature, simulation, live inputs, exact credit".into()
            } else {
                "free-tier or session check; no chain access".into()
            },
        ));
    }

    if let Some(upstream) = attempt.upstream_ms {
        spans.push(Span::new(
            "upstream serves the request",
            "envoy → upstream",
            start_ms + timing("x402-decide").unwrap_or(0.0),
            upstream,
            1,
            if attempt.status == 200 { "ok" } else { "err" },
            format!("HTTP {}", attempt.status),
        ));
    }

    match timing("x402-settle") {
        Some(settle) => spans.push(Span::new(
            "settle on chain",
            "verifier",
            (start_ms + attempt.elapsed_ms - settle).max(start_ms),
            settle,
            1,
            "pay",
            "broadcast the client's signed transaction".into(),
        )),
        // No settle phase on a paid attempt whose upstream failed: this is the
        // whole point of settling on the response path, so show the absence
        // rather than silently omitting it.
        None if paid && attempt.status != 200 => spans.push(Span::new(
            "settle on chain",
            "verifier",
            start_ms + attempt.elapsed_ms,
            0.0,
            1,
            "skip",
            "SKIPPED — upstream did not return 2xx, so nothing was charged".into(),
        )),
        None => {}
    }

    spans
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SendResult {
    target: String,
    /// Final status the visitor got.
    status: u16,
    /// True when this request had to buy its way in.
    paid: bool,
    /// Session token to present next time, if one was just minted.
    session: Option<String>,
    /// What the gateway says is left.
    meter: payclient::Meter,
    /// On-chain settlement digest, empty when nothing settled.
    transaction: String,
    network: String,
    /// Trimmed upstream response, so the page can prove something came back.
    body: String,
    /// Paid requests left in this process's budget.
    plays_remaining: u64,
    wire: Wire,
    /// Measured steps of this exchange, in order.
    trace: Vec<Span>,
    /// True when money actually moved. False on a 402, and false when the
    /// upstream failed after verification.
    settled: bool,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
    detail: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::TOO_MANY_REQUESTS, Json(self)).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "x402_demo=info".into()),
        )
        .init();

    let args = Arc::new(Args::parse());
    let listen = args.listen;

    // Fail at startup, not on the first visitor, if there is no usable key.
    let key = payclient::load_key().context("loading the demo wallet key")?;
    tracing::info!(
        wallet = %key.public_key().derive_address(),
        gateway = %args.gateway,
        max_plays = args.max_plays,
        targets = TARGETS.len(),
        "x402-demo starting; this process holds a hot testnet wallet"
    );

    let state = AppState {
        args: Arc::clone(&args),
        spent: Arc::new(Mutex::new(0)),
        per_ip: Arc::new(DashMap::new()),
    };

    let app = Router::new()
        .route("/targets", get(targets))
        .route("/send", post(send))
        .route("/balances", get(balances))
        .route("/policies", get(policies_proxy))
        // The gated application. Envoy proxies /spin here AFTER deciding the
        // caller may have it; this handler has no idea it is being sold.
        .route("/wheel", post(wheel))
        // Deliberately broken, and gated exactly like the working ones.
        .route("/broken", post(broken))
        .route("/health", get(|| async { "ok" }))
        .route("/metrics", get(metrics_proxy))
        .route("/", get(index))
        .route("/rickroll.mp4", get(prize))
        // Everything else is the gated gateway, so the break-it panel and any
        // curl the visitor tries land on the real thing.
        .fallback(gateway_proxy)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// What the gateway is selling.
async fn targets() -> Json<&'static [Target]> {
    Json(TARGETS)
}

/// Issue one request against a target, paying only if challenged.
///
/// This is the whole demo loop. The free tier is spent first because that is
/// what a real client would do — paying while an allowance remains is burning
/// money.
async fn send(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    incoming: axum::http::HeaderMap,
    Json(request): Json<SendRequest>,
) -> Result<Json<SendResult>, ApiError> {
    let Some(target) = target(&request.target) else {
        return Err(ApiError {
            error: "unknown_target".into(),
            detail: format!("no target named {:?}", request.target),
        });
    };

    let url = format!(
        "{}{}",
        state.args.gateway.trim_end_matches('/'),
        target.path
    );
    let http = reqwest::Client::new();

    let mut headers = vec![("content-type".to_string(), target.content_type.to_string())];
    // Carry the edge proxy's view of the original request inward. Without this
    // the gateway sees only our loopback call and advertises a resource URL
    // pointing at its own internal address, which no client can reach.
    headers.extend(forwarded(&incoming));
    if let Some(session) = &request.session {
        headers.push(("x-payment-session".to_string(), session.clone()));
    }
    if target.content_type.starts_with("application/grpc-web") {
        // grpc-web requires the client to declare itself, and Envoy's filter
        // keys off it.
        headers.push(("x-grpc-web".to_string(), "1".to_string()));
    }

    let body = grpc_web_body(target);
    let began = std::time::Instant::now();
    let first = payclient::send(&http, target.method, &url, &headers, &body, None)
        .await
        .map_err(|e| ApiError {
            error: "gateway_unreachable".into(),
            detail: e.to_string(),
        })?;

    let mut trace = vec![Span::new(
        if first.status == 402 { "request without payment" } else { "request" },
        "demo → gateway",
        0.0,
        first.elapsed_ms,
        0,
        if first.status == 402 { "pay" } else if first.status == 200 { "ok" } else { "err" },
        format!("HTTP {}", first.status),
    )];
    trace.extend(attempt_spans(&first, 0.0, false));

    let plays_remaining = {
        let spent = state.spent.lock().await;
        state.args.max_plays.saturating_sub(*spent)
    };

    // Served without payment: the free allowance had room, or a session the
    // page was already holding covered it.
    if first.status != 402 {
        return Ok(Json(SendResult {
            target: target.id.to_string(),
            status: first.status,
            paid: false,
            session: request.session,
            meter: first.meter,
            transaction: String::new(),
            network: String::new(),
            body: trim_body(&first.body),
            plays_remaining,
            wire: Wire {
                first_status: first.status,
                ..Default::default()
            },
            trace,
            settled: false,
        }));
    }

    // ---- challenged: spend controls before we touch the wallet -----------
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let hour = now / 3600;
    {
        let mut entry = state.per_ip.entry(peer.ip()).or_insert((hour, 0));
        if entry.0 != hour {
            *entry = (hour, 0);
        }
        if entry.1 >= state.args.plays_per_ip_hourly {
            return Err(ApiError {
                error: "rate_limited".into(),
                detail: format!(
                    "this demo pays from one small testnet wallet, so it allows {} paid \
                     requests per hour per visitor. Try again next hour, or point your own \
                     wallet at the same gateway.",
                    state.args.plays_per_ip_hourly
                ),
            });
        }
        entry.1 += 1;
    }

    let mut spent = state.spent.lock().await;
    if *spent >= state.args.max_plays {
        return Err(ApiError {
            error: "budget_exhausted".into(),
            detail: "the demo wallet's gas budget for this run is spent. \
                     Testnet SUI is free — top it up with `sui client faucet` and restart."
                .into(),
        });
    }

    // ---- pay and retry ----------------------------------------------------
    let challenge = first.payment_required.clone().ok_or_else(|| ApiError {
        error: "malformed_challenge".into(),
        detail: "402 without a PAYMENT-REQUIRED header".into(),
    })?;
    let terms = challenge.accepts.first().ok_or_else(|| ApiError {
        error: "malformed_challenge".into(),
        detail: "challenge advertised no payment options".into(),
    })?;

    let key = payclient::load_key().map_err(|e| ApiError {
        error: "no_wallet".into(),
        detail: e.to_string(),
    })?;
    let build_start = began.elapsed().as_secs_f64() * 1000.0;
    let payment =
        payclient::build_payment_header(&state.args.rpc, &key, &challenge.resource.url, terms)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, target = target.id, "building the payment failed");
                ApiError {
                    error: "payment_failed".into(),
                    detail: e.to_string(),
                }
            })?;

    let build_ms = began.elapsed().as_secs_f64() * 1000.0 - build_start;
    trace.push(Span::new(
        "build and sign the payment",
        "demo wallet",
        build_start,
        build_ms,
        0,
        "pay",
        // The wallet never leaves this process; only the signature goes out.
        "pick a coin, read gas price, build a PTB, sign locally".into(),
    ));

    let paid_start = began.elapsed().as_secs_f64() * 1000.0;
    let paid = payclient::send(&http, target.method, &url, &headers, &body, Some(&payment))
        .await
        .map_err(|e| ApiError {
            error: "gateway_unreachable".into(),
            detail: e.to_string(),
        })?;
    trace.push(Span::new(
        "request with payment",
        "demo → gateway",
        paid_start,
        paid.elapsed_ms,
        0,
        if paid.status == 200 { "ok" } else { "err" },
        format!("HTTP {}", paid.status),
    ));
    trace.extend(attempt_spans(&paid, paid_start, true));

    let receipt = paid.payment_response.clone();
    let settled = receipt
        .as_ref()
        .map(|r| r.success && !r.transaction.starts_with("stub-"))
        .unwrap_or(false);
    if settled {
        *spent += 1;
    }
    let plays_remaining = state.args.max_plays.saturating_sub(*spent);
    drop(spent);

    tracing::info!(
        target = target.id,
        status = paid.status,
        settled,
        transaction = receipt.as_ref().map(|r| r.transaction.as_str()).unwrap_or(""),
        plays_remaining,
        "sold a request"
    );

    Ok(Json(SendResult {
        target: target.id.to_string(),
        status: paid.status,
        paid: true,
        // A fresh session supersedes whatever the page was holding.
        session: paid.session.clone().or(request.session),
        meter: paid.meter,
        transaction: receipt.as_ref().map(|r| r.transaction.clone()).unwrap_or_default(),
        network: receipt.as_ref().map(|r| r.network.clone()).unwrap_or_default(),
        body: trim_body(&paid.body),
        plays_remaining,
        wire: Wire {
            challenge: serde_json::to_value(&challenge).ok(),
            // Re-decode what we sent, so the page shows the real bytes rather
            // than a reconstruction.
            payment: base64_json(&payment),
            receipt: receipt.as_ref().and_then(|r| serde_json::to_value(r).ok()),
            first_status: first.status,
            paid_status: Some(paid.status),
        },
        trace,
        settled,
    }))
}

/// Re-emit the `X-Forwarded-*` headers the edge proxy set on the request that
/// reached us.
///
/// This service calls the gateway on loopback, so without propagating these the
/// gateway would describe the resource as `http://127.0.0.1:10000/...`. Only
/// forwarded here, never synthesised: with no proxy in front there is nothing
/// to forward and the gateway's own view is already correct.
fn forwarded(incoming: &axum::http::HeaderMap) -> Vec<(String, String)> {
    ["x-forwarded-host", "x-forwarded-proto"]
        .iter()
        .filter_map(|name| {
            let value = incoming.get(*name)?.to_str().ok()?;
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

/// A zero-length grpc-web frame for targets that speak it.
///
/// grpc-web frames are `[flags:1][length:4][payload]`. `GetServiceInfoRequest`
/// is empty, so the whole body is five zero bytes — which is why this demo can
/// call a binary RPC without a protobuf library in the browser.
fn grpc_web_body(target: &Target) -> String {
    if target.content_type.starts_with("application/grpc-web") {
        "\0\0\0\0\0".to_string()
    } else {
        target.body.to_string()
    }
}

/// Keep response previews small enough to render and large enough to prove
/// something real came back.
fn trim_body(body: &str) -> String {
    const MAX: usize = 600;
    // Binary grpc-web frames are not text; say so rather than emitting
    // replacement characters the page would render as noise.
    if body.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return format!("<{} bytes of grpc-web frames>", body.len());
    }
    if body.len() <= MAX {
        return body.to_string();
    }
    let cut = body.char_indices().map(|(i, _)| i).take_while(|i| *i <= MAX).last().unwrap_or(0);
    format!("{}…", &body[..cut])
}

/// Balances on both sides of the payment, so money is visibly moving.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Balances {
    /// The wallet this demo pays from.
    payer: String,
    payer_balance: Option<u64>,
    /// Receiving wallets, by policy, as the gateway advertises them.
    payees: Vec<Payee>,
    asset: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Payee {
    target: String,
    address: String,
    balance: Option<u64>,
}

/// Proxy the verifier's policy table so the page can price every target on
/// load, same-origin, without spending a free-tier request to discover it.
async fn policies_proxy(State(state): State<AppState>) -> impl IntoResponse {
    let url = format!(
        "{}/policies",
        state.args.facilitator_api.trim_end_matches('/')
    );
    match reqwest::get(&url).await {
        Ok(response) => match response.text().await {
            Ok(body) => ([(axum::http::header::CONTENT_TYPE, "application/json")], body)
                .into_response(),
            Err(_) => (StatusCode::BAD_GATEWAY, "[]").into_response(),
        },
        // The page degrades to unpriced targets rather than failing to load.
        Err(_) => ([(axum::http::header::CONTENT_TYPE, "application/json")], "[]").into_response(),
    }
}

/// One row of the verifier's policy table.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyRow {
    name: String,
    pay_to: String,
}

/// Read the payer's balance, and each policy's receiving wallet and balance.
///
/// Payees are read from the verifier's `/policies`, not discovered by
/// provoking a 402. Provoking one would consume a free-tier request every time
/// the page refreshed, quietly draining the exact meter this demo is about.
async fn balances(State(state): State<AppState>) -> impl IntoResponse {
    let Ok(key) = payclient::load_key() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no demo wallet").into_response();
    };
    let payer = key.public_key().derive_address();

    let table: Vec<PolicyRow> = match reqwest::get(format!(
        "{}/policies",
        state.args.facilitator_api.trim_end_matches('/')
    ))
    .await
    {
        Ok(response) => response.json().await.unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = %e, "could not read the policy table; payees unavailable");
            Vec::new()
        }
    };

    let mut payees: Vec<Payee> = Vec::new();
    for row in table {
        // The free policy has a payee configured but never charges, so listing
        // it would imply money lands there. It does not.
        if !TARGETS.iter().any(|t| t.id == row.name && !t.free) {
            continue;
        }
        // Two policies sharing a wallet is legitimate; list the wallet once and
        // name every target that credits it.
        if let Some(existing) = payees.iter_mut().find(|p| p.address == row.pay_to) {
            existing.target = format!("{} + {}", existing.target, row.name);
            continue;
        }
        let balance = match row.pay_to.parse() {
            Ok(addr) => payclient::balance(&state.args.rpc, addr, &state.args.asset)
                .await
                .ok(),
            Err(_) => None,
        };
        payees.push(Payee {
            target: row.name,
            address: row.pay_to,
            balance,
        });
    }

    Json(Balances {
        payer: payer.to_string(),
        payer_balance: payclient::balance(&state.args.rpc, payer, &state.args.asset)
            .await
            .ok(),
        payees,
        asset: state.args.asset.clone(),
    })
    .into_response()
}

/// The gated application: one spin of the wheel.
///
/// Envoy only routes here once the gateway has decided the caller may have it,
/// so this handler contains no payment logic at all. That is the point — it is
/// an ordinary endpoint that someone else is selling.
async fn wheel(State(state): State<AppState>) -> impl IntoResponse {
    // Derive the result from chain state rather than this process's RNG, so
    // anyone can recompute it from the digest.
    let http = reqwest::Client::new();
    let url = format!(
        "{}/free/graphql",
        state.args.gateway.trim_end_matches('/')
    );
    let seed = match http
        .post(&url)
        .header("content-type", "application/json")
        .body(r#"{"query":"{ chainIdentifier checkpoint { digest } }"}"#)
        .send()
        .await
    {
        Ok(response) => response.text().await.unwrap_or_default(),
        Err(_) => String::new(),
    };

    let digest = Sha256::digest(seed.as_bytes());
    let roll = (u64::from_be_bytes(digest[..8].try_into().unwrap_or_default()) % 100) + 1;
    Json(serde_json::json!({
        "roll": roll,
        "seed": chain_id_from(&seed),
    }))
    .into_response()
}

/// An upstream that always fails, so the response-path settlement rule can be
/// watched rather than taken on trust.
///
/// The client's payment is verified on the way in and would settle on the way
/// out — but `ext_proc` only settles on a 2xx. This returns 503, so the
/// authorization is discarded unspent and its replay claim released. Nobody is
/// charged for a resource they did not receive.
async fn broken() -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "this upstream fails on purpose",
            "expect": "no settlement, no charge, and the signed payment is released for retry",
        })),
    )
}

/// Serve the demo page.
async fn index(State(state): State<AppState>) -> impl IntoResponse {
    let path = std::path::Path::new(&state.args.static_dir).join("index.html");
    match tokio::fs::read_to_string(&path).await {
        Ok(body) => (
            [
                (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
                // Never cache the page. While iterating on the demo, a stale
                // copy in a phone's browser looks exactly like a bug that was
                // already fixed.
                (axum::http::header::CACHE_CONTROL, "no-store, must-revalidate"),
            ],
            body,
        )
            .into_response(),
        Err(e) => (
            StatusCode::NOT_FOUND,
            format!("could not read {}: {e}", path.display()),
        )
            .into_response(),
    }
}

/// Serve the prize. Local rather than an embed: no third-party dependency, no
/// CSP to negotiate, and it still works if the VM has no outbound internet.
async fn prize(State(state): State<AppState>) -> impl IntoResponse {
    let path = std::path::Path::new(&state.args.static_dir).join("rickroll.mp4");
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [
                (axum::http::header::CONTENT_TYPE, "video/mp4"),
                (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
            ],
            bytes,
        )
            .into_response(),
        Err(e) => (StatusCode::NOT_FOUND, format!("{}: {e}", path.display())).into_response(),
    }
}

/// Proxy the verifier's Prometheus endpoint so the page can read it same-origin.
async fn metrics_proxy(State(state): State<AppState>) -> impl IntoResponse {
    match reqwest::get(format!("{}/metrics", state.args.metrics)).await {
        Ok(response) => match response.text().await {
            Ok(body) => (StatusCode::OK, body).into_response(),
            Err(_) => (StatusCode::BAD_GATEWAY, "").into_response(),
        },
        // Metrics are optional; the page degrades rather than erroring.
        Err(_) => (StatusCode::OK, String::new()).into_response(),
    }
}

/// Forward anything else to the gated gateway, preserving method, headers and
/// body so the payment headers survive.
async fn gateway_proxy(
    State(state): State<AppState>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let (parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", state.args.gateway.trim_end_matches('/'), path);

    let bytes = match axum::body::to_bytes(body, 1 << 20).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "body too large").into_response(),
    };

    let client = reqwest::Client::new();
    let mut request = client.request(parts.method.clone(), &url).body(bytes);
    for (name, value) in parts.headers.iter() {
        // `host` must not be forwarded or the upstream routes on the wrong name.
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        request = request.header(name, value);
    }

    match request.send().await {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.unwrap_or_default();
            let mut out = axum::response::Response::builder().status(status);
            for (name, value) in headers.iter() {
                if name.as_str().eq_ignore_ascii_case("content-length")
                    || name.as_str().eq_ignore_ascii_case("transfer-encoding")
                {
                    continue;
                }
                out = out.header(name, value);
            }
            out.body(axum::body::Body::from(body))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("gateway unreachable: {e}")).into_response(),
    }
}

/// Decode a base64(JSON) header value for display.
fn base64_json(raw: &str) -> Option<serde_json::Value> {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    B64.decode(raw.trim())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

/// Pull `chainIdentifier` out of a GraphQL response.
fn chain_id_from(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["data"]["chainIdentifier"].as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_has_a_distinct_id_and_path() {
        // The page keys its meters on target id and the gateway routes on
        // path; a duplicate of either silently merges two products into one.
        for (i, a) in TARGETS.iter().enumerate() {
            for b in &TARGETS[i + 1..] {
                assert_ne!(a.id, b.id, "duplicate target id {:?}", a.id);
                assert_ne!(a.path, b.path, "duplicate target path {:?}", a.path);
            }
        }
    }

    #[test]
    fn exactly_one_target_is_free() {
        // The free row is what proves the gate is not a paywall by default.
        // Losing it, or having two, both weaken the point being made.
        assert_eq!(TARGETS.iter().filter(|t| t.free).count(), 1);
    }

    #[test]
    fn grpc_targets_send_a_well_formed_empty_frame() {
        let grpc = target("grpc").expect("the grpc target exists");
        let body = grpc_web_body(grpc);
        // [flags:1][length:4] with a zero-length payload.
        assert_eq!(body.as_bytes(), &[0, 0, 0, 0, 0]);
    }

    #[test]
    fn json_targets_send_their_body_verbatim() {
        let graphql = target("graphql").expect("the graphql target exists");
        assert_eq!(grpc_web_body(graphql), graphql.body);
        assert!(graphql.body.contains("checkpoint"));
    }

    #[test]
    fn binary_response_bodies_are_described_rather_than_rendered() {
        // grpc-web frames contain control bytes; pasting them into the page
        // renders as replacement-character noise that looks like a bug.
        let described = trim_body("\0\0\0\0\x05hello");
        assert!(described.starts_with('<'), "got {described:?}");
        assert!(described.contains("bytes"));
    }

    #[test]
    fn long_text_bodies_are_truncated_on_a_character_boundary() {
        // Slicing a UTF-8 string by byte offset panics mid-codepoint, and the
        // GraphQL responses here are not guaranteed to be ASCII.
        let long = "é".repeat(500);
        let trimmed = trim_body(&long);
        assert!(trimmed.ends_with('…'));
        assert!(trimmed.len() < long.len());
    }

    #[test]
    fn short_text_bodies_are_left_alone() {
        assert_eq!(trim_body(r#"{"data":{}}"#), r#"{"data":{}}"#);
    }
}
