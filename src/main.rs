//! x402 payment-gated Envoy `ext_authz` verifier for Sui.
//!
//! Sits beside an Envoy proxy and answers authorization callouts: anonymous
//! clients get a rate-limited free tier, and clients presenting a valid x402
//! payment get an elevated tier backed by a time- and quota-limited session.

mod auth;
mod config;
mod ext_proc;
mod facilitator_api;
mod metrics;
mod ratelimit;
mod session;
mod sui;
mod util;
mod x402;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use envoy_types::ext_authz::v3::pb::AuthorizationServer;
use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_server::ExternalProcessorServer;
use tonic::transport::Server;

use crate::auth::{AppState, X402Auth};
use crate::config::{Config, StoreBackend, VerificationMode};
use crate::ratelimit::{MemoryRateLimiter, RateLimiter, RedisRateLimiter};
use crate::session::{MemorySessionStore, RedisSessionStore, SessionStore};
use crate::x402::Facilitator;

/// How often expired sessions and idle rate-limit keys are reaped.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Parser, Debug)]
#[command(name = "x402-verifier", about, version)]
struct Args {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "config.example.yaml")]
    config: String,

    /// Override the configured listen address.
    #[arg(short, long)]
    listen: Option<std::net::SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "x402_verifier=info".into()),
        )
        .init();

    let args = Args::parse();

    let mut config = Config::load(&args.config)
        .with_context(|| format!("loading configuration from {}", args.config))?;
    if let Some(listen) = args.listen {
        config.listen_addr = listen;
    }

    // Make it impossible to run the stub in production without knowing it.
    if config.verification_mode == VerificationMode::StubAcceptAll {
        tracing::warn!(
            "verification_mode is 'stub-accept-all': payments are ACCEPTED WITHOUT \
             on-chain verification and NO FUNDS MOVE. Development use only."
        );
    }

    // Install before anything can emit. A busy port degrades to "no metrics"
    // rather than taking the gateway down — telemetry must never be the reason
    // payments stop working.
    if let Some(addr) = config.metrics_listen_addr {
        match metrics::install(addr) {
            Ok(()) => tracing::info!(%addr, "serving Prometheus metrics at /metrics"),
            Err(e) => tracing::error!(error = %e, %addr, "could not start the metrics exporter"),
        }
    }

    let hmac_key = config.hmac_key()?;
    let facilitator = Facilitator::new(
        config.verification_mode,
        config.sui_grpc_url.clone(),
        config.payment.network.clone(),
    )
    .with_context(|| format!("connecting to the Sui fullnode at {}", config.sui_grpc_url))?;
    // Connect the state store up front so a bad Redis URL fails at boot rather
    // than on the first paying request.
    let (sessions, limiter) = match config.store.backend {
        StoreBackend::Memory => {
            tracing::warn!(
                "store.backend is 'memory': state is per-process. Run exactly ONE replica — \
                 with N replicas the effective rate limit becomes N x the configured value and \
                 sessions are replica-affine. Use 'redis' to scale out."
            );
            (
                // Tiers are per policy and passed per request; the store only
                // needs a horizon for sweeping the replay cache.
                SessionStore::Memory(MemorySessionStore::new(
                    hmac_key,
                    config.paid_tier.duration_secs,
                )),
                RateLimiter::Memory(MemoryRateLimiter::new()),
            )
        }
        StoreBackend::Redis => {
            let url = &config.store.redis_url;
            tracing::info!(redis_url = %url, "connecting to redis state store");
            let sessions = RedisSessionStore::connect(url, hmac_key)
                .await
                .with_context(|| format!("connecting to redis at {url}"))?;
            let limiter = RedisRateLimiter::connect(url)
                .await
                .with_context(|| format!("connecting to redis at {url}"))?;
            (SessionStore::Redis(sessions), RateLimiter::Redis(limiter))
        }
    };

    let listen_addr = config.listen_addr;
    tracing::info!(
        %listen_addr,
        network = %config.payment.network,
        sui_grpc_url = %config.sui_grpc_url,
        sui_chain = %config.sui_chain,
        pay_to = %config.payment.pay_to,
        asset = %config.payment.asset,
        price = %config.payment.amount,
        free_tier = format!(
            "{}/{}s",
            config.free_tier.max_requests, config.free_tier.window_secs
        ),
        paid_tier = format!(
            "{} req/{}s",
            config.paid_tier.quota, config.paid_tier.duration_secs
        ),
        "starting x402 verifier"
    );

    // Shared with the optional §7 HTTP API, so both surfaces enforce exactly
    // the same rules rather than drifting into two implementations.
    let facilitator = Arc::new(facilitator);

    let facilitator_api_addr = config.facilitator_api_listen_addr;

    // Shared with the §7 API so a payment cannot be spent once through the
    // gateway and again through /settle.
    let sessions = Arc::new(sessions);

    // The §7 API reads the policy table; the gateway owns the config itself.
    let api_config = Arc::new(config.clone());

    let state = Arc::new(AppState {
        config,
        sessions: Arc::clone(&sessions),
        limiter,
        facilitator: Arc::clone(&facilitator),
    });

    if let Some(addr) = facilitator_api_addr {
        let router = facilitator_api::router(
            Arc::clone(&facilitator),
            Arc::clone(&sessions),
            api_config,
        );
        tracing::info!(
            %addr,
            "serving the x402 facilitator HTTP API (POST /verify, POST /settle, GET /supported, GET /policies)"
        );
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    if let Err(e) = axum::serve(listener, router).await {
                        tracing::error!(error = %e, "facilitator HTTP API stopped");
                    }
                }
                Err(e) => tracing::error!(error = %e, %addr, "could not bind facilitator HTTP API"),
            }
        });
    }

    // Reap expired state so neither map grows without bound on a public
    // endpoint. Both structures are also self-healing on read, so a missed
    // tick costs memory but never correctness.
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(CLEANUP_INTERVAL);
        // The first tick fires immediately; skip it so startup does no work.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let expired_sessions = cleanup_state.sessions.cleanup_expired().await;
            let idle_ips = cleanup_state.limiter.cleanup_idle().await;
            if expired_sessions > 0 || idle_ips > 0 {
                tracing::debug!(
                    expired_sessions,
                    idle_ips,
                    live_sessions = cleanup_state.sessions.len(),
                    tracked_ips = cleanup_state.limiter.len(),
                    "reaped stale state"
                );
            }
        }
    });

    // Both filters are served on the same port: they are distinct gRPC
    // services, so Envoy picks whichever the config points at. ext_proc is the
    // spec-correct one (settles only after the upstream succeeds); ext_authz
    // remains for gateways that support nothing else.
    Server::builder()
        .add_service(ExternalProcessorServer::new(ext_proc::X402ExtProc::new(
            Arc::clone(&state),
        )))
        .add_service(AuthorizationServer::new(X402Auth::new(state)))
        .serve_with_shutdown(listen_addr, shutdown_signal())
        .await
        .context("ext_authz gRPC server failed")?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Resolve on SIGINT/SIGTERM so container stops are graceful rather than abrupt.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT; shutting down"),
        _ = terminate => tracing::info!("received SIGTERM; shutting down"),
    }
}
