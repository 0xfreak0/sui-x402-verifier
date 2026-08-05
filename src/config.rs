//! Configuration loading.
//!
//! Config is YAML on disk (see `config.example.yaml`). A handful of fields can
//! be overridden by CLI flags or environment variables, which matters for the
//! HMAC secret: baking that into a checked-in YAML file is the single easiest
//! way to leak it, so `X402_SESSION_HMAC_SECRET` is the preferred source.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

/// Environment variable that overrides `session_hmac_secret` from the file.
pub const ENV_HMAC_SECRET: &str = "X402_SESSION_HMAC_SECRET";

/// Environment variable that overrides `payment.pay_to` from the file.
///
/// Exists so no real receiving wallet ever needs to live in a committed config.
pub const ENV_PAY_TO: &str = "X402_PAY_TO";

/// Prefix for per-policy receiving-wallet overrides: `X402_PAY_TO_<POLICY>`,
/// with the policy name upper-cased and `-` mapped to `_`.
///
/// The whole point of per-policy `pay_to` is that different routes credit
/// different wallets, so one [`ENV_PAY_TO`] is not enough to keep real
/// addresses out of a committed config once there is more than one payee.
pub const ENV_PAY_TO_PREFIX: &str = "X402_PAY_TO_";

/// Environment-variable name carrying the receiving wallet for `policy`.
pub fn pay_to_env_var(policy: &str) -> String {
    format!(
        "{ENV_PAY_TO_PREFIX}{}",
        policy.to_ascii_uppercase().replace('-', "_")
    )
}

/// Length of a Sui address in hex characters (32 bytes).
const SUI_ADDRESS_HEX_LEN: usize = 64;

/// The HMAC secret shipped in every example config.
///
/// Published in a public repository, so a deployment that keeps it is using a
/// session signing key the whole internet knows: anyone can mint themselves a
/// token for any payer with unexpired claims and skip payment entirely.
///
/// The zero address is refused for the same reason, and this is the more
/// dangerous of the two — a wrong `pay_to` sends money nowhere, a known HMAC key
/// gives the paid tier away.
const PLACEHOLDER_HMAC_SECRET: &str =
    "abababababababababababababababababababababababababababababababab";

/// Smallest transfer Sui's gasless stablecoin path will execute, in base units
/// of a 6-decimal stablecoin: 0.01.
///
/// Below this the transfer is simply not executed, so a price set under it
/// forces the old coin-object path — the payer needs SUI for gas, an object is
/// created and pinned, and the authorization becomes spendable out from under
/// itself. All of which is avoidable by charging at least a cent.
///
/// This is why sessions matter here. Per-request pricing cannot go below a cent
/// at all; one payment buying a thousand requests brings the effective price to
/// $0.00001 while staying above the floor.
pub const GASLESS_MINIMUM_BASE_UNITS: u128 = 10_000;

/// Decimals assumed when reporting a price against the gasless floor. Only used
/// for the startup warning, never for anything on the wire.
const STABLECOIN_DECIMALS: u32 = 6;

/// Minimum accepted HMAC key length in bytes. 32 bytes matches the SHA-256
/// block security level; shorter keys are rejected outright rather than
/// silently weakening session-token forgery resistance.
pub const MIN_HMAC_KEY_BYTES: usize = 32;

/// How the facilitator decides whether a payment is real.
///
/// The stub variant is named loudly on purpose: it appears verbatim in the
/// config file an operator has to write, so nobody enables it by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum VerificationMode {
    /// Accept any structurally valid payment payload without touching the
    /// chain. Development and protocol-plumbing work only.
    #[serde(rename = "stub-accept-all")]
    StubAcceptAll,
    /// Verify and settle against a Sui fullnode over gRPC. Not yet implemented;
    /// selecting it currently causes every payment to be rejected rather than
    /// silently falling back to the stub.
    #[serde(rename = "sui-grpc")]
    SuiGrpc,
}

/// Payment terms advertised in the `PAYMENT-REQUIRED` challenge.
///
/// Field names mirror the x402 v2 `PaymentRequirements` object so the wire
/// format is a direct serialization of what the operator configured.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentConfig {
    /// x402 payment scheme. Only `exact` is implemented.
    pub scheme: String,
    /// CAIP-2-style network identifier, e.g. `sui:testnet`.
    pub network: String,
    /// Price in the asset's smallest unit, as a decimal string. A string (not
    /// an integer) because x402 carries amounts as strings to dodge the
    /// 2^53 precision cliff in JSON parsers.
    ///
    /// Named `amount` to match the v2 wire field exactly — v1 called this
    /// `maxAmountRequired`. Keeping one name end-to-end means there is no
    /// translation table between config and protocol to get wrong.
    pub amount: String,
    /// Fully-qualified Move coin type to be paid in.
    pub asset: String,
    /// Sui address that receives payment. Must be this operator's wallet.
    pub pay_to: String,
    /// How long a signed authorization stays acceptable, in seconds.
    pub max_timeout_seconds: u64,
    /// Human-readable description of the resource. In v2 this belongs to the
    /// top-level `resource` object, not to each `accepts` entry.
    pub description: String,
    /// Gas station URL advertised as `extra.gasStation` when set, signalling
    /// to clients that this facilitator will sponsor transactions. Advertising
    /// only — the interactive sponsorship protocol itself is not implemented.
    #[serde(default)]
    pub gas_station: Option<String>,
}

/// Key Envoy uses to name a payment policy in `context_extensions`.
///
/// Set per route in Envoy via `ExtAuthzPerRoute.check_settings`; arrives on
/// `CheckRequest.attributes.context_extensions`.
pub const POLICY_CONTEXT_KEY: &str = "x402_policy";

/// Payment terms *and tier limits* that differ from the defaults. Every field is
/// optional and falls back to the corresponding top-level value when unset.
///
/// Tiers are overridable per policy because price alone does not describe what a
/// route sells. A cheap read endpoint might give away 20 requests a minute and
/// sell 1000 more; an expensive one might give away nothing and sell 50. Those
/// are different products at the same gateway, and one global `free_tier` cannot
/// express that.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PaymentOverride {
    /// Receiving wallet for this policy.
    #[serde(default)]
    pub pay_to: Option<String>,
    /// Price for this policy.
    #[serde(default)]
    pub amount: Option<String>,
    /// Description surfaced in the challenge.
    #[serde(default)]
    pub description: Option<String>,
    /// Anonymous allowance for this policy. Unset inherits the global tier.
    #[serde(default)]
    pub free_tier: Option<FreeTierConfig>,
    /// What one payment buys on this policy. Unset inherits the global tier.
    #[serde(default)]
    pub paid_tier: Option<PaidTierConfig>,
}

impl PaymentOverride {
    /// Layer this override onto resolved terms.
    fn apply_to(&self, resolved: &mut ResolvedPolicy) {
        if let Some(pay_to) = &self.pay_to {
            resolved.payment.pay_to = pay_to.clone();
        }
        if let Some(amount) = &self.amount {
            resolved.payment.amount = amount.clone();
        }
        if let Some(description) = &self.description {
            resolved.payment.description = description.clone();
        }
        if let Some(free_tier) = &self.free_tier {
            resolved.free_tier = free_tier.clone();
        }
        if let Some(paid_tier) = &self.paid_tier {
            resolved.paid_tier = paid_tier.clone();
        }
    }

    /// Same rules as the top-level fields, so typos fail at boot.
    fn validate(&self, context: &str) -> Result<()> {
        if let Some(pay_to) = &self.pay_to {
            validate_pay_to(pay_to).with_context(|| context.to_string())?;
        }
        if let Some(amount) = &self.amount
            && amount.parse::<u128>().is_err()
        {
            bail!("{context}: amount must be a decimal integer string, got {amount:?}");
        }
        if let Some(free_tier) = &self.free_tier {
            free_tier.validate(&format!("{context} free_tier"))?;
        }
        if let Some(paid_tier) = &self.paid_tier {
            paid_tier.validate(&format!("{context} paid_tier"))?;
        }
        Ok(())
    }
}

/// Every tier and term decision for one request, with all fallbacks applied.
///
/// Resolved once per request and threaded through from there, so the free-tier
/// check, the challenge, the session mint and the response headers cannot
/// disagree about which policy is in force.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    /// Stable name for this policy: the `policies` key, the matched
    /// `path_prefix`, or [`DEFAULT_POLICY_LABEL`]. Used to scope rate-limit
    /// buckets, so two policies never share a free-tier allowance.
    pub label: String,
    pub payment: PaymentConfig,
    pub free_tier: FreeTierConfig,
    pub paid_tier: PaidTierConfig,
}

/// Bucket and metric label for requests matching no named policy or prefix.
pub const DEFAULT_POLICY_LABEL: &str = "default";

/// Per-route override of the default payment terms.
///
/// Lets one proxy monetize several upstreams at different prices, or credit
/// different wallets — e.g. cheap reads to GraphQL and pricier gRPC calls
/// settling to a separate treasury address.
///
/// Matching is longest-prefix-wins, so a specific `/sui.rpc.v2.` rule beats a
/// general `/` rule regardless of the order they appear in the file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOverride {
    /// Request path prefix this rule applies to.
    pub path_prefix: String,
    /// Terms that differ from the defaults for this prefix.
    #[serde(flatten)]
    pub overrides: PaymentOverride,
}

/// Anonymous, unpaid tier limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTierConfig {
    /// Requests permitted per window, per source IP. Zero means every request
    /// is challenged; there is no free allowance at all.
    pub max_requests: u64,
    /// Sliding-window length in seconds.
    pub window_secs: u64,
}

impl FreeTierConfig {
    fn validate(&self, context: &str) -> Result<()> {
        if self.window_secs == 0 {
            bail!("{context}: window_secs must be greater than zero");
        }
        Ok(())
    }
}

/// Limits unlocked by a settled payment.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaidTierConfig {
    /// Requests granted by a single payment.
    pub quota: u64,
    /// Wall-clock lifetime of the session, in seconds. The session dies at
    /// whichever comes first: quota exhaustion or this deadline.
    pub duration_secs: u64,
}

impl PaidTierConfig {
    fn validate(&self, context: &str) -> Result<()> {
        if self.duration_secs == 0 {
            bail!("{context}: duration_secs must be greater than zero");
        }
        if self.quota == 0 {
            bail!("{context}: quota must be greater than zero");
        }
        Ok(())
    }
}

/// Where session and rate-limit state lives.
///
/// This is the horizontal-scaling seam. The in-process maps are correct for a
/// single replica but are *per-process*: run two verifiers behind the same
/// Envoy and each enforces the configured limits independently, so the real
/// ceiling becomes N times the configured one, and a session minted by one
/// replica is `Unknown` to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub enum StoreBackend {
    /// In-process `DashMap`s. Zero dependencies; single replica only.
    #[serde(rename = "memory")]
    #[default]
    Memory,
    /// Shared Redis. Required for more than one replica. Connected at startup,
    /// so a bad URL fails at boot rather than on the first paying request.
    #[serde(rename = "redis")]
    Redis,
}

/// State-store configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default)]
    pub backend: StoreBackend,
    /// Connection URL, e.g. `redis://127.0.0.1:6379`. Required when
    /// `backend: redis`.
    #[serde(default)]
    pub redis_url: String,
}

/// Top-level service configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the ext_authz gRPC server binds to.
    pub listen_addr: SocketAddr,
    /// Optional address for the Prometheus exporter, serving `/metrics`.
    ///
    /// Disabled unless set. Bind it to a private interface: the metrics
    /// themselves are not sensitive, but the endpoint is unauthenticated.
    #[serde(default)]
    pub metrics_listen_addr: Option<SocketAddr>,
    /// Optional address for the standard facilitator HTTP API (spec §7:
    /// `/verify`, `/settle`, `/supported`).
    ///
    /// **Disabled unless set.** Envoy never calls these endpoints — it uses the
    /// ext_authz gRPC service above, where verification and settlement happen
    /// together inside one `Check()`. §7 exists so *other* x402 resource
    /// servers can delegate Sui work to this service.
    ///
    /// Unauthenticated: bind loopback or a private interface. `/settle` is the
    /// endpoint that moves money once real settlement lands.
    #[serde(default)]
    pub facilitator_api_listen_addr: Option<SocketAddr>,
    /// Sui fullnode gRPC endpoint used for verification and settlement.
    pub sui_grpc_url: String,
    /// Chain the fullnode is expected to be serving (`testnet`, `mainnet`, …).
    /// Cross-checked against the node at startup in `sui-grpc` mode.
    pub sui_chain: String,
    /// How payments are verified.
    pub verification_mode: VerificationMode,
    pub payment: PaymentConfig,
    /// Named payment policies, selected by Envoy per route via
    /// `context_extensions: { x402_policy: <name> }`.
    ///
    /// **This is the preferred way to price multiple routes.** Envoy stays the
    /// single source of truth for which paths exist and which policy each one
    /// uses; this file only says what each policy costs and where it pays. No
    /// path prefixes are duplicated between the two configs.
    #[serde(default)]
    pub policies: std::collections::HashMap<String, PaymentOverride>,
    /// Path-prefix overrides, matched by the verifier itself.
    ///
    /// Fallback for gateways that cannot attach per-route metadata to an
    /// ext_authz call. This *does* duplicate path knowledge between the gateway
    /// and this file, so prefer `policies` when running Envoy.
    #[serde(default)]
    pub routes: Vec<RouteOverride>,
    pub free_tier: FreeTierConfig,
    pub paid_tier: PaidTierConfig,
    /// Defaults to the in-process store, which is what local testing wants.
    #[serde(default)]
    pub store: StoreConfig,
    /// Hex-encoded HMAC key for session tokens. Prefer leaving this empty in
    /// the file and supplying [`ENV_HMAC_SECRET`] instead.
    #[serde(default)]
    pub session_hmac_secret: String,
}

/// Reject anything that is not a usable Sui receiving address.
///
/// The zero address is called out separately because it is the placeholder
/// shipped in `config.example.yaml`: settling to it would burn real funds, so
/// the service must refuse to start rather than run with an unconfigured
/// destination.
fn validate_pay_to(pay_to: &str) -> Result<()> {
    let Some(hex_part) = pay_to.strip_prefix("0x") else {
        bail!("payment.pay_to must be a 0x-prefixed Sui address, got {pay_to:?}");
    };

    if hex_part.len() != SUI_ADDRESS_HEX_LEN || !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "payment.pay_to must be 0x followed by {SUI_ADDRESS_HEX_LEN} hex characters, got {pay_to:?}"
        );
    }

    if hex_part.chars().all(|c| c == '0') {
        bail!(
            "payment.pay_to is the zero address — this is the placeholder from \
             config.example.yaml. Set a real receiving wallet in the config or via {ENV_PAY_TO}."
        );
    }

    Ok(())
}

impl Config {
    /// Load YAML from `path`, then apply the environment override for the HMAC
    /// secret.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let mut config: Config = serde_norway::from_str(&raw)
            .with_context(|| format!("parsing config file {}", path.display()))?;

        // Environment wins over the file so secrets and real wallet addresses
        // never need to live on disk.
        if let Ok(secret) = std::env::var(ENV_HMAC_SECRET) {
            config.session_hmac_secret = secret;
        }
        if let Ok(pay_to) = std::env::var(ENV_PAY_TO) {
            config.payment.pay_to = pay_to;
        }
        for (name, policy) in config.policies.iter_mut() {
            if let Ok(pay_to) = std::env::var(pay_to_env_var(name)) {
                policy.pay_to = Some(pay_to);
            }
        }

        config.validate()?;
        Ok(config)
    }

    /// Reject configurations that would be unsafe or nonsensical at runtime.
    fn validate(&self) -> Result<()> {
        if self.payment.scheme != "exact" {
            bail!(
                "unsupported payment scheme {:?}; only \"exact\" is implemented",
                self.payment.scheme
            );
        }

        // An empty or malformed amount would be advertised to clients verbatim
        // and then fail to compare at verification time, so catch it here.
        if self.payment.amount.parse::<u128>().is_err() {
            bail!(
                "payment.amount must be a decimal integer string, got {:?}",
                self.payment.amount
            );
        }

        validate_pay_to(&self.payment.pay_to)?;

        self.free_tier.validate("free_tier")?;
        self.paid_tier.validate("paid_tier")?;

        self.warn_if_below_the_gasless_floor();

        // Validate overrides with the same rules as the defaults, so a typo in
        // a wallet or price fails at boot rather than at payment time.
        for (name, policy) in &self.policies {
            policy.validate(&format!("policy {name:?}"))?;
        }
        for route in &self.routes {
            if route.path_prefix.is_empty() {
                bail!("routes[].path_prefix must not be empty");
            }
            route
                .overrides
                .validate(&format!("route {:?}", route.path_prefix))?;
        }

        if self.store.backend == StoreBackend::Redis && self.store.redis_url.is_empty() {
            bail!("store.redis_url is required when store.backend is \"redis\"");
        }

        // Force the key check here so a bad key fails at boot, not on the first
        // paying request.
        self.hmac_key()?;
        Ok(())
    }

    /// Warn about prices too small for Sui's gasless stablecoin transfers.
    ///
    /// A warning rather than an error: a sub-cent price is a legitimate choice
    /// if the operator is content for payers to hold SUI and pay gas. It should
    /// just never be an accident, because the difference is invisible in the
    /// config and expensive at runtime.
    fn warn_if_below_the_gasless_floor(&self) {
        let scale = 10u128.pow(STABLECOIN_DECIMALS) as f64;
        for (name, amount) in self.priced_policies() {
            let Ok(value) = amount.parse::<u128>() else {
                continue;
            };
            if value > 0 && value < GASLESS_MINIMUM_BASE_UNITS {
                tracing::warn!(
                    policy = %name,
                    amount = %amount,
                    price = format!("{:.6}", value as f64 / scale),
                    floor = format!("{:.2}", GASLESS_MINIMUM_BASE_UNITS as f64 / scale),
                    "price is below the gasless stablecoin minimum; payers will need SUI \
                     for gas and the payment will pin a coin object. Charge at least the \
                     floor and sell a session to keep the effective per-request price low."
                );
            }
        }
    }

    /// Every policy's effective price, including the default terms.
    fn priced_policies(&self) -> Vec<(String, &str)> {
        std::iter::once((
            DEFAULT_POLICY_LABEL.to_string(),
            self.payment.amount.as_str(),
        ))
        .chain(self.policies.iter().map(|(name, over)| {
            (
                name.clone(),
                over.amount.as_deref().unwrap_or(&self.payment.amount),
            )
        }))
        .collect()
    }

    /// Resolve the payment terms for a request.
    ///
    /// Precedence, highest first:
    ///
    /// 1. `policy` — the name Envoy attached to the matched route. Authoritative
    ///    because the gateway already decided which route this is; no path
    ///    matching is repeated here.
    /// 2. Longest matching `routes[].path_prefix`, for gateways that cannot
    ///    attach route metadata. Longest-wins, so file order is irrelevant.
    /// 3. The top-level `payment` defaults.
    ///
    /// An unknown policy name falls through to the lower tiers rather than
    /// failing the request; it is logged by the caller.
    pub fn policy_for(&self, path: &str, policy: Option<&str>) -> ResolvedPolicy {
        let mut resolved = ResolvedPolicy {
            label: DEFAULT_POLICY_LABEL.to_string(),
            payment: self.payment.clone(),
            free_tier: self.free_tier.clone(),
            paid_tier: self.paid_tier.clone(),
        };

        if let Some(name) = policy
            && let Some(over) = self.policies.get(name)
        {
            over.apply_to(&mut resolved);
            resolved.label = name.to_string();
            return resolved;
        }

        if let Some(route) = self
            .routes
            .iter()
            .filter(|r| path.starts_with(&r.path_prefix))
            .max_by_key(|r| r.path_prefix.len())
        {
            route.overrides.apply_to(&mut resolved);
            resolved.label = route.path_prefix.clone();
        }

        resolved
    }

    /// True when `policy` was supplied but matches no configured policy.
    pub fn is_unknown_policy(&self, policy: &str) -> bool {
        !self.policies.contains_key(policy)
    }

    /// Decode the configured HMAC secret into raw key bytes.
    pub fn hmac_key(&self) -> Result<Vec<u8>> {
        if self.session_hmac_secret.is_empty() {
            bail!(
                "session HMAC secret is empty; set it in the config file or via {ENV_HMAC_SECRET}"
            );
        }

        if self.session_hmac_secret.trim() == PLACEHOLDER_HMAC_SECRET {
            bail!(
                "session HMAC secret is the placeholder from the example config, which is \
                 published and therefore public. Anyone could forge session tokens against \
                 this deployment. Generate a real one:\n\n    \
                 export {ENV_HMAC_SECRET}=$(openssl rand -hex 32)"
            );
        }

        let key = hex::decode(&self.session_hmac_secret).context(
            "session HMAC secret must be hex-encoded (generate with: openssl rand -hex 32)",
        )?;

        if key.len() < MIN_HMAC_KEY_BYTES {
            bail!(
                "session HMAC secret must be at least {MIN_HMAC_KEY_BYTES} bytes ({} hex chars), got {}",
                MIN_HMAC_KEY_BYTES * 2,
                key.len()
            );
        }

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid non-placeholder secret. Deliberately not the `"abab…"` example
    /// value, which is published and is now refused.
    const TEST_HMAC_SECRET: &str =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    /// Synthetic, obviously-fake receiving address. Never use a real wallet in
    /// tests or committed config — see [`ENV_PAY_TO`].
    const TEST_PAY_TO: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    /// A valid config with a placeholder key, used as the base for mutation.
    fn base_yaml() -> String {
        format!(
            r#"
listen_addr: "127.0.0.1:50051"
sui_grpc_url: "https://fullnode.testnet.sui.io:443"
sui_chain: "testnet"
verification_mode: stub-accept-all
session_hmac_secret: "{}"
payment:
  scheme: "exact"
  network: "sui:testnet"
  amount: "1000"
  asset: "0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC"
  pay_to: "{}"
  max_timeout_seconds: 60
  description: "test"
free_tier:
  max_requests: 10
  window_secs: 60
paid_tier:
  quota: 100
  duration_secs: 3600
"#,
            TEST_HMAC_SECRET, TEST_PAY_TO
        )
    }

    fn parse(yaml: &str) -> Result<Config> {
        let config: Config = serde_norway::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn parses_a_valid_config() {
        let config = parse(&base_yaml()).expect("base config should be valid");
        assert_eq!(config.verification_mode, VerificationMode::StubAcceptAll);
        assert_eq!(config.payment.network, "sui:testnet");
        assert_eq!(config.hmac_key().unwrap().len(), 32);
    }

    #[test]
    fn rejects_unknown_fields() {
        // Guards against typos silently falling back to defaults.
        let yaml = format!("{}\nnot_a_real_field: 1\n", base_yaml());
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn rejects_short_hmac_key() {
        let yaml = base_yaml().replace(TEST_HMAC_SECRET, "abcd");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("at least"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_non_hex_hmac_key() {
        let yaml = base_yaml().replace(TEST_HMAC_SECRET, &"zz".repeat(32));
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("hex-encoded"), "unexpected error: {err}");
    }

    #[test]
    fn the_shipped_configs_price_above_the_gasless_floor() {
        // Below 0.01 the gasless stablecoin path refuses to execute, which
        // silently forces payers back onto coin objects and SUI gas. The
        // shipped configs must not demonstrate the wrong thing.
        for path in [
            "config.example.yaml",
            "config.demo.yaml",
            "deploy/config.prod.yaml",
        ] {
            let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
            let raw = std::fs::read_to_string(&full)
                .unwrap_or_else(|e| panic!("{} must exist and be readable: {e}", full.display()));
            for line in raw.lines() {
                let Some(rest) = line.trim().strip_prefix("amount: ") else {
                    continue;
                };
                let amount: u128 = rest
                    .trim_matches('"')
                    .parse()
                    .expect("amount is an integer");
                assert!(
                    amount >= GASLESS_MINIMUM_BASE_UNITS,
                    "{}: amount {amount} is below the gasless floor of {}",
                    full.display(),
                    GASLESS_MINIMUM_BASE_UNITS
                );
            }
        }
    }

    #[test]
    fn a_price_below_the_gasless_floor_still_loads() {
        // A warning, not an error: sub-cent pricing is a legitimate choice if
        // the operator accepts that payers hold SUI. It must simply never be
        // an accident.
        let yaml = base_yaml().replace(r#"amount: "1000""#, r#"amount: "10""#);
        assert!(parse(&yaml).is_ok());
    }

    #[test]
    fn rejects_the_published_placeholder_hmac_secret() {
        // Shipped in every example config and therefore public. Keeping it
        // means anyone can forge a session token for any payer and skip
        // payment entirely — strictly worse than the zero-address case, which
        // only misdirects money.
        let yaml = base_yaml().replace(TEST_HMAC_SECRET, PLACEHOLDER_HMAC_SECRET);
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("placeholder"), "got: {err}");
        assert!(
            err.contains("openssl rand -hex 32"),
            "the error should say how to fix it: {err}"
        );
    }

    #[test]
    fn the_shipped_example_configs_all_carry_the_placeholder() {
        // If one of them ever ships a real-looking secret instead, the check
        // above stops protecting anybody. This asserts the example files stay
        // the thing that gets refused.
        for path in ["config.example.yaml", "config.demo.yaml"] {
            let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
            let raw = std::fs::read_to_string(&full)
                .unwrap_or_else(|e| panic!("{} must exist and be readable: {e}", full.display()));
            assert!(
                raw.contains(PLACEHOLDER_HMAC_SECRET),
                "{} should carry the placeholder secret so it cannot boot unconfigured",
                full.display()
            );
        }
    }

    #[test]
    fn rejects_empty_hmac_key() {
        let yaml = base_yaml().replace(&format!("\"{TEST_HMAC_SECRET}\""), "\"\"");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let yaml = base_yaml().replace(r#"scheme: "exact""#, r#"scheme: "upto""#);
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("unsupported payment scheme"), "got: {err}");
    }

    #[test]
    fn rejects_non_numeric_amount() {
        let yaml = base_yaml().replace(r#"amount: "1000""#, r#"amount: "1.5""#);
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("decimal integer"), "got: {err}");
    }

    #[test]
    fn rejects_pay_to_without_0x_prefix() {
        let yaml = base_yaml().replace(TEST_PAY_TO, &TEST_PAY_TO[2..]);
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("0x-prefixed"), "got: {err}");
    }

    #[test]
    fn rejects_pay_to_of_the_wrong_length_or_with_non_hex_characters() {
        for bad in [
            "0xdeadbeef",                     // too short
            &format!("0x{}", "1".repeat(65)), // too long
            &format!("0x{}", "z".repeat(64)), // not hex
        ] {
            let yaml = base_yaml().replace(TEST_PAY_TO, bad);
            assert!(parse(&yaml).is_err(), "should have rejected pay_to {bad:?}");
        }
    }

    #[test]
    fn rejects_the_zero_address_placeholder() {
        // config.example.yaml ships the zero address precisely so an
        // unconfigured deployment refuses to start instead of burning funds.
        let yaml = base_yaml().replace(TEST_PAY_TO, &format!("0x{}", "0".repeat(64)));
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("zero address"), "got: {err}");
    }

    /// Base config plus per-route overrides, deliberately listed with the
    /// general rule first to prove ordering does not matter.
    fn routed_yaml() -> String {
        format!(
            r#"{}
routes:
  - path_prefix: "/"
    amount: "100"
    description: "cheap default"
  - path_prefix: "/sui.rpc.v2."
    pay_to: "0x{}"
    amount: "5000"
    description: "gRPC calls"
"#,
            base_yaml(),
            "3".repeat(64)
        )
    }

    #[test]
    fn without_routes_every_path_uses_the_default_terms() {
        let config = parse(&base_yaml()).unwrap();
        let terms = config.policy_for("/anything", None).payment;
        assert_eq!(terms.pay_to, TEST_PAY_TO);
        assert_eq!(terms.amount, "1000");
    }

    #[test]
    fn longest_matching_prefix_wins_regardless_of_file_order() {
        let config = parse(&routed_yaml()).unwrap();

        // "/sui.rpc.v2." is longer than "/", so it must win even though the
        // "/" rule is listed first.
        let grpc = config
            .policy_for("/sui.rpc.v2.LedgerService/GetServiceInfo", None)
            .payment;
        assert_eq!(grpc.pay_to, format!("0x{}", "3".repeat(64)));
        assert_eq!(grpc.amount, "5000");
        assert_eq!(grpc.description, "gRPC calls");

        let graphql = config.policy_for("/graphql", None).payment;
        assert_eq!(graphql.amount, "100");
        assert_eq!(graphql.description, "cheap default");
    }

    #[test]
    fn unset_route_fields_fall_back_to_the_defaults() {
        let config = parse(&routed_yaml()).unwrap();
        // The "/" rule sets no pay_to, so the default wallet applies.
        assert_eq!(
            config.policy_for("/graphql", None).payment.pay_to,
            TEST_PAY_TO
        );
        // And unrelated fields are untouched.
        assert_eq!(
            config.policy_for("/graphql", None).payment.network,
            "sui:testnet"
        );
    }

    /// Base config plus named policies — the Envoy-driven mechanism, which
    /// duplicates no path information.
    fn policy_yaml() -> String {
        format!(
            r#"{}
policies:
  grpc:
    pay_to: "0x{}"
    amount: "5000"
    description: "gRPC calls"
  graphql:
    amount: "100"
routes:
  - path_prefix: "/graphql"
    amount: "77"
"#,
            base_yaml(),
            "4".repeat(64)
        )
    }

    #[test]
    fn a_named_policy_selects_its_terms() {
        let config = parse(&policy_yaml()).unwrap();
        // Path is deliberately unrelated: the policy name alone decides, which
        // is the point — Envoy already matched the route.
        let terms = config.policy_for("/whatever", Some("grpc")).payment;
        assert_eq!(terms.pay_to, format!("0x{}", "4".repeat(64)));
        assert_eq!(terms.amount, "5000");
    }

    #[test]
    fn a_named_policy_outranks_a_path_prefix_rule() {
        let config = parse(&policy_yaml()).unwrap();
        // "/graphql" matches the routes[] rule (77), but the policy wins (100).
        let terms = config.policy_for("/graphql", Some("graphql")).payment;
        assert_eq!(terms.amount, "100");
    }

    #[test]
    fn an_unknown_policy_falls_back_instead_of_failing() {
        let config = parse(&policy_yaml()).unwrap();
        assert!(config.is_unknown_policy("typo"));
        // Falls through to the path-prefix rule rather than erroring.
        let terms = config.policy_for("/graphql", Some("typo")).payment;
        assert_eq!(terms.amount, "77");
    }

    #[test]
    fn rejects_a_policy_with_an_invalid_wallet() {
        let yaml = policy_yaml().replace(&format!("0x{}", "4".repeat(64)), "0xnope");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("policy"),
            "error should name the policy: {err}"
        );
    }

    #[test]
    fn rejects_a_route_with_an_invalid_wallet() {
        let yaml = routed_yaml().replace(&format!("0x{}", "3".repeat(64)), "0xnope");
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("route"), "error should name the route: {err}");
    }

    #[test]
    fn rejects_a_route_with_a_non_numeric_amount() {
        let yaml = routed_yaml().replace(r#"amount: "5000""#, r#"amount: "free""#);
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn rejects_redis_backend_without_a_url() {
        let yaml = format!("{}\nstore:\n  backend: redis\n", base_yaml());
        let err = parse(&yaml).unwrap_err().to_string();
        assert!(err.contains("redis_url"), "got: {err}");
    }

    #[test]
    fn defaults_to_the_memory_backend_when_store_is_omitted() {
        let config = parse(&base_yaml()).unwrap();
        assert_eq!(config.store.backend, StoreBackend::Memory);
    }

    #[test]
    fn rejects_zero_window() {
        let yaml = base_yaml().replace("window_secs: 60", "window_secs: 0");
        assert!(parse(&yaml).is_err());
    }

    #[test]
    fn rejects_zero_quota() {
        let yaml = base_yaml().replace("quota: 100", "quota: 0");
        assert!(parse(&yaml).is_err());
    }
}
