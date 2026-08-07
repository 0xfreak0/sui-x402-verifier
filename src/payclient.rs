//! Reusable x402 client for the Sui `exact` scheme.
//!
//! Shared by `x402-pay` (a CLI) and `x402-demo` (a pay-on-behalf service) so
//! there is one implementation of building, signing and presenting a payment
//! rather than two that can drift.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::proto::sui::rpc::v2 as pb;
use sui_sdk_types::Identifier;
use sui_sdk_types::{Address, Digest};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};

/// Gas budget for a coin-split-and-transfer. Generous: an underfunded budget
/// fails at execution, and the unused remainder is refunded.
pub const GAS_BUDGET: u64 = 10_000_000;

/// Smallest transfer Sui's gasless path executes, in base units of a 6-decimal
/// stablecoin: 0.01. Mirrors `config::GASLESS_MINIMUM_BASE_UNITS`, duplicated
/// because the client is usable without the server's config.
pub const GASLESS_MINIMUM: u64 = 10_000;

/// How a payment is funded. Tried in the order given to [`build_payment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentPath {
    /// Withdraw from the sender's address balance. Costs no gas at all.
    Gasless,
    /// Let a gas station pay. Advertised by the server as `extra.gasStation`.
    Sponsored,
    /// Split a `Coin` object and transfer it. The payer supplies SUI for gas.
    CoinObject,
}

impl PaymentPath {
    /// Parse a comma-separated list, for `--payment-paths`.
    pub fn parse_list(s: &str) -> Result<Vec<Self>> {
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| match p {
                "gasless" => Ok(Self::Gasless),
                "sponsored" => Ok(Self::Sponsored),
                "coin-object" | "coin_object" => Ok(Self::CoinObject),
                other => bail!(
                    "unknown payment path {other:?}; expected gasless, sponsored or coin-object"
                ),
            })
            .collect()
    }

    fn name(self) -> &'static str {
        match self {
            Self::Gasless => "gasless",
            Self::Sponsored => "sponsored",
            Self::CoinObject => "coin-object",
        }
    }
}

/// Cheapest for the payer first.
///
/// Gasless before sponsored on purpose: a payer who can fund themselves for free
/// should not spend someone else's gas budget to do it.
pub const DEFAULT_PAYMENT_PATHS: &[PaymentPath] = &[
    PaymentPath::Gasless,
    PaymentPath::Sponsored,
    PaymentPath::CoinObject,
];

/// Why a path was passed over.
///
/// Collected across every attempt so that exhausting all of them can say what
/// was tried and what each one needed, rather than "could not build a payment".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skipped {
    BelowGaslessFloor { amount: u64, floor: u64 },
    AddressBalanceShort { have: u64, need: u64 },
    NoGasStationAdvertised,
    SponsorshipNotImplemented,
    CoinObjectsShort { have: u64, need: u64 },
}

impl std::fmt::Display for Skipped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BelowGaslessFloor { amount, floor } => write!(
                f,
                "price {amount} is below the gasless floor of {floor}; Sui will not \
                 execute a gasless transfer that small"
            ),
            Self::AddressBalanceShort { have, need } => write!(
                f,
                "address balance holds {have}, needs {need}. Coin objects do not count — \
                 move funds across once with `0x2::coin::send_funds` (costs gas once)"
            ),
            Self::NoGasStationAdvertised => {
                write!(f, "the server advertised no extra.gasStation")
            }
            Self::SponsorshipNotImplemented => write!(
                f,
                "a gas station was advertised but the interactive sponsorship \
                 protocol is not implemented here"
            ),
            Self::CoinObjectsShort { have, need } => {
                write!(f, "Coin objects hold {have}, needs {need}")
            }
        }
    }
}

/// What a sender can actually spend, split the way the funding paths need it.
///
/// One `GetBalance` answers both questions: `balance` is the total, and it is
/// the sum of these two. Probing costs a single round trip no matter how many
/// paths get tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Funding {
    /// Spendable by the gasless path.
    pub address_balance: u64,
    /// Spendable by the coin-object path.
    pub coin_balance: u64,
}

/// Read the sender's spendable funds, split by where they live.
pub async fn funding(rpc: &str, owner: Address, coin_type: &str) -> Result<Funding> {
    let mut client = sui_rpc::Client::new(rpc).context("connecting to the fullnode")?;
    let response = client
        .state_client()
        .get_balance(
            pb::GetBalanceRequest::default()
                .with_owner(owner.to_string())
                .with_coin_type(coin_type.to_string()),
        )
        .await
        .context("GetBalance")?
        .into_inner();

    // An address that has never held this coin has no balance object at all,
    // which is zero rather than an error.
    let balance = response.balance.unwrap_or_default();
    Ok(Funding {
        address_balance: balance.address_balance.unwrap_or_default(),
        coin_balance: balance.coin_balance.unwrap_or_default(),
    })
}

/// Build a PTB that credits `payee` with exactly `amount` of `asset`.
///
/// Tries each path in `paths` and takes the first whose preconditions hold.
///
/// | Path | Needs |
/// |---|---|
/// | Gasless | `amount` at or above [`GASLESS_MINIMUM`], and that much in the sender's **address balance** |
/// | Sponsored | the server to advertise `extra.gasStation` |
/// | Coin object | that much in `Coin` objects, plus SUI for gas |
///
/// # Why the address-balance probe is not optional
///
/// Gasless spends from the address balance, and USDC from a faucet or an
/// ordinary transfer arrives as `Coin` objects, so a freshly funded wallet has
/// an address balance of zero. Choosing gasless on `amount` alone — which is
/// what this did before — builds a transaction that cannot execute and hands
/// the payer a Sui-level error at first contact.
///
/// The probe doubles as an eligibility check. Funds only reach an address
/// balance through `send_funds`, which requires the coin type to support address
/// balances in the first place, so a non-zero address balance for `asset` is
/// itself evidence that `asset` can be spent this way.
///
/// # Skip versus fail
///
/// A path whose *preconditions* fail is skipped and the next is tried. A path
/// whose preconditions hold but whose build then fails returns that error
/// instead of falling through — degrading to a costlier path because something
/// broke is how a payer ends up paying gas forever without noticing.
pub async fn build_payment(
    rpc: &str,
    sender: Address,
    payee: Address,
    asset: &str,
    amount: u64,
    paths: &[PaymentPath],
    gas_station: Option<&str>,
) -> Result<sui_sdk_types::Transaction> {
    let funds = funding(rpc, sender, asset)
        .await
        .with_context(|| format!("reading {sender}'s {asset} balance"))?;

    let mut skipped: Vec<(PaymentPath, Skipped)> = Vec::new();
    for path in paths {
        match check(*path, amount, funds, gas_station) {
            Some(reason) => skipped.push((*path, reason)),
            None => {
                return match path {
                    PaymentPath::Gasless => {
                        build_gasless_payment(rpc, sender, payee, asset, amount).await
                    }
                    PaymentPath::CoinObject => {
                        build_coin_object_payment(rpc, sender, payee, asset, amount).await
                    }
                    // `check` never clears this path, so it cannot be reached.
                    PaymentPath::Sponsored => unreachable!("sponsorship is never available"),
                };
            }
        }
    }

    bail!("{}", no_path_available(asset, amount, funds, &skipped))
}

/// Preconditions for one path. `None` means it is usable.
fn check(
    path: PaymentPath,
    amount: u64,
    funds: Funding,
    gas_station: Option<&str>,
) -> Option<Skipped> {
    match path {
        PaymentPath::Gasless => {
            if amount < GASLESS_MINIMUM {
                return Some(Skipped::BelowGaslessFloor {
                    amount,
                    floor: GASLESS_MINIMUM,
                });
            }
            if funds.address_balance < amount {
                return Some(Skipped::AddressBalanceShort {
                    have: funds.address_balance,
                    need: amount,
                });
            }
            None
        }
        // Advertising a gas station is not the same as being able to use one:
        // the interactive protocol is unimplemented, so this path is always
        // skipped. The two reasons are distinct so the failure message can tell
        // "nobody offered" from "offered, cannot take it".
        PaymentPath::Sponsored => Some(match gas_station {
            None => Skipped::NoGasStationAdvertised,
            Some(_) => Skipped::SponsorshipNotImplemented,
        }),
        PaymentPath::CoinObject => {
            if funds.coin_balance < amount {
                return Some(Skipped::CoinObjectsShort {
                    have: funds.coin_balance,
                    need: amount,
                });
            }
            None
        }
    }
}

/// The message for a payer whose every path was unavailable.
fn no_path_available(
    asset: &str,
    amount: u64,
    funds: Funding,
    skipped: &[(PaymentPath, Skipped)],
) -> String {
    use std::fmt::Write;

    let mut out = format!(
        "no usable payment path for {amount} of {asset}. \
         Holdings: {} in the address balance, {} in Coin objects.",
        funds.address_balance, funds.coin_balance
    );
    for (path, why) in skipped {
        let _ = write!(out, "\n  {:<12} {why}", path.name());
    }
    if funds.address_balance == 0 && funds.coin_balance == 0 {
        out.push_str("\n  This address holds none of this coin. Fund it at https://faucet.circle.com (Sui Testnet).");
    }
    out
}

/// Withdraw from the sender's address balance and send it, paying no gas.
///
/// Only three Move functions are permitted on this path — `withdrawal_split`,
/// `redeem_funds`, `send_funds` — and the transaction may not write any object.
/// That is why this sends into the recipient's address balance rather than
/// splitting a coin and transferring it: creating a `Coin` would be an object
/// write and the transaction would be rejected.
async fn build_gasless_payment(
    rpc: &str,
    sender: Address,
    payee: Address,
    asset: &str,
    amount: u64,
) -> Result<sui_sdk_types::Transaction> {
    let mut rpc_client = sui_rpc::Client::new(rpc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let coin_type: sui_sdk_types::TypeTag = asset
        .parse()
        .with_context(|| format!("asset {asset:?} is not a Move type tag"))?;

    let mut builder = TransactionBuilder::new();
    builder.set_sender(sender);

    // Zero, not "cheap". This is what makes the transaction free; anything
    // else falls back to being charged against an address balance.
    builder.set_gas_price(0);
    builder.set_gas_budget(0);
    // The builder refuses to produce a transaction with no gas objects, but a
    // gasless one has none by definition — `GasPayment.objects` is allowed to
    // be empty at the protocol level. So satisfy the builder with a placeholder
    // and drop it below. Purely a limitation of sui-transaction-builder 0.3.
    builder.add_gas_objects(vec![ObjectInput::owned(Address::ZERO, 0, Digest::ZERO)]);

    // Reserves `amount` from the sender's address balance and redeems it into
    // a Coin, without any object being selected, pinned, or versioned.
    let coin = builder.funds_withdrawal_coin(coin_type.clone(), amount);
    let recipient = builder.pure(&payee);
    builder.move_call(
        Function::new(
            Address::TWO,
            Identifier::from_static("coin"),
            Identifier::from_static("send_funds"),
        )
        .with_type_args(vec![coin_type]),
        vec![coin, recipient],
    );

    // MANDATORY, not optional. Paying gas from an address balance removes the
    // replay protection that came from mutating a gas coin object, so the
    // transaction has to carry its own uniqueness: epoch bounds, the chain id,
    // and a nonce. Without this validators reject it.
    builder.set_expiration(current_epoch_expiration(&mut rpc_client, amount).await?);

    let mut transaction = builder
        .try_build()
        .map_err(|e| anyhow::anyhow!("building the gasless transaction: {e}"))?;

    // Remove the placeholder. What makes this free is the combination of no gas
    // objects, price zero and budget zero — leaving the object in place turns it
    // into an ordinary transaction against an object that does not exist.
    transaction.gas_payment.objects.clear();
    Ok(transaction)
}

/// The legacy path: select a coin, split it, transfer the piece.
///
/// Retained for sub-cent prices, which the gasless path refuses outright. Every
/// drawback this project documented lives here — the payer needs SUI, the coin
/// object is pinned at a version, and spending it elsewhere kills the
/// authorization after it has already been verified.
async fn build_coin_object_payment(
    rpc: &str,
    sender: Address,
    payee: Address,
    asset: &str,
    amount: u64,
) -> Result<sui_sdk_types::Transaction> {
    let mut rpc_client = sui_rpc::Client::new(rpc).map_err(|e| anyhow::anyhow!("{e}"))?;

    let payment_coin = pick_coin(&mut rpc_client, sender, asset, amount)
        .await
        .with_context(|| format!("finding a {asset} coin worth at least {amount}"))?;
    // Gas must be SUI and must be a different object from the coin being split.
    let gas_coin = pick_coin(&mut rpc_client, sender, "0x2::sui::SUI", GAS_BUDGET)
        .await
        .context("finding a SUI coin for gas")?;

    let gas_price = reference_gas_price(&mut rpc_client).await?;

    let mut builder = TransactionBuilder::new();
    builder.set_sender(sender);
    builder.set_gas_budget(GAS_BUDGET);
    builder.set_gas_price(gas_price);
    builder.add_gas_objects(vec![ObjectInput::owned(
        gas_coin.id,
        gas_coin.version,
        gas_coin.digest,
    )]);

    let coin = builder.object(ObjectInput::owned(
        payment_coin.id,
        payment_coin.version,
        payment_coin.digest,
    ));
    let split_amount = builder.pure(&amount);
    let parts = builder.split_coins(coin, vec![split_amount]);
    let recipient = builder.pure(&payee);
    builder.transfer_objects(parts, recipient);

    builder
        .try_build()
        .map_err(|e| anyhow::anyhow!("building the transaction: {e}"))
}

/// A `ValidDuring` expiry pinned to the current epoch, carrying a nonce.
///
/// Both epoch bounds must equal the current epoch — the sub-epoch timestamp
/// fields exist in the type but are documented as not yet implemented, which is
/// also why `maxTimeoutSeconds` still cannot be enforced on chain at finer than
/// epoch granularity.
async fn current_epoch_expiration(
    client: &mut sui_rpc::Client,
    salt: u64,
) -> Result<sui_sdk_types::TransactionExpiration> {
    let epoch = client
        .ledger_client()
        .get_epoch(
            pb::GetEpochRequest::default().with_read_mask(prost_types::FieldMask {
                paths: vec!["epoch".into()],
            }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("GetEpoch: {e}"))?
        .into_inner();
    let epoch_id = epoch
        .epoch
        .and_then(|e| e.epoch)
        .context("node returned no epoch")?;

    let chain: Digest = client
        .ledger_client()
        .get_service_info(pb::GetServiceInfoRequest::default())
        .await
        .map_err(|e| anyhow::anyhow!("GetServiceInfo: {e}"))?
        .into_inner()
        .chain_id
        .context("node returned no chain id")?
        .parse()
        .map_err(|e| anyhow::anyhow!("chain id is not a digest: {e}"))?;

    Ok(sui_sdk_types::TransactionExpiration::ValidDuring {
        min_epoch: Some(epoch_id),
        max_epoch: Some(epoch_id),
        min_timestamp: None,
        max_timestamp: None,
        chain,
        // Distinguishes two otherwise identical payments in the same epoch —
        // same sender, same payee, same amount would collide without it.
        nonce: nonce(salt),
    })
}

/// A per-transaction nonce.
///
/// Random rather than a counter: this client is stateless and several may run
/// against one wallet, so a counter would collide across processes.
fn nonce(salt: u64) -> u32 {
    use rand::RngCore;
    rand::rng().next_u32() ^ (salt as u32)
}

/// A coin object we can spend.
///
/// Public because `pick_coin` returns it; the fields stay private so callers
/// pass it back rather than reassembling one from parts.
pub struct Coin {
    id: Address,
    version: u64,
    digest: Digest,
}

/// Find an owned coin of `coin_type` holding at least `at_least`.
///
/// Deliberately picks a single sufficient coin rather than merging several:
/// merging would work, but it makes the transaction larger and the failure
/// modes harder to explain when a demo goes wrong.
pub async fn pick_coin(
    client: &mut sui_rpc::Client,
    owner: Address,
    coin_type: &str,
    at_least: u64,
) -> Result<Coin> {
    let response = client
        .state_client()
        .list_owned_objects(
            pb::ListOwnedObjectsRequest::default()
                .with_owner(owner.to_string())
                .with_object_type(format!("0x2::coin::Coin<{coin_type}>"))
                .with_read_mask(prost_types::FieldMask {
                    paths: vec![
                        "object_id".into(),
                        "version".into(),
                        "digest".into(),
                        "balance".into(),
                    ],
                }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("ListOwnedObjects: {e}"))?
        .into_inner();

    for object in response.objects {
        let balance = object.balance.unwrap_or(0);
        if balance < at_least {
            continue;
        }
        let (Some(id), Some(version), Some(digest)) =
            (object.object_id, object.version, object.digest)
        else {
            continue;
        };
        return Ok(Coin {
            id: id.parse().map_err(|e| anyhow::anyhow!("object id: {e}"))?,
            version,
            digest: digest.parse().map_err(|e| anyhow::anyhow!("digest: {e}"))?,
        });
    }

    bail!(
        "no {coin_type} coin owned by {owner} holds at least {at_least}. \
         Fund it — USDC at https://faucet.circle.com (Sui Testnet), SUI via `sui client faucet`."
    )
}

/// Current reference gas price, so the transaction is priced to land.
pub async fn reference_gas_price(client: &mut sui_rpc::Client) -> Result<u64> {
    let epoch = client
        .ledger_client()
        .get_epoch(
            pb::GetEpochRequest::default().with_read_mask(prost_types::FieldMask {
                paths: vec!["reference_gas_price".into()],
            }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("GetEpoch: {e}"))?
        .into_inner();
    Ok(epoch
        .epoch
        .and_then(|e| e.reference_gas_price)
        .unwrap_or(1000))
}

/// Load the signing key.
///
/// `X402_SUI_PRIVATE_KEY` wins; otherwise the first entry of the `sui` CLI
/// keystore, which is what a developer testing locally already has.
pub fn load_key() -> Result<Ed25519PrivateKey> {
    if let Ok(encoded) = std::env::var("X402_SUI_PRIVATE_KEY") {
        return Ed25519PrivateKey::from_suiprivkey(encoded.trim())
            .map_err(|e| anyhow::anyhow!("X402_SUI_PRIVATE_KEY is not a suiprivkey: {e}"));
    }

    let path = keystore_path();
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "reading {}. Set X402_SUI_PRIVATE_KEY, or install the sui CLI and create an address.",
            path.display()
        )
    })?;
    let entries: Vec<String> = serde_json::from_str(&raw).context("parsing the sui keystore")?;
    let first = entries.first().context("the sui keystore is empty")?;

    // Keystore entries are base64 of `flag || private key`; flag 0 is ed25519.
    let bytes = B64.decode(first).context("keystore entry is not base64")?;
    let Some((&flag, key)) = bytes.split_first() else {
        bail!("keystore entry is empty");
    };
    if flag != 0 {
        bail!(
            "the first keystore entry is not ed25519 (scheme flag {flag}); set X402_SUI_PRIVATE_KEY"
        );
    }
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| anyhow::anyhow!("keystore entry is not a 32-byte ed25519 key"))?;
    Ok(Ed25519PrivateKey::new(key))
}

fn keystore_path() -> PathBuf {
    std::env::var("SUI_KEYSTORE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            PathBuf::from(home).join(".sui/sui_config/sui.keystore")
        })
}
/// What the gateway reported is left, read from the `x-x402-*` response
/// headers.
///
/// Every field is optional because the two tiers are mutually exclusive — a
/// free-tier response carries the `free_*` trio, a paid one the `session_*`
/// trio, and a rejected payment carries neither. `None` means "not measured",
/// which a caller must be able to tell apart from a measured zero.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Meter {
    pub tier: Option<String>,
    pub free_remaining: Option<u64>,
    pub free_limit: Option<u64>,
    pub free_reset: Option<u64>,
    pub session_remaining: Option<u64>,
    pub session_quota: Option<u64>,
    pub session_expires: Option<u64>,
}

/// What one HTTP attempt told us.
pub struct Attempt {
    pub status: u16,
    pub body: String,
    pub payment_required: Option<wire::PaymentRequired>,
    pub payment_response: Option<wire::SettlementResponse>,
    pub session: Option<String>,
    pub meter: Meter,
    /// Wall time for the whole attempt, measured by this client.
    pub elapsed_ms: f64,
    /// Phase timings the gateway reported via `Server-Timing`, in ms.
    ///
    /// Self-reported rather than inferred: only the gateway knows how its own
    /// latency splits between deciding and settling.
    pub server_timing: Vec<(String, f64)>,
    /// Envoy's own measurement of the upstream call, from
    /// `x-envoy-upstream-service-time`. Present only when a request actually
    /// reached an upstream — a 402 never does.
    pub upstream_ms: Option<f64>,
}

/// Parse a `Server-Timing` value into `(name, milliseconds)` pairs.
///
/// Tolerant on purpose: this drives a display, so an unparseable metric is
/// dropped rather than failing the request that carried it.
fn parse_server_timing(raw: &str) -> Vec<(String, f64)> {
    raw.split(',')
        .filter_map(|metric| {
            let mut parts = metric.split(';');
            let name = parts.next()?.trim().to_string();
            let dur = parts.find_map(|p| p.trim().strip_prefix("dur=")?.parse::<f64>().ok())?;
            Some((name, dur))
        })
        .collect()
}

/// Send one request, optionally carrying a payment.
pub async fn send(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &str,
    payment: Option<&str>,
) -> Result<Attempt> {
    let method: reqwest::Method = method.parse().context("invalid HTTP method")?;
    let mut request = client.request(method, url);

    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if !body.is_empty() {
        request = request.body(body.to_string());
    }
    if let Some(payment) = payment {
        request = request.header("payment-signature", payment);
    }

    let started = std::time::Instant::now();
    let response = request.send().await.context("sending the request")?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let status = response.status().as_u16();

    let header = |name: &str| -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    // Two closures rather than one generic helper: each decodes into a
    // different type, and a shared closure would fix the first one's.
    let challenge: Option<wire::PaymentRequired> = header("payment-required")
        .and_then(|raw| B64.decode(raw.trim()).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let receipt: Option<wire::SettlementResponse> = header("payment-response")
        .and_then(|raw| B64.decode(raw.trim()).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let session = header("x-payment-session");
    let number = |name: &str| header(name).and_then(|v| v.trim().parse::<u64>().ok());
    let meter = Meter {
        tier: header("x-x402-tier"),
        free_remaining: number("x-x402-free-remaining"),
        free_limit: number("x-x402-free-limit"),
        free_reset: number("x-x402-free-reset"),
        session_remaining: number("x-x402-session-remaining"),
        session_quota: number("x-x402-session-quota"),
        session_expires: number("x-x402-session-expires"),
    };

    let server_timing = header("server-timing")
        .map(|raw| parse_server_timing(&raw))
        .unwrap_or_default();
    let upstream_ms =
        header("x-envoy-upstream-service-time").and_then(|v| v.trim().parse::<f64>().ok());

    Ok(Attempt {
        status,
        body: response.text().await.unwrap_or_default(),
        payment_required: challenge,
        payment_response: receipt,
        session,
        meter,
        elapsed_ms,
        server_timing,
        upstream_ms,
    })
}

/// Read an address's balance of one coin type, in base units.
///
/// Used by the demo to show funds actually leaving one wallet and arriving at
/// another — the part of a payment that a receipt alone does not make felt.
pub async fn balance(rpc: &str, owner: Address, coin_type: &str) -> Result<u64> {
    let mut client = sui_rpc::Client::new(rpc).context("connecting to the fullnode")?;
    let response = client
        .state_client()
        .get_balance(
            pb::GetBalanceRequest::default()
                .with_owner(owner.to_string())
                .with_coin_type(coin_type.to_string()),
        )
        .await
        .context("GetBalance")?
        .into_inner();

    // An address that has never held this coin has no balance object at all,
    // which is zero rather than an error.
    Ok(response.balance.and_then(|b| b.balance).unwrap_or_default())
}

/// The gas station a server advertised, if it did.
///
/// Lives in the scheme-specific `extra` bag, so it is absent on any challenge
/// from a server that does not sponsor.
pub fn advertised_gas_station(terms: &wire::PaymentRequirements) -> Option<&str> {
    terms.extra.as_ref()?.get("gasStation")?.as_str()
}

/// Build the base64 `PAYMENT-SIGNATURE` header for a set of terms.
pub async fn build_payment_header(
    rpc: &str,
    key: &Ed25519PrivateKey,
    resource_url: &str,
    terms: &wire::PaymentRequirements,
    paths: &[PaymentPath],
) -> Result<String> {
    let sender = key.public_key().derive_address();
    let amount: u64 = terms
        .amount
        .parse()
        .with_context(|| format!("amount {:?} is not an integer", terms.amount))?;
    let payee: Address = terms
        .pay_to
        .parse()
        .with_context(|| format!("payTo {:?} is not a Sui address", terms.pay_to))?;

    let transaction = build_payment(
        rpc,
        sender,
        payee,
        &terms.asset,
        amount,
        paths,
        advertised_gas_station(terms),
    )
    .await
    .with_context(|| {
        format!(
            "building the payment transaction for {amount} of {}",
            terms.asset
        )
    })?;
    let signature = key
        .sign_transaction(&transaction)
        .context("signing the payment")?;

    let payload = serde_json::json!({
        "x402Version": 2,
        "resource": { "url": resource_url },
        // Echo back the terms we accepted; the server re-checks every field.
        "accepted": {
            "scheme": terms.scheme,
            "network": terms.network,
            "amount": terms.amount,
            "asset": terms.asset,
            "payTo": terms.pay_to,
            "maxTimeoutSeconds": terms.max_timeout_seconds,
        },
        "payload": {
            "signature": B64.encode(signature.to_bytes()),
            "transaction": B64.encode(bcs::to_bytes(&transaction)?),
        },
    });
    Ok(B64.encode(serde_json::to_vec(&payload)?))
}

/// Minimal client-side mirrors of the wire types.
///
/// Deliberately separate from the server's: a client only needs to *read* the
/// challenge and receipt, and duplicating those two shapes is cheaper than
/// exposing the server's internals as a library.
pub mod wire {
    use serde::Deserialize;

    #[derive(Debug, Clone, serde::Serialize, Deserialize)]
    pub struct ResourceInfo {
        pub url: String,
    }

    #[derive(Debug, Clone, serde::Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PaymentRequirements {
        pub scheme: String,
        pub network: String,
        pub amount: String,
        pub asset: String,
        pub pay_to: String,
        pub max_timeout_seconds: u64,
        /// Scheme extras. Carries `gasStation` when the server sponsors, which
        /// is how the client learns the sponsored path is even on offer.
        /// Absent from most challenges, so it must not be required here.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub extra: Option<serde_json::Value>,
    }

    #[derive(Debug, Clone, serde::Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PaymentRequired {
        pub resource: ResourceInfo,
        pub accepts: Vec<PaymentRequirements>,
    }

    #[derive(Debug, Clone, serde::Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SettlementResponse {
        pub success: bool,
        #[serde(default)]
        pub error_reason: Option<String>,
        pub transaction: String,
        pub network: String,
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    const FLOOR: u64 = GASLESS_MINIMUM;

    fn funds(address_balance: u64, coin_balance: u64) -> Funding {
        Funding {
            address_balance,
            coin_balance,
        }
    }

    /// The bug this whole mechanism exists for. USDC from a faucet or an
    /// ordinary transfer arrives as Coin objects, so a wallet can hold plenty
    /// and still have an address balance of zero. Choosing gasless on amount
    /// alone builds a transaction that cannot execute.
    #[test]
    fn a_wallet_holding_only_coin_objects_does_not_get_routed_to_gasless() {
        let f = funds(0, 1_000_000);
        assert_eq!(
            check(PaymentPath::Gasless, FLOOR, f, None),
            Some(Skipped::AddressBalanceShort {
                have: 0,
                need: FLOOR
            })
        );
        assert_eq!(check(PaymentPath::CoinObject, FLOOR, f, None), None);
    }

    #[test]
    fn a_funded_address_balance_takes_the_gasless_path() {
        assert_eq!(
            check(PaymentPath::Gasless, FLOOR, funds(FLOOR, 0), None),
            None
        );
    }

    /// Sub-cent prices cannot go gasless at all, whatever the balance is.
    #[test]
    fn a_sub_cent_price_skips_gasless_even_with_a_full_address_balance() {
        assert_eq!(
            check(PaymentPath::Gasless, 10, funds(u64::MAX, 0), None),
            Some(Skipped::BelowGaslessFloor {
                amount: 10,
                floor: FLOOR
            })
        );
    }

    /// Advertising a gas station is not the same as being able to use one. The
    /// two reasons stay distinct so the failure message can tell "nobody
    /// offered" from "offered, cannot take it".
    #[test]
    fn sponsorship_reports_whether_it_was_offered_or_merely_unimplemented() {
        let f = funds(0, 0);
        assert_eq!(
            check(PaymentPath::Sponsored, FLOOR, f, None),
            Some(Skipped::NoGasStationAdvertised)
        );
        assert_eq!(
            check(
                PaymentPath::Sponsored,
                FLOOR,
                f,
                Some("https://gas.example.com")
            ),
            Some(Skipped::SponsorshipNotImplemented)
        );
    }

    /// A payer who cannot pay any way at all should be told what was tried and
    /// what each path wanted, not "could not build a payment".
    #[test]
    fn exhausting_every_path_names_all_of_them_and_why() {
        let f = funds(0, 5);
        let skipped = DEFAULT_PAYMENT_PATHS
            .iter()
            .filter_map(|p| check(*p, FLOOR, f, None).map(|why| (*p, why)))
            .collect::<Vec<_>>();
        assert_eq!(skipped.len(), 3, "no path should be usable here");

        let msg = no_path_available("0x2::usdc::USDC", FLOOR, f, &skipped);
        assert!(msg.contains("gasless"), "{msg}");
        assert!(msg.contains("sponsored"), "{msg}");
        assert!(msg.contains("coin-object"), "{msg}");
        // The actionable part: the payer has funds, just not where gasless
        // needs them, and the message has to say how to move them.
        assert!(msg.contains("send_funds"), "{msg}");
    }

    #[test]
    fn an_address_holding_none_of_the_coin_is_told_to_fund_it() {
        let f = funds(0, 0);
        let skipped = DEFAULT_PAYMENT_PATHS
            .iter()
            .filter_map(|p| check(*p, FLOOR, f, None).map(|why| (*p, why)))
            .collect::<Vec<_>>();
        let msg = no_path_available("0x2::usdc::USDC", FLOOR, f, &skipped);
        assert!(msg.contains("faucet.circle.com"), "{msg}");
    }

    #[test]
    fn payment_paths_parse_from_the_cli_spelling() {
        assert_eq!(
            PaymentPath::parse_list("gasless,sponsored,coin-object").unwrap(),
            DEFAULT_PAYMENT_PATHS.to_vec()
        );
        // Pinning one path is how the e2e script exercises each deterministically.
        assert_eq!(
            PaymentPath::parse_list(" coin-object ").unwrap(),
            vec![PaymentPath::CoinObject]
        );
        assert!(PaymentPath::parse_list("gasless,teleport").is_err());
    }

    /// A challenge with no `extra` at all is the common case and must not be
    /// mistaken for one advertising a gas station.
    #[test]
    fn a_gas_station_is_read_from_extra_only_when_present() {
        let mut terms = wire::PaymentRequirements {
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            amount: "10000".into(),
            asset: "0x2::usdc::USDC".into(),
            pay_to: "0x1111".into(),
            max_timeout_seconds: 60,
            extra: None,
        };
        assert_eq!(advertised_gas_station(&terms), None);

        terms.extra = Some(serde_json::json!({}));
        assert_eq!(advertised_gas_station(&terms), None);

        terms.extra = Some(serde_json::json!({ "gasStation": "https://gas.example.com" }));
        assert_eq!(
            advertised_gas_station(&terms),
            Some("https://gas.example.com")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_timing_parses_the_gateways_phases() {
        let phases = parse_server_timing("x402-decide;dur=412.5, x402-settle;dur=1203.0");
        assert_eq!(
            phases,
            vec![
                ("x402-decide".to_string(), 412.5),
                ("x402-settle".to_string(), 1203.0),
            ]
        );
    }

    #[test]
    fn server_timing_drops_metrics_it_cannot_read_rather_than_failing() {
        // This drives a display. One malformed metric must not cost the whole
        // trace, and must never fail the request that carried it.
        let phases = parse_server_timing("cache;desc=\"hit\", x402-decide;dur=7, junk");
        assert_eq!(phases, vec![("x402-decide".to_string(), 7.0)]);
    }

    #[test]
    fn server_timing_of_an_empty_header_is_empty_not_an_error() {
        assert!(parse_server_timing("").is_empty());
    }
}
