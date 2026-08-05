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
use sui_sdk_types::{Address, Digest};
use sui_transaction_builder::{ObjectInput, TransactionBuilder};

/// Gas budget for a coin-split-and-transfer. Generous: an underfunded budget
/// fails at execution, and the unused remainder is refunded.
pub const GAS_BUDGET: u64 = 10_000_000;

/// Build a PTB that credits `payee` with exactly `amount` of `asset`.
///
/// Splits a coin rather than transferring one whole, because the scheme is
/// `exact` and the server asserts the recipient's balance change equals the
/// advertised price.
pub async fn build_payment(
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
    let upstream_ms = header("x-envoy-upstream-service-time")
        .and_then(|v| v.trim().parse::<f64>().ok());

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
    Ok(response
        .balance
        .and_then(|b| b.balance)
        .unwrap_or_default())
}

/// Build the base64 `PAYMENT-SIGNATURE` header for a set of terms.
pub async fn build_payment_header(
    rpc: &str,
    key: &Ed25519PrivateKey,
    resource_url: &str,
    terms: &wire::PaymentRequirements,
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

    let transaction = build_payment(rpc, sender, payee, &terms.asset, amount)
        .await
        .context("building the payment transaction")?;
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
