//! `x402-pay` — a real x402 client for the Sui `exact` scheme.
//!
//! Performs the full protocol against any x402 v2 endpoint:
//!
//! ```text
//!   1. request the resource            -> 402 Payment Required
//!   2. decode PAYMENT-REQUIRED         -> payTo, amount, asset, network
//!   3. build a PTB paying exactly that
//!   4. sign it locally
//!   5. resend with PAYMENT-SIGNATURE   -> 200 + receipt + session
//! ```
//!
//! # Why this exists
//!
//! `scheme_exact_sui.md` defines the Sui scheme, but at the time of writing no
//! client implements it — the official SDK ships mechanisms for aptos, avm, evm,
//! stellar and svm, and a GitHub search for x402 + sui returns nothing. So a
//! conformant Sui *server* had nothing that could pay it. This is that client.
//!
//! It replaces the bash test scaffolding, which shelled out to the `sui` CLI and
//! was therefore neither embeddable nor usable by anyone else.
//!
//! # Keys
//!
//! Reads the key from `X402_SUI_PRIVATE_KEY` (a `suiprivkey1…` string) or, by
//! default, the first key in the standard `sui` CLI keystore. It never writes
//! keys anywhere and never sends them over the wire — only the signature goes
//! out.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::Parser;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::proto::sui::rpc::v2 as pb;
use sui_sdk_types::{Address, Digest};
use sui_transaction_builder::{ObjectInput, TransactionBuilder};

/// Gas budget for a coin-split-and-transfer. Generous: an underfunded budget
/// fails at execution, and the unused remainder is refunded.
const GAS_BUDGET: u64 = 10_000_000;

#[derive(Parser, Debug)]
#[command(
    name = "x402-pay",
    about = "Pay an x402-gated endpoint with USDC on Sui",
    version
)]
struct Args {
    /// The gated URL to call.
    url: String,

    /// HTTP method.
    #[arg(short = 'X', long, default_value = "POST")]
    method: String,

    /// Request body.
    #[arg(short, long, default_value = "")]
    data: String,

    /// Extra headers, `Name: value`. Repeatable.
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Sui fullnode used to look up coins and gas.
    #[arg(long, default_value = "https://fullnode.testnet.sui.io:443")]
    rpc: String,

    /// Verify the payment without sending it to the resource.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::new();

    // ---- 1. Ask for the resource, expect a challenge --------------------
    let first = send(&client, &args, None).await?;
    if first.status != 402 {
        println!("{} (no payment required)", first.status);
        println!("{}", first.body);
        return Ok(());
    }

    let challenge = first
        .payment_required
        .context("402 without a PAYMENT-REQUIRED header; is this an x402 endpoint?")?;
    let terms = challenge
        .accepts
        .first()
        .context("challenge advertised no payment options")?;

    println!("402 Payment Required");
    println!("  resource  {}", challenge.resource.url);
    println!("  network   {}", terms.network);
    println!("  amount    {} of {}", terms.amount, terms.asset);
    println!("  payTo     {}", terms.pay_to);

    if terms.scheme != "exact" {
        bail!(
            "this client implements the `exact` scheme; the resource wants `{}`",
            terms.scheme
        );
    }

    // ---- 2-4. Build and sign a transaction paying exactly that ----------
    let key = load_key()?;
    let sender = key.public_key().derive_address();
    println!("  paying as {sender}");

    let amount: u64 = terms
        .amount
        .parse()
        .with_context(|| format!("amount {:?} is not an integer", terms.amount))?;
    let payee: Address = terms
        .pay_to
        .parse()
        .with_context(|| format!("payTo {:?} is not a Sui address", terms.pay_to))?;

    let transaction = build_payment(&args.rpc, sender, payee, &terms.asset, amount)
        .await
        .context("building the payment transaction")?;

    let signature = key
        .sign_transaction(&transaction)
        .context("signing the payment")?;

    let payload = serde_json::json!({
        "x402Version": 2,
        "resource": { "url": challenge.resource.url },
        // Echo back the terms we accepted. The server re-checks every field.
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
    let header = B64.encode(serde_json::to_vec(&payload)?);

    if args.dry_run {
        println!("\n--dry-run: built and signed, not sent");
        println!("PAYMENT-SIGNATURE: {header}");
        return Ok(());
    }

    // ---- 5. Resend with the payment -------------------------------------
    println!("\nretrying with payment…");
    let paid = send(&client, &args, Some(&header)).await?;
    println!("{}", paid.status);

    if let Some(receipt) = &paid.payment_response {
        if receipt.success {
            println!(
                "  settled  tx {} on {}",
                receipt.transaction, receipt.network
            );
        } else {
            println!(
                "  refused  {}",
                receipt.error_reason.as_deref().unwrap_or("no reason given")
            );
        }
    }
    if let Some(session) = &paid.session {
        println!("  session  {session}");
        println!("           present this as `x-payment-session` to reuse the paid tier");
    }
    println!("\n{}", paid.body);

    if paid.status != 200 {
        std::process::exit(1);
    }
    Ok(())
}

/// Build a PTB that credits `payee` with exactly `amount` of `asset`.
///
/// Splits a coin rather than transferring one whole, because the scheme is
/// `exact` and the server asserts the recipient's balance change equals the
/// advertised price.
async fn build_payment(
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
struct Coin {
    id: Address,
    version: u64,
    digest: Digest,
}

/// Find an owned coin of `coin_type` holding at least `at_least`.
///
/// Deliberately picks a single sufficient coin rather than merging several:
/// merging would work, but it makes the transaction larger and the failure
/// modes harder to explain when a demo goes wrong.
async fn pick_coin(
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
async fn reference_gas_price(client: &mut sui_rpc::Client) -> Result<u64> {
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
fn load_key() -> Result<Ed25519PrivateKey> {
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

/// What one HTTP attempt told us.
struct Attempt {
    status: u16,
    body: String,
    payment_required: Option<x402_types::PaymentRequired>,
    payment_response: Option<x402_types::SettlementResponse>,
    session: Option<String>,
}

async fn send(client: &reqwest::Client, args: &Args, payment: Option<&str>) -> Result<Attempt> {
    let method: reqwest::Method = args.method.parse().context("invalid HTTP method")?;
    let mut request = client.request(method, &args.url);

    for header in &args.headers {
        let (name, value) = header
            .split_once(':')
            .with_context(|| format!("header {header:?} is not `Name: value`"))?;
        request = request.header(name.trim(), value.trim());
    }
    if !args.data.is_empty() {
        request = request.body(args.data.clone());
    }
    if let Some(payment) = payment {
        request = request.header("payment-signature", payment);
    }

    let response = request.send().await.context("sending the request")?;
    let status = response.status().as_u16();

    let decode = |name: &str| -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let challenge = decode("payment-required")
        .and_then(|raw| B64.decode(raw.trim()).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let receipt = decode("payment-response")
        .and_then(|raw| B64.decode(raw.trim()).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let session = decode("x-payment-session");

    Ok(Attempt {
        status,
        body: response.text().await.unwrap_or_default(),
        payment_required: challenge,
        payment_response: receipt,
        session,
    })
}

/// Minimal client-side mirrors of the wire types.
///
/// Deliberately separate from the server's: a client only needs to *read* the
/// challenge and receipt, and duplicating those two shapes is cheaper than
/// exposing the server's internals as a library.
mod x402_types {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct ResourceInfo {
        pub url: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PaymentRequirements {
        pub scheme: String,
        pub network: String,
        pub amount: String,
        pub asset: String,
        pub pay_to: String,
        pub max_timeout_seconds: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PaymentRequired {
        pub resource: ResourceInfo,
        pub accepts: Vec<PaymentRequirements>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SettlementResponse {
        pub success: bool,
        #[serde(default)]
        pub error_reason: Option<String>,
        pub transaction: String,
        pub network: String,
    }
}
