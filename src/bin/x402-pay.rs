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

use anyhow::{Context, Result, bail};
use clap::Parser;
use x402_verifier::payclient;

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

    let headers: Vec<(String, String)> = args
        .headers
        .iter()
        .map(|h| {
            let (name, value) = h
                .split_once(':')
                .with_context(|| format!("header {h:?} is not `Name: value`"))?;
            Ok((name.trim().to_string(), value.trim().to_string()))
        })
        .collect::<Result<_>>()?;

    // ---- 1. Ask for the resource, expect a challenge --------------------
    let first =
        payclient::send(&client, &args.method, &args.url, &headers, &args.data, None).await?;
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
    let key = payclient::load_key()?;
    println!("  paying as {}", key.public_key().derive_address());

    let header =
        payclient::build_payment_header(&args.rpc, &key, &challenge.resource.url, terms).await?;

    if args.dry_run {
        println!("\n--dry-run: built and signed, not sent");
        println!("PAYMENT-SIGNATURE: {header}");
        return Ok(());
    }

    // ---- 5. Resend with the payment -------------------------------------
    println!("\nretrying with payment…");
    let paid = payclient::send(
        &client,
        &args.method,
        &args.url,
        &headers,
        &args.data,
        Some(&header),
    )
    .await?;
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
