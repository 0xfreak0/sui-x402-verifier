//! x402 v2 wire types, header codecs, and the facilitator.
//!
//! # Header case
//!
//! Envoy normalizes incoming HTTP header names to lowercase before handing
//! them to ext_authz, so every *lookup* constant here is lowercase. Response
//! header constants keep the spec's uppercase spelling purely for readability
//! on the wire; HTTP header names are case-insensitive.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};

use crate::config::{PaymentConfig, VerificationMode};

/// Protocol version this service speaks.
pub const X402_VERSION: u32 = 2;

/// Request header carrying a signed payment authorization (lowercase: lookup).
pub const HEADER_PAYMENT_SIGNATURE: &str = "payment-signature";
/// Request header carrying a previously issued session token (lowercase: lookup).
pub const HEADER_PAYMENT_SESSION: &str = "x-payment-session";

/// Response header carrying the payment challenge.
pub const HEADER_PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";
/// Response header carrying the settlement receipt.
pub const HEADER_PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// Terms a client must satisfy to unlock the paid tier.
///
/// Mirrors the x402 v2 `PaymentRequirements` object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub max_amount_required: String,
    /// The resource being paid for; we populate this with the request path.
    pub resource: String,
    pub description: String,
    pub mime_type: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub asset: String,
}

impl PaymentRequirements {
    /// Build the advertised terms for a specific resource path.
    pub fn from_config(payment: &PaymentConfig, resource: impl Into<String>) -> Self {
        Self {
            scheme: payment.scheme.clone(),
            network: payment.network.clone(),
            max_amount_required: payment.max_amount_required.clone(),
            resource: resource.into(),
            description: payment.description.clone(),
            // Describes the representation of the paid resource. The proxy
            // fronts both GraphQL (JSON) and gRPC; JSON is advertised because
            // gRPC clients never read this field, while HTTP clients do.
            mime_type: "application/json".to_string(),
            pay_to: payment.pay_to.clone(),
            max_timeout_seconds: payment.max_timeout_seconds,
            asset: payment.asset.clone(),
        }
    }
}

/// Body/header payload of a `402 Payment Required` challenge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u32,
    /// Why the request was refused, e.g. free-tier exhaustion.
    pub error: String,
    /// Payment options; a client picks one. We advertise exactly one.
    pub accepts: Vec<PaymentRequirements>,
}

impl PaymentRequired {
    pub fn new(error: impl Into<String>, accepts: Vec<PaymentRequirements>) -> Self {
        Self {
            x402_version: X402_VERSION,
            error: error.into(),
            accepts,
        }
    }
}

/// Sui-specific body of an `exact`-scheme payment.
///
/// `transaction_bytes` is a base64 BCS-serialized `TransactionData` and
/// `signatures` are base64 `flag || sig || pubkey` blobs — exactly the shape
/// Sui's `TransactionExecutionService.ExecuteTransaction` expects, so
/// settlement is a passthrough rather than a re-encode.
///
/// # Producing this in a browser
///
/// A wallet extension (Slush, Suiet, …) via `@mysten/dapp-kit` fills these two
/// fields directly. Use **`signTransaction`, not `signAndExecuteTransaction`**:
/// x402 needs a signed-but-unsubmitted authorization, because the *facilitator*
/// is what submits it. `useSignTransaction` returns `{ bytes, signature }`,
/// which map onto `transaction_bytes` and `signatures[0]` unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SuiExactPayload {
    pub transaction_bytes: String,
    #[serde(default)]
    pub signatures: Vec<String>,
    /// Advisory sender hint. Honored **only** in `stub-accept-all` mode;
    /// `sui-grpc` mode recovers the payer from the signature and ignores this,
    /// because a client-supplied address is not evidence of anything.
    #[serde(default)]
    pub payer: Option<String>,
}

/// A client's signed payment authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    pub payload: SuiExactPayload,
}

/// Receipt returned after settlement, echoed in `PAYMENT-RESPONSE`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    /// On-chain transaction digest.
    pub transaction: String,
    pub network: String,
    pub payer: String,
}

/// Encode a value as base64(JSON) for transport in an HTTP header.
///
/// Headers cannot carry raw JSON safely (commas and quotes confuse
/// intermediaries), hence the base64 wrapper mandated by x402.
pub fn encode_header<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(B64.encode(serde_json::to_vec(value)?))
}

/// Errors produced while decoding a base64(JSON) header.
#[derive(Debug, thiserror::Error)]
pub enum HeaderDecodeError {
    #[error("header is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("header is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Decode a base64(JSON) header value.
pub fn decode_header<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T, HeaderDecodeError> {
    let bytes = B64.decode(raw.trim())?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Reasons a payment can be refused.
#[derive(Debug, thiserror::Error)]
pub enum FacilitatorError {
    #[error("unsupported x402 version {got}, expected {expected}")]
    VersionMismatch { got: u32, expected: u32 },
    #[error("scheme mismatch: payment is {got:?}, resource requires {expected:?}")]
    SchemeMismatch { got: String, expected: String },
    #[error("network mismatch: payment is {got:?}, resource requires {expected:?}")]
    NetworkMismatch { got: String, expected: String },
    #[error("payment payload is missing transaction bytes")]
    EmptyTransaction,
    #[error("payment payload carries no signature")]
    MissingSignature,
    #[error("on-chain verification is not implemented yet (verification_mode: sui-grpc)")]
    NotImplemented,
}

/// Verifies and settles x402 payments.
///
/// Today this is a protocol-plumbing stub. The real implementation maps onto
/// the Sui fullnode gRPC v2 API as follows:
///
/// | Step | Sui gRPC call |
/// |------|---------------|
/// | recover/validate signer | `SignatureVerificationService.VerifySignature` |
/// | check payer can afford it | `StateService.GetBalance` |
/// | confirm the tx would land | `TransactionExecutionService.SimulateTransaction` |
/// | settle | `TransactionExecutionService.ExecuteTransaction` |
///
/// Note that Sui fullnodes removed JSON-RPC; gRPC is the only supported path.
#[derive(Debug, Clone)]
pub struct Facilitator {
    mode: VerificationMode,
    #[allow(dead_code)] // Consumed by the sui-grpc implementation.
    grpc_url: String,
    network: String,
}

impl Facilitator {
    pub fn new(mode: VerificationMode, grpc_url: String, network: String) -> Self {
        Self {
            mode,
            grpc_url,
            network,
        }
    }

    /// Validate a payment and, on success, move funds.
    ///
    /// Structural checks run in every mode so that malformed payloads are
    /// rejected identically whether or not the chain is in the loop.
    pub async fn verify_and_settle(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettlementResponse, FacilitatorError> {
        if payload.x402_version != X402_VERSION {
            return Err(FacilitatorError::VersionMismatch {
                got: payload.x402_version,
                expected: X402_VERSION,
            });
        }
        if payload.scheme != requirements.scheme {
            return Err(FacilitatorError::SchemeMismatch {
                got: payload.scheme.clone(),
                expected: requirements.scheme.clone(),
            });
        }
        if payload.network != requirements.network {
            return Err(FacilitatorError::NetworkMismatch {
                got: payload.network.clone(),
                expected: requirements.network.clone(),
            });
        }
        if payload.payload.transaction_bytes.trim().is_empty() {
            return Err(FacilitatorError::EmptyTransaction);
        }
        if payload.payload.signatures.is_empty() {
            return Err(FacilitatorError::MissingSignature);
        }

        match self.mode {
            VerificationMode::StubAcceptAll => {
                let payer = payload
                    .payload
                    .payer
                    .clone()
                    .unwrap_or_else(|| "0xunknown".to_string());

                tracing::warn!(
                    payer = %payer,
                    "STUB MODE: accepting payment without on-chain verification or settlement"
                );

                Ok(SettlementResponse {
                    success: true,
                    // Clearly not a real digest, so stub receipts can never be
                    // mistaken for evidence of an on-chain transfer.
                    transaction: "stub-not-settled-on-chain".to_string(),
                    network: self.network.clone(),
                    payer,
                })
            }
            VerificationMode::SuiGrpc => Err(FacilitatorError::NotImplemented),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            max_amount_required: "1000".into(),
            resource: "/sui.rpc.v2.LedgerService/GetServiceInfo".into(),
            description: "test".into(),
            mime_type: "application/grpc".into(),
            pay_to: "0xabc".into(),
            max_timeout_seconds: 60,
            asset: "0xa1::usdc::USDC".into(),
        }
    }

    fn payload() -> PaymentPayload {
        PaymentPayload {
            x402_version: X402_VERSION,
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            payload: SuiExactPayload {
                transaction_bytes: "AAAA".into(),
                signatures: vec!["BBBB".into()],
                payer: Some("0xpayer".into()),
            },
        }
    }

    fn stub() -> Facilitator {
        Facilitator::new(
            VerificationMode::StubAcceptAll,
            "https://fullnode.testnet.sui.io:443".into(),
            "sui:testnet".into(),
        )
    }

    #[test]
    fn header_roundtrips_through_base64_json() {
        let required = PaymentRequired::new("payment required", vec![requirements()]);
        let encoded = encode_header(&required).unwrap();
        // Must be transport-safe: no characters needing header quoting.
        assert!(!encoded.contains(','));
        let decoded: PaymentRequired = decode_header(&encoded).unwrap();
        assert_eq!(decoded, required);
    }

    #[test]
    fn decode_rejects_non_base64() {
        let err = decode_header::<PaymentRequired>("!!!not base64!!!").unwrap_err();
        assert!(matches!(err, HeaderDecodeError::Base64(_)));
    }

    #[test]
    fn decode_rejects_valid_base64_that_is_not_json() {
        let raw = B64.encode(b"plain text, not json");
        let err = decode_header::<PaymentRequired>(&raw).unwrap_err();
        assert!(matches!(err, HeaderDecodeError::Json(_)));
    }

    #[test]
    fn payment_requirements_serialize_as_camel_case() {
        // The x402 spec is camelCase on the wire; our structs are snake_case.
        let json = serde_json::to_string(&requirements()).unwrap();
        assert!(json.contains("maxAmountRequired"), "got: {json}");
        assert!(json.contains("payTo"), "got: {json}");
        assert!(!json.contains("max_amount_required"), "got: {json}");
    }

    #[tokio::test]
    async fn stub_accepts_a_well_formed_payment() {
        let receipt = stub()
            .verify_and_settle(&payload(), &requirements())
            .await
            .unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.payer, "0xpayer");
        // Stub receipts must not look like real digests.
        assert_eq!(receipt.transaction, "stub-not-settled-on-chain");
    }

    #[tokio::test]
    async fn stub_still_rejects_scheme_mismatch() {
        let mut p = payload();
        p.scheme = "upto".into();
        let err = stub()
            .verify_and_settle(&p, &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::SchemeMismatch { .. }));
    }

    #[tokio::test]
    async fn stub_still_rejects_network_mismatch() {
        // Guards against a mainnet-signed payment unlocking a testnet resource.
        let mut p = payload();
        p.network = "sui:mainnet".into();
        let err = stub()
            .verify_and_settle(&p, &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::NetworkMismatch { .. }));
    }

    #[tokio::test]
    async fn stub_still_rejects_version_mismatch() {
        let mut p = payload();
        p.x402_version = 1;
        let err = stub()
            .verify_and_settle(&p, &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::VersionMismatch { .. }));
    }

    #[tokio::test]
    async fn stub_rejects_empty_or_unsigned_transactions() {
        let mut empty = payload();
        empty.payload.transaction_bytes = "   ".into();
        assert!(matches!(
            stub().verify_and_settle(&empty, &requirements()).await,
            Err(FacilitatorError::EmptyTransaction)
        ));

        let mut unsigned = payload();
        unsigned.payload.signatures.clear();
        assert!(matches!(
            stub().verify_and_settle(&unsigned, &requirements()).await,
            Err(FacilitatorError::MissingSignature)
        ));
    }

    #[tokio::test]
    async fn sui_grpc_mode_refuses_rather_than_falling_back_to_stub() {
        // The critical safety property: selecting the real mode before it
        // exists must deny payments, never silently accept them.
        let facilitator = Facilitator::new(
            VerificationMode::SuiGrpc,
            "https://fullnode.testnet.sui.io:443".into(),
            "sui:testnet".into(),
        );
        let err = facilitator
            .verify_and_settle(&payload(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::NotImplemented));
    }
}
