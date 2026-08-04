//! x402 v2 wire types, header codecs, and the facilitator.
//!
//! Types here mirror `docs/spec/upstream/x402-specification-v2.md` §5 and
//! `scheme_exact_sui.md`. The spec's own JSON examples are vendored into
//! `tests/fixtures/` and round-tripped by the tests at the bottom of this file,
//! so a shape that drifts from the spec fails CI rather than failing silently
//! against a real client.
//!
//! # Header case
//!
//! Envoy normalizes incoming HTTP header names to lowercase before handing
//! them to ext_authz, so every *lookup* constant here is lowercase. Response
//! header constants keep the spec's uppercase spelling purely for readability
//! on the wire; HTTP header names are case-insensitive.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// Description of the protected resource (§5.1.2, `ResourceInfo`).
///
/// In v2 this is a *required top-level object* on `PaymentRequired`. In v1 its
/// fields lived inside each `PaymentRequirements` entry, which is where this
/// implementation had them until the conformance review.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// Full URL of the protected resource — not a bare path.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// One acceptable way to pay (§5.1.2).
///
/// Note `amount`, not `maxAmountRequired`: v2 renamed the field, and the
/// scheme is `exact`, so it is the precise price rather than a ceiling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    /// CAIP-2 network identifier, e.g. `sui:testnet`.
    pub network: String,
    /// Price in the asset's smallest unit. A string, not an integer, because
    /// x402 carries amounts as strings to dodge the 2^53 precision cliff in
    /// JSON parsers.
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    /// Scheme-specific extras. For Sui this carries `gasStation` when the
    /// facilitator supports sponsorship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl PaymentRequirements {
    /// Build the advertised terms from resolved config.
    pub fn from_config(payment: &PaymentConfig) -> Self {
        Self {
            scheme: payment.scheme.clone(),
            network: payment.network.clone(),
            amount: payment.amount.clone(),
            asset: payment.asset.clone(),
            pay_to: payment.pay_to.clone(),
            max_timeout_seconds: payment.max_timeout_seconds,
            extra: payment.gas_station.as_ref().map(|url| {
                // Per scheme_exact_sui.md Appendix, a facilitator advertises
                // sponsorship support by publishing a gas station URL here.
                serde_json::json!({ "gasStation": url })
            }),
        }
    }
}

/// Body of a `402 Payment Required` challenge (§5.1.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u32,
    /// Human-readable explanation. Optional in the spec; always set here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    /// Payment options; a client picks one. We advertise exactly one.
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl PaymentRequired {
    pub fn new(
        error: impl Into<String>,
        resource: ResourceInfo,
        accepts: Vec<PaymentRequirements>,
    ) -> Self {
        Self {
            x402_version: X402_VERSION,
            error: Some(error.into()),
            resource,
            accepts,
            extensions: None,
        }
    }
}

/// Sui-specific body of an `exact`-scheme payment (`scheme_exact_sui.md`).
///
/// Exactly two fields, both base64: the user's signature, and the serialized
/// Sui `TransactionData` it signs.
///
/// # Producing this in a browser
///
/// A wallet extension (Slush, Suiet, …) via `@mysten/dapp-kit` fills these
/// directly. Use **`signTransaction`, not `signAndExecuteTransaction`**: x402
/// needs a signed-but-unsubmitted authorization, because the *facilitator*
/// submits it. `useSignTransaction` returns `{ bytes, signature }`, which map
/// onto `transaction` and `signature` respectively.
///
/// # Why there is no `payer` field
///
/// The payer is *recovered from the signature*, never taken from the client. A
/// self-declared payer is not evidence of anything.
///
/// # Why `signature` is scalar, not an array
///
/// Sponsored transactions need a second signature, but per the spec's Appendix
/// the client sends one and the *facilitator* adds its own sponsor signature at
/// settle time. So the wire format carries exactly one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SuiExactPayload {
    /// Base64 user signature over the transaction.
    pub signature: String,
    /// Base64 BCS-serialized Sui `TransactionData`.
    pub transaction: String,
}

/// A client's signed payment authorization (§5.2.1).
///
/// `payload` is deliberately untyped here: it is scheme-specific, and keeping
/// the envelope generic lets this service parse (and correctly reject with
/// `unsupported_scheme`) payloads for schemes it does not implement, rather
/// than failing deserialization of the whole request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    /// Which of the advertised `accepts` entries the client chose.
    pub accepted: PaymentRequirements,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Settlement receipt, echoed in `PAYMENT-RESPONSE` (§5.3).
///
/// Sent on **both** paths: success carries a transaction digest, failure
/// carries an `errorReason` and an empty `transaction`. Emitting it only on
/// success would make "your payment was rejected" indistinguishable from "you
/// never paid".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    /// Machine-readable code from §9. Omitted when successful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Transaction digest; empty string when settlement failed.
    pub transaction: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Facilitator `/verify` result (§5.4.2).
///
/// Constructed by the facilitator HTTP interface, which is Phase 2 work; the
/// type lands here with the rest of the wire format so it is covered by the
/// same conformance fixtures.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// Identifier for this service's session extension.
///
/// §5.1.2's `extensions` map is the sanctioned way to add optional
/// functionality beyond core payment mechanics, which is exactly what paid
/// sessions are. Namespaced so it cannot collide with a future standard one.
pub const SESSION_EXTENSION: &str = "sui-x402-verifier.session.v1";

/// Advertise the session extension in a `PaymentRequired`.
///
/// `info` tells a client that a settled payment buys a reusable token rather
/// than a single request, and `schema` describes the shape it will come back
/// in — per §5.1.2 an extension carries both.
pub fn session_extension_advertisement(
    quota: u64,
    duration_secs: u64,
    header: &str,
) -> serde_json::Value {
    serde_json::json!({
        SESSION_EXTENSION: {
            "info": {
                "description": "A settled payment mints a reusable session token                                 covering many requests, returned in the                                 PAYMENT-RESPONSE extensions and presented on                                 subsequent requests.",
                "header": header,
                "quota": quota,
                "durationSeconds": duration_secs,
            },
            "schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["token"],
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "Opaque session token. Present it on later                                         requests to reuse the paid tier.",
                    },
                    "quota": { "type": "integer", "minimum": 0 },
                    "durationSeconds": { "type": "integer", "minimum": 0 },
                },
            },
        }
    })
}

/// Carry a freshly minted session token back in a settlement receipt.
pub fn session_extension_grant(token: &str, quota: u64, duration_secs: u64) -> serde_json::Value {
    serde_json::json!({
        SESSION_EXTENSION: {
            "info": { "token": token, "quota": quota, "durationSeconds": duration_secs }
        }
    })
}

/// Pull a session token out of a client's echoed `extensions`.
///
/// Returns `None` when the extension is absent or malformed; callers fall back
/// to the deprecated raw header.
pub fn session_token_from_extensions(extensions: Option<&serde_json::Value>) -> Option<&str> {
    extensions?
        .get(SESSION_EXTENSION)?
        .get("info")?
        .get("token")?
        .as_str()
}

/// Facilitator `/supported` entry (§7.3.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Facilitator `GET /supported` response (§7.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
    /// Extension identifiers this facilitator implements.
    pub extensions: Vec<String>,
    /// CAIP-2 pattern -> public signer addresses.
    ///
    /// Empty here, and deliberately so: this facilitator holds no signing keys.
    /// It never sponsors a transaction, so there is no address for a client to
    /// verify against — which is also what makes "this service has custody of
    /// nothing" checkable rather than merely claimed.
    pub signers: std::collections::BTreeMap<String, Vec<String>>,
}

/// Facilitator `/verify` and `/settle` request body (§7.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorRequest {
    pub x402_version: u32,
    pub payment_payload: PaymentPayload,
    pub payment_requirements: PaymentRequirements,
}

/// Encode a value as base64(JSON) for transport in an HTTP header.
///
/// Headers cannot carry raw JSON safely (commas and quotes confuse
/// intermediaries), hence the base64 wrapper mandated by the HTTP transport.
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
///
/// Each maps onto a §9 standard error code via [`FacilitatorError::code`], so
/// clients get a machine-readable reason rather than a prose string.
#[derive(Debug, thiserror::Error)]
pub enum FacilitatorError {
    #[error("unsupported x402 version {got}, expected {expected}")]
    VersionMismatch { got: u32, expected: u32 },
    #[error("scheme mismatch: payment is {got:?}, resource requires {expected:?}")]
    SchemeMismatch { got: String, expected: String },
    #[error("network mismatch: payment is {got:?}, resource requires {expected:?}")]
    NetworkMismatch { got: String, expected: String },
    #[error("amount mismatch: payment offers {got:?}, resource costs {expected:?}")]
    AmountMismatch { got: String, expected: String },
    #[error("asset mismatch: payment is in {got:?}, resource requires {expected:?}")]
    AssetMismatch { got: String, expected: String },
    #[error("recipient mismatch: payment pays {got:?}, resource requires {expected:?}")]
    RecipientMismatch { got: String, expected: String },
    #[error("payment payload is not a valid {scheme} payload: {detail}")]
    MalformedPayload { scheme: String, detail: String },
    #[error("payment payload is missing the transaction")]
    EmptyTransaction,
    #[error("payment payload carries no signature")]
    MissingSignature,
    #[error("on-chain verification is not implemented yet (verification_mode: sui-grpc)")]
    NotImplemented,
}

impl FacilitatorError {
    /// The §9 standard error code for this failure.
    ///
    /// The per-scheme codes upstream are all EVM-named
    /// (`invalid_exact_evm_payload_*`) and **no Sui equivalents are defined**.
    /// Rather than invent parallel Sui names in the wire format — which would
    /// be indistinguishable from a real spec code to a client — every
    /// Sui-specific failure maps onto a generic code, with the specifics left
    /// to the human-readable message. See `docs/spec-gaps.md`.
    pub fn code(&self) -> &'static str {
        match self {
            FacilitatorError::VersionMismatch { .. } => "invalid_x402_version",
            FacilitatorError::SchemeMismatch { .. } => "invalid_scheme",
            FacilitatorError::NetworkMismatch { .. } => "invalid_network",
            // No Sui analogue of invalid_exact_evm_payload_value_mismatch or
            // _recipient_mismatch exists, so these fall back to the generic
            // "the requirements you accepted are not the ones we advertised".
            FacilitatorError::AmountMismatch { .. }
            | FacilitatorError::AssetMismatch { .. }
            | FacilitatorError::RecipientMismatch { .. } => "invalid_payment_requirements",
            FacilitatorError::MalformedPayload { .. }
            | FacilitatorError::EmptyTransaction
            | FacilitatorError::MissingSignature => "invalid_payload",
            FacilitatorError::NotImplemented => "unexpected_verify_error",
        }
    }
}

/// Verifies and settles x402 payments.
///
/// Today this is a protocol-plumbing stub. The real implementation maps onto
/// the Sui fullnode gRPC v2 API — Sui fullnodes have removed JSON-RPC, so gRPC
/// is the only path. The four verification steps in `scheme_exact_sui.md` map
/// as follows:
///
/// | Scheme step | Sui gRPC call |
/// |---|---|
/// | 1. network matches | string compare (done) |
/// | 2. signature valid over the transaction | `SignatureVerificationService.VerifySignature` |
/// | 3. simulate; not already executed | `TransactionExecutionService.SimulateTransaction` |
/// | 4. `payTo` sees a balance change of exactly `amount` | simulation output, cross-checked with `StateService.GetBalance` |
/// | settle | `TransactionExecutionService.ExecuteTransaction` |
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
    /// Structural checks run in every mode so malformed payloads are rejected
    /// identically whether or not the chain is in the loop.
    ///
    /// Note this compares the *whole* of `accepted` against what was
    /// advertised, not just scheme and network. A client that echoes back a
    /// cheaper `amount`, a different `asset`, or its own `payTo` must not be
    /// able to buy access on its own terms.
    pub async fn verify_and_settle(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettlementResponse, FacilitatorError> {
        self.settle(payload, requirements).await
    }

    /// Validate a payment authorization **without** executing it (§7.1).
    ///
    /// Returns the payer on success. In `sui-grpc` mode this is where the four
    /// `scheme_exact_sui.md` verification steps run; today only step 1 (network)
    /// plus the structural checks below are implemented, so it refuses.
    pub async fn verify(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<String, FacilitatorError> {
        let sui = self.check_terms(payload, requirements)?;

        match self.mode {
            VerificationMode::StubAcceptAll => Ok(stub_payer(&sui.transaction)),
            VerificationMode::SuiGrpc => Err(FacilitatorError::NotImplemented),
        }
    }

    /// Execute a verified payment (§7.2).
    pub async fn settle(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettlementResponse, FacilitatorError> {
        let sui = self.check_terms(payload, requirements)?;

        match self.mode {
            VerificationMode::StubAcceptAll => {
                // The spec recovers the payer from the signature. The stub
                // cannot, and must not fall back to a client-supplied value, so
                // it derives a deterministic pseudo-address from the
                // transaction bytes: stable per payment (sessions behave), and
                // untrusted input never becomes an identity claim.
                let payer = stub_payer(&sui.transaction);

                tracing::warn!(
                    payer = %payer,
                    "STUB MODE: accepting payment without on-chain verification or settlement"
                );

                Ok(SettlementResponse {
                    success: true,
                    error_reason: None,
                    payer: Some(payer),
                    // Clearly not a digest, so a stub receipt can never be
                    // mistaken for evidence of an on-chain transfer.
                    transaction: "stub-not-settled-on-chain".to_string(),
                    network: self.network.clone(),
                    amount: Some(requirements.amount.clone()),
                    extensions: None,
                })
            }
            VerificationMode::SuiGrpc => Err(FacilitatorError::NotImplemented),
        }
    }

    /// Checks shared by verify and settle: the client must have accepted
    /// exactly the terms that were advertised, and the payload must be a
    /// well-formed Sui `exact` payload.
    fn check_terms(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SuiExactPayload, FacilitatorError> {
        if payload.x402_version != X402_VERSION {
            return Err(FacilitatorError::VersionMismatch {
                got: payload.x402_version,
                expected: X402_VERSION,
            });
        }

        let accepted = &payload.accepted;
        if accepted.scheme != requirements.scheme {
            return Err(FacilitatorError::SchemeMismatch {
                got: accepted.scheme.clone(),
                expected: requirements.scheme.clone(),
            });
        }
        if accepted.network != requirements.network {
            return Err(FacilitatorError::NetworkMismatch {
                got: accepted.network.clone(),
                expected: requirements.network.clone(),
            });
        }
        if accepted.amount != requirements.amount {
            return Err(FacilitatorError::AmountMismatch {
                got: accepted.amount.clone(),
                expected: requirements.amount.clone(),
            });
        }
        if accepted.asset != requirements.asset {
            return Err(FacilitatorError::AssetMismatch {
                got: accepted.asset.clone(),
                expected: requirements.asset.clone(),
            });
        }
        if accepted.pay_to != requirements.pay_to {
            return Err(FacilitatorError::RecipientMismatch {
                got: accepted.pay_to.clone(),
                expected: requirements.pay_to.clone(),
            });
        }

        let sui: SuiExactPayload =
            serde_json::from_value(payload.payload.clone()).map_err(|e| {
                FacilitatorError::MalformedPayload {
                    scheme: requirements.scheme.clone(),
                    detail: e.to_string(),
                }
            })?;

        if sui.transaction.trim().is_empty() {
            return Err(FacilitatorError::EmptyTransaction);
        }
        if sui.signature.trim().is_empty() {
            return Err(FacilitatorError::MissingSignature);
        }

        Ok(sui)
    }

    /// Receipt for a payment that was refused.
    ///
    /// The HTTP transport requires a 402 that carries `PAYMENT-RESPONSE` as
    /// well as `PAYMENT-REQUIRED` when a payment was *attempted* and failed.
    ///
    /// Emitted on the denial path in Phase 2; already exercised by tests.
    pub fn failure_receipt(&self, code: &str) -> SettlementResponse {
        SettlementResponse {
            success: false,
            error_reason: Some(code.to_string()),
            // Unknown: the payer is recovered during verification, which is
            // exactly what did not complete.
            payer: None,
            transaction: String::new(),
            network: self.network.clone(),
            amount: None,
            extensions: None,
        }
    }
}

impl Facilitator {
    /// What this facilitator will accept (§7.3).
    pub fn supported(&self) -> SupportedResponse {
        SupportedResponse {
            kinds: vec![SupportedKind {
                x402_version: X402_VERSION,
                scheme: "exact".to_string(),
                network: self.network.clone(),
                extra: None,
            }],
            extensions: vec![SESSION_EXTENSION.to_string()],
            // Deliberately empty — see the field's doc comment.
            signers: std::collections::BTreeMap::new(),
        }
    }
}

/// Deterministic placeholder payer for stub mode. Never a real Sui address.
fn stub_payer(transaction_b64: &str) -> String {
    let digest = Sha256::digest(transaction_b64.as_bytes());
    format!("0x{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Spec conformance ------------------------------------------------
    //
    // These assert our types round-trip the spec's own JSON examples, byte for
    // byte in value terms. They are the reason "conformant" is something CI
    // checks rather than something a human asserts.

    const PAYMENT_REQUIRED_JSON: &str = include_str!("../tests/fixtures/payment_required_v2.json");
    const PAYLOAD_EVM_JSON: &str = include_str!("../tests/fixtures/payment_payload_evm_v2.json");
    const PAYLOAD_SUI_JSON: &str = include_str!("../tests/fixtures/payment_payload_sui.json");
    const SUI_EXACT_JSON: &str = include_str!("../tests/fixtures/sui_exact_payload.json");
    const SETTLEMENT_JSON: &str = include_str!("../tests/fixtures/settlement_response_v2.json");

    /// Deserialize into `T`, re-serialize, and assert the JSON is unchanged.
    ///
    /// Compares parsed `Value`s so key order and whitespace are irrelevant but
    /// any added, dropped, or renamed field fails.
    fn assert_roundtrip<T>(raw: &str)
    where
        T: serde::de::DeserializeOwned + Serialize,
    {
        let original: serde_json::Value = serde_json::from_str(raw).expect("fixture is valid JSON");
        let typed: T = serde_json::from_str(raw).expect("fixture should deserialize into T");
        let reserialized = serde_json::to_value(&typed).expect("T should serialize");
        assert_eq!(
            reserialized, original,
            "round-trip changed the document; our type has drifted from the spec"
        );
    }

    #[test]
    fn spec_payment_required_roundtrips() {
        assert_roundtrip::<PaymentRequired>(PAYMENT_REQUIRED_JSON);
    }

    #[test]
    fn spec_payment_payload_evm_roundtrips() {
        // Proves the envelope is scheme-agnostic: this is the EVM example, and
        // it must survive even though this service only settles Sui.
        assert_roundtrip::<PaymentPayload>(PAYLOAD_EVM_JSON);
    }

    #[test]
    fn spec_payment_payload_sui_roundtrips() {
        assert_roundtrip::<PaymentPayload>(PAYLOAD_SUI_JSON);
    }

    #[test]
    fn spec_sui_exact_payload_roundtrips() {
        assert_roundtrip::<SuiExactPayload>(SUI_EXACT_JSON);
    }

    #[test]
    fn spec_settlement_response_roundtrips() {
        assert_roundtrip::<SettlementResponse>(SETTLEMENT_JSON);
    }

    #[test]
    fn sponsorship_is_advertised_as_extra_gas_station() {
        // scheme_exact_sui.md Appendix: a facilitator signals that it will
        // sponsor transactions by publishing a gas station URL here.
        use crate::config::PaymentConfig;
        let mut payment = PaymentConfig {
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            amount: "1000".into(),
            asset: "0xa1::usdc::USDC".into(),
            pay_to: "0xabc".into(),
            max_timeout_seconds: 60,
            description: "test".into(),
            gas_station: None,
        };

        // Unset: no `extra` at all, rather than an empty object claiming
        // support we do not have.
        assert!(PaymentRequirements::from_config(&payment).extra.is_none());

        payment.gas_station = Some("https://gas.example.com".into());
        let extra = PaymentRequirements::from_config(&payment).extra.unwrap();
        assert_eq!(
            extra["gasStation"],
            serde_json::json!("https://gas.example.com")
        );
    }

    #[test]
    fn session_extension_advertisement_carries_info_and_schema() {
        // §5.1.2 requires both halves; a client cannot validate the echo
        // without the schema.
        let adv = session_extension_advertisement(1000, 3600, "x-payment-session");
        let entry = &adv[SESSION_EXTENSION];
        assert!(entry["info"].is_object());
        assert!(entry["schema"].is_object());
        assert_eq!(entry["schema"]["required"], serde_json::json!(["token"]));

        // And the grant round-trips back out.
        let grant = session_extension_grant("tok", 1000, 3600);
        assert_eq!(session_token_from_extensions(Some(&grant)), Some("tok"));
        assert_eq!(session_token_from_extensions(None), None);
        assert_eq!(
            session_token_from_extensions(Some(&serde_json::json!({"other": {}}))),
            None
        );
    }

    #[test]
    fn requirements_use_the_v2_field_names() {
        // v2 renamed maxAmountRequired -> amount, and moved resource,
        // description and mimeType out of PaymentRequirements entirely.
        let json = serde_json::to_string(&requirements()).unwrap();
        assert!(json.contains(r#""amount""#), "got: {json}");
        assert!(json.contains(r#""payTo""#), "got: {json}");
        assert!(!json.contains("maxAmountRequired"), "got: {json}");
        assert!(!json.contains(r#""resource""#), "got: {json}");
        assert!(!json.contains("mimeType"), "got: {json}");
    }

    #[test]
    fn sui_payload_from_the_spec_parses_into_the_typed_form() {
        let envelope: PaymentPayload = serde_json::from_str(PAYLOAD_SUI_JSON).unwrap();
        let sui: SuiExactPayload = serde_json::from_value(envelope.payload).unwrap();
        assert!(sui.signature.starts_with("99X8xzbQ"));
        assert!(sui.transaction.starts_with("AAAIAQDi"));
    }

    // ---- Fixtures --------------------------------------------------------

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            amount: "1000".into(),
            asset: "0xa1::usdc::USDC".into(),
            pay_to: "0xabc".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    fn resource() -> ResourceInfo {
        ResourceInfo {
            url: "https://api.example.com/graphql".into(),
            description: Some("test".into()),
            mime_type: Some("application/json".into()),
        }
    }

    fn payload() -> PaymentPayload {
        PaymentPayload {
            x402_version: X402_VERSION,
            resource: Some(resource()),
            accepted: requirements(),
            payload: serde_json::json!({ "signature": "c2ln", "transaction": "dHg=" }),
            extensions: None,
        }
    }

    fn stub() -> Facilitator {
        Facilitator::new(
            VerificationMode::StubAcceptAll,
            "https://fullnode.testnet.sui.io:443".into(),
            "sui:testnet".into(),
        )
    }

    // ---- Header codec ----------------------------------------------------

    #[test]
    fn header_roundtrips_through_base64_json() {
        let required = PaymentRequired::new("payment required", resource(), vec![requirements()]);
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

    // ---- Facilitator -----------------------------------------------------

    #[tokio::test]
    async fn stub_accepts_a_well_formed_payment() {
        let receipt = stub()
            .verify_and_settle(&payload(), &requirements())
            .await
            .unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.amount.as_deref(), Some("1000"));
        assert_eq!(receipt.transaction, "stub-not-settled-on-chain");
        assert!(receipt.error_reason.is_none());
    }

    #[tokio::test]
    async fn stub_payer_is_derived_from_the_transaction_not_supplied_by_the_client() {
        // A client cannot name itself: the same transaction always yields the
        // same payer, and a different one always yields a different payer.
        let a = stub()
            .verify_and_settle(&payload(), &requirements())
            .await
            .unwrap();

        let mut other = payload();
        other.payload = serde_json::json!({ "signature": "c2ln", "transaction": "b3RoZXI=" });
        let b = stub()
            .verify_and_settle(&other, &requirements())
            .await
            .unwrap();

        assert_ne!(a.payer, b.payer);
        let again = stub()
            .verify_and_settle(&payload(), &requirements())
            .await
            .unwrap();
        assert_eq!(a.payer, again.payer);
    }

    /// Assert that mutating the echoed-back terms is refused with `code`.
    async fn expect_refused(mutate: impl FnOnce(&mut PaymentPayload), code: &str, field: &str) {
        let mut p = payload();
        mutate(&mut p);
        let err = stub()
            .verify_and_settle(&p, &requirements())
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            code,
            "tampering with {field} should be refused with {code}"
        );
    }

    #[tokio::test]
    async fn a_client_cannot_buy_access_on_its_own_terms() {
        // The whole point of comparing `accepted` field by field: echoing back
        // a cheaper price, a different asset, or your own payTo must fail.
        expect_refused(
            |p| p.accepted.amount = "1".into(),
            "invalid_payment_requirements",
            "amount",
        )
        .await;
        expect_refused(
            |p| p.accepted.asset = "0xdead::fake::FAKE".into(),
            "invalid_payment_requirements",
            "asset",
        )
        .await;
        expect_refused(
            |p| p.accepted.pay_to = "0xattacker".into(),
            "invalid_payment_requirements",
            "payTo",
        )
        .await;
        expect_refused(
            |p| p.accepted.scheme = "upto".into(),
            "invalid_scheme",
            "scheme",
        )
        .await;
        expect_refused(
            |p| p.accepted.network = "sui:mainnet".into(),
            "invalid_network",
            "network",
        )
        .await;
    }

    #[tokio::test]
    async fn stub_still_rejects_version_mismatch() {
        let mut p = payload();
        p.x402_version = 1;
        let err = stub()
            .verify_and_settle(&p, &requirements())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_x402_version");
    }

    #[tokio::test]
    async fn stub_rejects_payloads_that_are_not_the_sui_scheme_shape() {
        // v1-shaped payload: the old transactionBytes/signatures names.
        let mut p = payload();
        p.payload = serde_json::json!({
            "transactionBytes": "dHg=", "signatures": ["c2ln"], "payer": "0xclaimed"
        });
        let err = stub()
            .verify_and_settle(&p, &requirements())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_payload");
    }

    #[tokio::test]
    async fn stub_rejects_empty_or_unsigned_transactions() {
        let mut empty = payload();
        empty.payload = serde_json::json!({ "signature": "c2ln", "transaction": "   " });
        assert!(matches!(
            stub().verify_and_settle(&empty, &requirements()).await,
            Err(FacilitatorError::EmptyTransaction)
        ));

        let mut unsigned = payload();
        unsigned.payload = serde_json::json!({ "signature": "", "transaction": "dHg=" });
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

    #[test]
    fn failure_receipt_matches_the_transport_spec() {
        // http.md: a failed payment is a 402 carrying success:false, a machine
        // readable errorReason, and an EMPTY transaction string.
        let err = FacilitatorError::NetworkMismatch {
            got: "sui:mainnet".into(),
            expected: "sui:testnet".into(),
        };
        let receipt = stub().failure_receipt(err.code());
        assert!(!receipt.success);
        assert_eq!(receipt.error_reason.as_deref(), Some("invalid_network"));
        assert_eq!(receipt.transaction, "");
        assert_eq!(receipt.network, "sui:testnet");
    }

    #[test]
    fn every_error_maps_to_a_standard_spec_code() {
        // §9 defines a closed vocabulary. A code outside it is as useless to a
        // client as a prose string.
        const SPEC_CODES: &[&str] = &[
            "insufficient_funds",
            "invalid_network",
            "invalid_payload",
            "invalid_payment_requirements",
            "invalid_scheme",
            "unsupported_scheme",
            "invalid_x402_version",
            "invalid_transaction_state",
            "unexpected_verify_error",
            "unexpected_settle_error",
        ];

        let all = [
            FacilitatorError::VersionMismatch {
                got: 1,
                expected: 2,
            },
            FacilitatorError::SchemeMismatch {
                got: "a".into(),
                expected: "b".into(),
            },
            FacilitatorError::NetworkMismatch {
                got: "a".into(),
                expected: "b".into(),
            },
            FacilitatorError::AmountMismatch {
                got: "a".into(),
                expected: "b".into(),
            },
            FacilitatorError::AssetMismatch {
                got: "a".into(),
                expected: "b".into(),
            },
            FacilitatorError::RecipientMismatch {
                got: "a".into(),
                expected: "b".into(),
            },
            FacilitatorError::MalformedPayload {
                scheme: "exact".into(),
                detail: "x".into(),
            },
            FacilitatorError::EmptyTransaction,
            FacilitatorError::MissingSignature,
            FacilitatorError::NotImplemented,
        ];

        for e in all {
            assert!(
                SPEC_CODES.contains(&e.code()),
                "{:?} maps to {:?}, which is not a §9 code",
                e,
                e.code()
            );
        }
    }
}
