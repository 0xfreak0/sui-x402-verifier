//! On-chain verification and settlement against a Sui fullnode.
//!
//! Implements the four verification steps of `scheme_exact_sui.md`:
//!
//! | Step | How |
//! |---|---|
//! | 1. network matches | string compare, done by the caller |
//! | 2. signature valid over the transaction | `SignatureVerificationService.VerifySignature` |
//! | 3. simulate; would succeed and is not already executed | `TransactionExecutionService.SimulateTransaction` |
//! | 4. `payTo` credited with exactly `amount` of `asset` | the simulation's `balance_changes` |
//!
//! Step 4 is the one that makes this a payment rather than a handshake. The
//! other three prove *someone signed something that would execute*; only step 4
//! proves the money moves to the right place in the right amount.
//!
//! Sui has deprecated JSON-RPC in favour of gRPC, so gRPC is the interface
//! this targets.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use sui_rpc::proto::sui::rpc::v2 as pb;

use crate::x402::{FacilitatorError, PaymentRequirements, SuiExactPayload};

/// What verification established about a payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    /// Sender recovered from the transaction and confirmed by the signature.
    /// Never taken from a client-supplied field.
    pub payer: String,
    /// Transaction digest, used as the replay key and reported on settlement.
    pub digest: String,
}

/// Talks to a Sui fullnode over gRPC.
///
/// `sui_rpc::Client` is not `Debug`, so this is implemented by hand rather than
/// derived — the connection has nothing worth printing anyway.
#[derive(Clone)]
pub struct SuiVerifier {
    client: sui_rpc::Client,
    /// CAIP-2 network this verifier serves. Held for diagnostics; the
    /// authoritative network check lives in `Facilitator::check_terms`, which
    /// runs before any payload reaches here.
    network: String,
}

impl std::fmt::Debug for SuiVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuiVerifier")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl SuiVerifier {
    /// Connect to a fullnode. TLS is configured automatically for `https` URLs.
    pub fn connect(grpc_url: &str, network: String) -> Result<Self, FacilitatorError> {
        let client = sui_rpc::Client::new(grpc_url).map_err(|e| FacilitatorError::Rpc {
            detail: format!("connecting to {grpc_url}: {e}"),
        })?;
        Ok(Self { client, network })
    }

    /// Decode the payload's base64 into raw transaction and signature bytes.
    fn decode(payload: &SuiExactPayload) -> Result<(Vec<u8>, Vec<u8>), FacilitatorError> {
        let transaction = B64.decode(payload.transaction.trim()).map_err(|e| {
            FacilitatorError::MalformedPayload {
                scheme: "exact".into(),
                detail: format!("transaction is not valid base64: {e}"),
            }
        })?;
        let signature = B64.decode(payload.signature.trim()).map_err(|e| {
            FacilitatorError::MalformedPayload {
                scheme: "exact".into(),
                detail: format!("signature is not valid base64: {e}"),
            }
        })?;
        Ok((transaction, signature))
    }

    /// Steps 2-4. Returns the recovered payer and the transaction digest.
    pub async fn verify(
        &self,
        payload: &SuiExactPayload,
        requirements: &PaymentRequirements,
    ) -> Result<VerifiedPayment, FacilitatorError> {
        let (transaction_bytes, signature_bytes) = Self::decode(payload)?;

        // Parse the transaction so the sender comes from the signed bytes
        // themselves. Anything a client says about who it is, outside the
        // signature, is not evidence.
        let transaction: sui_sdk_types::Transaction =
            bcs::from_bytes(&transaction_bytes).map_err(|e| {
                FacilitatorError::MalformedPayload {
                    scheme: "exact".into(),
                    detail: format!("transaction is not valid BCS TransactionData: {e}"),
                }
            })?;
        let sender = transaction.sender.to_string();

        let signature =
            sui_sdk_types::UserSignature::from_bytes(&signature_bytes).map_err(|e| {
                FacilitatorError::MalformedPayload {
                    scheme: "exact".into(),
                    detail: format!("signature is not a valid Sui user signature: {e}"),
                }
            })?;

        // ---- Step 2: the signature is valid over these exact bytes ---------
        let mut signature_client = self.client.clone().signature_verification_client();
        let response = signature_client
            .verify_signature(
                // The proto types are #[non_exhaustive]; build them through the
                // generated builders rather than struct literals.
                pb::VerifySignatureRequest::default()
                    .with_message(pb::Bcs::from(transaction_bytes.clone()))
                    .with_signature(pb::UserSignature::from(signature))
                    .with_address(sender.clone()),
            )
            .await
            .map_err(|e| FacilitatorError::Rpc {
                detail: format!("VerifySignature: {e}"),
            })?
            .into_inner();

        if !response.is_valid.unwrap_or(false) {
            return Err(FacilitatorError::InvalidSignature {
                detail: response
                    .reason
                    .unwrap_or_else(|| "signature did not verify".into()),
            });
        }

        // ---- Step 3: it would actually execute ----------------------------
        let mut execution_client = self.client.clone().execution_client();
        let simulation = execution_client
            .simulate_transaction(
                pb::SimulateTransactionRequest::default()
                    .with_transaction(
                        pb::Transaction::default().with_bcs(pb::Bcs::from(transaction_bytes)),
                    )
                    // Ask for the fields step 4 needs. Without a read mask the
                    // node may omit balance_changes entirely.
                    .with_read_mask(prost_types::FieldMask {
                        paths: vec![
                            "transaction.digest".into(),
                            "transaction.effects.status".into(),
                            "transaction.balance_changes".into(),
                        ],
                    }),
            )
            .await
            .map_err(|e| FacilitatorError::Rpc {
                detail: format!("SimulateTransaction: {e}"),
            })?
            .into_inner();

        let executed =
            simulation
                .transaction
                .ok_or_else(|| FacilitatorError::SimulationFailed {
                    detail: "simulation returned no transaction".into(),
                })?;

        // A simulation that reports failure means this would not land, which
        // includes the already-executed case.
        if let Some(effects) = &executed.effects
            && let Some(status) = &effects.status
            && !status.success.unwrap_or(false)
        {
            return Err(FacilitatorError::SimulationFailed {
                detail: status
                    .error
                    .as_ref()
                    .and_then(|e| e.description.clone())
                    .unwrap_or_else(|| "transaction would not succeed".into()),
            });
        }

        // ---- Step 3b: the inputs it pins are still live --------------------
        //
        // Simulation does NOT enforce this: an authorization whose coins have
        // since been spent still simulates successfully, then fails at
        // execution. Without this check a client can spend the pinned coin,
        // present the (now dead) payment, be verified, receive the resource,
        // and have settlement fail — free service, no race required.
        self.assert_inputs_are_live(&transaction).await?;

        // ---- Step 4: it pays the right party the right amount -------------
        assert_credits(&executed.balance_changes, requirements)?;

        Ok(VerifiedPayment {
            payer: sender,
            digest: executed.digest.unwrap_or_default(),
        })
    }

    /// Confirm every object the transaction pins still exists at the pinned
    /// version.
    ///
    /// A Sui transaction references owned objects as `(id, version, digest)`.
    /// Execution rejects a stale version; **simulation does not**, which is the
    /// gap this closes. Shared inputs are skipped: they are versioned by
    /// consensus at execution time, not pinned by the client.
    async fn assert_inputs_are_live(
        &self,
        transaction: &sui_sdk_types::Transaction,
    ) -> Result<(), FacilitatorError> {
        use sui_sdk_types::{Input, TransactionKind};

        let mut pinned: Vec<(String, u64)> = Vec::new();

        if let TransactionKind::ProgrammableTransaction(ptb) = &transaction.kind {
            for input in &ptb.inputs {
                match input {
                    // Owned and receiving inputs carry a client-pinned version.
                    Input::ImmutableOrOwned(r) | Input::Receiving(r) => {
                        pinned.push((r.object_id().to_string(), r.version()));
                    }
                    // Shared objects are versioned at execution by consensus.
                    Input::Shared(_) => {}
                    _ => {}
                }
            }
        }

        // Gas coins are pinned the same way and are just as spendable.
        for r in &transaction.gas_payment.objects {
            pinned.push((r.object_id().to_string(), r.version()));
        }

        if pinned.is_empty() {
            return Ok(());
        }

        let mut ledger = self.client.clone().ledger_client();
        for (object_id, version) in pinned {
            let response = ledger
                .get_object(
                    pb::GetObjectRequest::default()
                        .with_object_id(object_id.clone())
                        .with_read_mask(prost_types::FieldMask {
                            paths: vec!["object_id".into(), "version".into()],
                        }),
                )
                .await;

            let current = match response {
                Ok(response) => response.into_inner().object.and_then(|o| o.version),
                // A pinned object that no longer exists reads as NotFound. That
                // is exactly the "already spent" case, not an infrastructure
                // failure, so treat it as a dead input rather than an RPC error.
                Err(status) if status.code() == tonic::Code::NotFound => None,
                Err(e) => {
                    return Err(FacilitatorError::Rpc {
                        detail: format!("GetObject({object_id}): {e}"),
                    });
                }
            };

            match current {
                Some(current) if current == version => {}
                other => {
                    return Err(FacilitatorError::StaleInput {
                        object_id,
                        pinned: version,
                        current: other,
                    });
                }
            }
        }

        Ok(())
    }

    /// Broadcast the client-signed transaction (`scheme_exact_sui.md`,
    /// "Settlement"). Returns the on-chain digest.
    pub async fn settle(&self, payload: &SuiExactPayload) -> Result<String, FacilitatorError> {
        let (transaction_bytes, signature_bytes) = Self::decode(payload)?;
        let signature =
            sui_sdk_types::UserSignature::from_bytes(&signature_bytes).map_err(|e| {
                FacilitatorError::MalformedPayload {
                    scheme: "exact".into(),
                    detail: format!("signature is not a valid Sui user signature: {e}"),
                }
            })?;

        let mut execution_client = self.client.clone().execution_client();
        let response = execution_client
            .execute_transaction(
                pb::ExecuteTransactionRequest::default()
                    .with_transaction(
                        pb::Transaction::default().with_bcs(pb::Bcs::from(transaction_bytes)),
                    )
                    .with_signatures(vec![pb::UserSignature::from(signature)])
                    // NOTE the asymmetry with SimulateTransaction above.
                    // Execute's read_mask selects fields of *ExecutedTransaction*
                    // ("digest", "effects.status"), while Simulate's selects
                    // fields of its *response* ("transaction.digest", …). Using
                    // the simulate form here is rejected outright with
                    // `invalid read_mask path: transaction.effects.status`.
                    .with_read_mask(prost_types::FieldMask {
                        paths: vec!["digest".into(), "effects.status".into()],
                    }),
            )
            .await
            .map_err(|e| FacilitatorError::SettlementFailed {
                detail: format!("ExecuteTransaction: {e}"),
            })?
            .into_inner();

        let executed = response
            .transaction
            .ok_or_else(|| FacilitatorError::SettlementFailed {
                detail: "execution returned no transaction".into(),
            })?;

        if let Some(effects) = &executed.effects
            && let Some(status) = &effects.status
            && !status.success.unwrap_or(false)
        {
            return Err(FacilitatorError::SettlementFailed {
                detail: status
                    .error
                    .as_ref()
                    .and_then(|e| e.description.clone())
                    .unwrap_or_else(|| "transaction failed on chain".into()),
            });
        }

        Ok(executed.digest.unwrap_or_default())
    }
}

/// Step 4: assert the recipient is credited with **exactly** the required
/// amount of the required asset.
///
/// Deliberately an equality check, not `>=`: the scheme is called `exact`, and
/// accepting an overpayment silently would make the advertised price a
/// suggestion. A client wanting to tip can do so out of band.
///
/// Note this reads the *recipient's* balance change, not the sender's. The
/// sender's delta also includes gas, so it is not a clean measure of what was
/// paid; the recipient's is.
fn assert_credits(
    balance_changes: &[pb::BalanceChange],
    requirements: &PaymentRequirements,
) -> Result<(), FacilitatorError> {
    let expected: i128 =
        requirements
            .amount
            .parse()
            .map_err(|_| FacilitatorError::InvalidRequirements {
                detail: format!("amount {:?} is not an integer", requirements.amount),
            })?;

    // Sum rather than find-first: a transaction may legitimately credit the
    // same address more than once, and only the total is the payment.
    let credited: i128 = balance_changes
        .iter()
        .filter(|change| {
            change.address.as_deref() == Some(requirements.pay_to.as_str())
                && change.coin_type.as_deref() == Some(requirements.asset.as_str())
        })
        .filter_map(|change| change.amount.as_deref())
        .filter_map(|amount| amount.parse::<i128>().ok())
        .sum();

    if credited != expected {
        return Err(FacilitatorError::AmountNotCredited {
            expected: requirements.amount.clone(),
            credited: credited.to_string(),
            pay_to: requirements.pay_to.clone(),
            asset: requirements.asset.clone(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "sui:testnet".into(),
            amount: "1000".into(),
            asset: "0xa1::usdc::USDC".into(),
            pay_to: "0xmerchant".into(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    fn change(address: &str, coin_type: &str, amount: &str) -> pb::BalanceChange {
        pb::BalanceChange::default()
            .with_address(address)
            .with_coin_type(coin_type)
            .with_amount(amount)
    }

    #[test]
    fn credits_the_exact_amount_to_the_right_address_and_asset() {
        let changes = vec![
            // The payer's side, including gas — deliberately ignored.
            change("0xpayer", "0xa1::usdc::USDC", "-1000"),
            change("0xmerchant", "0xa1::usdc::USDC", "1000"),
        ];
        assert!(assert_credits(&changes, &requirements()).is_ok());
    }

    #[test]
    fn rejects_an_underpayment() {
        let changes = vec![change("0xmerchant", "0xa1::usdc::USDC", "999")];
        let err = assert_credits(&changes, &requirements()).unwrap_err();
        assert!(matches!(err, FacilitatorError::AmountNotCredited { .. }));
    }

    #[test]
    fn rejects_an_overpayment_too() {
        // `exact` means exact. Silently accepting more would make the
        // advertised price a suggestion.
        let changes = vec![change("0xmerchant", "0xa1::usdc::USDC", "1001")];
        assert!(assert_credits(&changes, &requirements()).is_err());
    }

    #[test]
    fn rejects_payment_to_the_wrong_address() {
        // The attack this stops: a transaction that is perfectly valid and
        // perfectly signed, but pays the client instead of the merchant.
        let changes = vec![change("0xattacker", "0xa1::usdc::USDC", "1000")];
        let err = assert_credits(&changes, &requirements()).unwrap_err();
        assert!(matches!(err, FacilitatorError::AmountNotCredited { .. }));
    }

    #[test]
    fn rejects_payment_in_the_wrong_asset() {
        // 1000 units of a worthless token is not 1000 units of USDC.
        let changes = vec![change("0xmerchant", "0xdead::fake::FAKE", "1000")];
        assert!(assert_credits(&changes, &requirements()).is_err());
    }

    #[test]
    fn sums_multiple_credits_to_the_same_recipient() {
        let changes = vec![
            change("0xmerchant", "0xa1::usdc::USDC", "600"),
            change("0xmerchant", "0xa1::usdc::USDC", "400"),
        ];
        assert!(assert_credits(&changes, &requirements()).is_ok());
    }

    #[test]
    fn rejects_when_the_recipient_is_credited_nothing() {
        assert!(assert_credits(&[], &requirements()).is_err());
    }
}
