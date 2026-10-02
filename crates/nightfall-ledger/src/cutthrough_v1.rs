//! Versioned cut-through transaction-format candidate.
//!
//! This module is deliberately NOT consensus-active.
//!
//! It defines the proposed wire objects and their canonical ordering/hashing
//! without modifying the existing `Transaction`, `Input`, `Output`, `TxKernel`
//! or `BlockBody` types.
//!
//! Consensus activation, UTXO lookup, stealth-balance validation, retention
//! horizon and actual cut-through remain later phases.

use std::collections::BTreeSet;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use nightfall_crypto::{hash_multi, Commitment, Output, TxKernel};
use nightfall_types::{Hash256, Height};
use serde::{Deserialize, Serialize};

use crate::{
    is_mature, KernelBoundAuthorizationBundleError, KernelBoundAuthorizationBundleV1, LedgerState,
};

use crate::{
    KernelStealthBindingV1, SenderAuthorizationV1, SpendAuthorizationV1, StealthOffsetV1,
    MAX_INPUTS, MAX_KERNELS, MAX_OUTPUTS, TX_VERSION,
};

/// Candidate transaction version.
///
/// The active Nightfall transaction format remains `TX_VERSION == 2`.
pub const CUTTHROUGH_TX_VERSION: u32 = TX_VERSION + 1;

pub const CUTTHROUGH_BODY_DOMAIN: &[u8] = b"nightfall:cutthrough:body:v1";

pub const CUTTHROUGH_TX_DOMAIN: &[u8] = b"nightfall:cutthrough:tx:v1";

/// Versioned input candidate.
///
/// Canonical `Ko` is deliberately absent. Validation must resolve it from the
/// authoritative UTXO set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutThroughInputV1 {
    pub commit: Commitment,
    pub authorization: SpendAuthorizationV1,
}

/// Versioned output candidate.
///
/// The existing Nightfall `Output` remains intact while the independent `Ks`
/// authorization is carried separately during this prototype phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutThroughOutputV1 {
    pub output: Output,
    pub sender_authorization: SenderAuthorizationV1,
}

/// Versioned kernel candidate.
///
/// A kernel may carry a stealth-excess binding. The exact policy deciding when
/// that binding is mandatory belongs to the later consensus-validation phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutThroughKernelV1 {
    pub kernel: TxKernel,
    pub stealth_binding: Option<KernelStealthBindingV1>,
}

/// Flat, aggregatable candidate body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutThroughBodyV1 {
    pub inputs: Vec<CutThroughInputV1>,
    pub outputs: Vec<CutThroughOutputV1>,
    pub kernels: Vec<CutThroughKernelV1>,

    /// Aggregate stealth offset x'.
    pub stealth_offset: StealthOffsetV1,
}

/// Complete versioned candidate transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutThroughTransactionV1 {
    pub version: u32,
    pub body: CutThroughBodyV1,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CutThroughV1Error {
    #[error("wrong cut-through transaction version: got {got}, expected {expected}")]
    WrongVersion { got: u32, expected: u32 },

    #[error("too many inputs")]
    TooManyInputs,

    #[error("too many outputs")]
    TooManyOutputs,

    #[error("invalid kernel count")]
    BadKernelCount,

    #[error("transaction has no outputs")]
    NoOutputs,

    #[error("duplicate input commitment")]
    DuplicateInput,

    #[error("duplicate output commitment")]
    DuplicateOutput,

    #[error("duplicate kernel")]
    DuplicateKernel,

    #[error("malformed input commitment at index {index}")]
    MalformedInputCommitment { index: usize },

    #[error("malformed Ki at input index {index}")]
    MalformedInputKey { index: usize },

    #[error("malformed input signature at index {index}")]
    MalformedInputSignature { index: usize },

    #[error("malformed output at index {index}")]
    MalformedOutput { index: usize },

    #[error("invalid existing output signature at index {index}")]
    InvalidExistingOutputSignature { index: usize },

    #[error("invalid Ks output authorization at index {index}")]
    InvalidSenderAuthorization { index: usize },

    #[error("invalid kernel at index {index}")]
    InvalidKernel { index: usize },

    #[error("invalid kernel/stealth binding at index {index}")]
    InvalidKernelStealthBinding { index: usize },

    #[error("non-canonical stealth offset")]
    NonCanonicalStealthOffset,

    #[error("body is not canonically ordered")]
    NonCanonicalBody,
}

/// Failure during stateful validation of a v3 cut-through candidate.
///
/// This validator is intentionally separate from the active v2 mempool and
/// block-validation paths.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CutThroughStateError {
    #[error(transparent)]
    Shape(#[from] CutThroughV1Error),

    #[error("coinbase material is not accepted by the transfer validator")]
    CoinbaseInTransfer,

    #[error("input {commit} does not exist in authoritative UTXO state")]
    UnknownInput { commit: String },

    #[error("immature coinbase: created at {created}, spend attempted at {now}")]
    ImmatureCoinbaseSpend { created: u64, now: u64 },

    #[error("output commitment already exists in authoritative UTXO state")]
    OutputAlreadyExists,

    #[error("invalid range proof at output index {index}")]
    BadRangeProof { index: usize },

    #[error("kernel locked until height {until}")]
    KernelLocked { until: u64 },

    #[error("malformed value-balance material")]
    MalformedValueBalance,

    #[error("MW value equation does not balance")]
    UnbalancedTransaction,

    #[error("stealth authorization validation failed: {0}")]
    StealthAuthorization(KernelBoundAuthorizationBundleError),
}

impl CutThroughBodyV1 {
    pub fn total_fee(&self) -> u64 {
        self.kernels
            .iter()
            .map(|kernel| kernel.kernel.fee_darks)
            .sum()
    }

    pub fn total_reward(&self) -> u64 {
        self.kernels
            .iter()
            .map(|kernel| kernel.kernel.reward_darks)
            .sum()
    }
}

impl LedgerState {
    /// Validate a v3 cut-through transfer candidate against authoritative
    /// ledger state without mutating the state.
    ///
    /// Checks performed here:
    ///
    /// 1. canonical candidate shape/encoding
    /// 2. no coinbase material in the transfer path
    /// 3. kernel lock heights
    /// 4. output range proofs and UTXO collisions
    /// 5. authoritative input lookup and coinbase maturity
    /// 6. input authorization against state-derived canonical Ko
    /// 7. ordinary Mimblewimble value balance
    /// 8. Ks/Ki/Ko/E'/x' stealth balance
    /// 9. every retained E' is bound to its concrete kernel
    ///
    /// This method does NOT mutate the UTXO set, kernel accumulator, supply,
    /// height or transaction counter.
    pub fn check_cutthrough_v1_acceptable(
        &self,
        tx: &CutThroughTransactionV1,
        next_height: Height,
        ctx: &[u8],
    ) -> Result<(), CutThroughStateError> {
        tx.check_shape()?;

        // This method models the mempool/ordinary-transfer path.
        //
        // Coinbase construction will receive its own explicit v3 path rather
        // than weakening the transfer rules.
        if tx
            .body
            .kernels
            .iter()
            .any(|kernel| kernel.kernel.feature == nightfall_crypto::KernelFeature::Coinbase)
            || tx
                .body
                .outputs
                .iter()
                .any(|output| output.output.features.is_coinbase())
        {
            return Err(CutThroughStateError::CoinbaseInTransfer);
        }

        for kernel in &tx.body.kernels {
            if kernel.kernel.lock_height > next_height.0 {
                return Err(CutThroughStateError::KernelLocked {
                    until: kernel.kernel.lock_height,
                });
            }
        }

        // Full output crypto checks.
        //
        // check_shape() already verifies both output signatures and point
        // encodings; range proofs need the network proof context and therefore
        // live here.
        for (index, output) in tx.body.outputs.iter().enumerate() {
            if !nightfall_crypto::rangeproofs::verify(
                &output.output.range_proof,
                &output.output.commit,
                ctx,
            ) {
                return Err(CutThroughStateError::BadRangeProof { index });
            }

            if self.utxos.contains(&output.output.commit) {
                return Err(CutThroughStateError::OutputAlreadyExists);
            }
        }

        // Resolve Ko ONLY from authoritative UTXO state.
        let mut canonical_kos = Vec::with_capacity(tx.body.inputs.len());

        for input in &tx.body.inputs {
            let entry = self.utxos.get(&input.commit).ok_or_else(|| {
                CutThroughStateError::UnknownInput {
                    commit: input.commit.to_hex(),
                }
            })?;

            if !is_mature(entry, next_height, self.coinbase_maturity) {
                return Err(CutThroughStateError::ImmatureCoinbaseSpend {
                    created: entry.height,
                    now: next_height.0,
                });
            }

            canonical_kos.push(entry.output_pk);
        }

        // Preserve Nightfall's existing inflation-resistance equation.
        let input_commits: Vec<Commitment> =
            tx.body.inputs.iter().map(|input| input.commit).collect();

        let output_commits: Vec<Commitment> = tx
            .body
            .outputs
            .iter()
            .map(|output| output.output.commit)
            .collect();

        let expected = nightfall_crypto::expected_excess(
            &input_commits,
            &output_commits,
            tx.body.total_fee(),
            tx.body.total_reward(),
        )
        .ok_or(CutThroughStateError::MalformedValueBalance)?;

        let kernel_excesses: Vec<Commitment> = tx
            .body
            .kernels
            .iter()
            .map(|kernel| kernel.kernel.excess)
            .collect();

        let kernel_sum =
            Commitment::sum(&kernel_excesses).ok_or(CutThroughStateError::MalformedValueBalance)?;

        if expected != kernel_sum {
            return Err(CutThroughStateError::UnbalancedTransaction);
        }

        // Only kernels actually carrying E' participate in the kernel-bound
        // stealth bundle. Kernels without E' remain ordinary MW kernels.
        let mut bindings = Vec::new();

        let mut bound_kernels = Vec::new();

        for kernel in &tx.body.kernels {
            if let Some(binding) = kernel.stealth_binding {
                bindings.push(binding);
                bound_kernels.push(kernel.kernel.clone());
            }
        }

        let sender_authorizations = tx
            .body
            .outputs
            .iter()
            .map(|output| output.sender_authorization)
            .collect();

        let input_authorizations = tx
            .body
            .inputs
            .iter()
            .map(|input| input.authorization)
            .collect();

        let outputs: Vec<nightfall_crypto::Output> = tx
            .body
            .outputs
            .iter()
            .map(|output| output.output.clone())
            .collect();

        let bundle = KernelBoundAuthorizationBundleV1 {
            sender_authorizations,
            input_authorizations,
            kernel_bindings: bindings,
            stealth_offset: tx.body.stealth_offset,
        };

        bundle
            .validate(&outputs, &input_commits, &canonical_kos, &bound_kernels)
            .map_err(CutThroughStateError::StealthAuthorization)?;

        Ok(())
    }
}

impl CutThroughTransactionV1 {
    /// Construct a canonically ordered v3 candidate.
    pub fn new(mut body: CutThroughBodyV1) -> Self {
        body.canonicalise();

        Self {
            version: CUTTHROUGH_TX_VERSION,
            body,
        }
    }

    pub fn check_shape(&self) -> Result<(), CutThroughV1Error> {
        if self.version != CUTTHROUGH_TX_VERSION {
            return Err(CutThroughV1Error::WrongVersion {
                got: self.version,
                expected: CUTTHROUGH_TX_VERSION,
            });
        }

        self.body.check_shape()
    }

    /// Candidate txid covering the explicit version and complete candidate
    /// body hash.
    pub fn txid(&self) -> Hash256 {
        let body_hash = self.body.hash();

        hash_multi(
            CUTTHROUGH_TX_DOMAIN,
            &[&self.version.to_le_bytes(), &body_hash.0],
        )
    }
}

impl CutThroughBodyV1 {
    /// Canonical ordering mirrors Nightfall's current aggregate philosophy:
    ///
    /// * inputs by spent commitment
    /// * outputs by output commitment
    /// * kernels by stable kernel id
    pub fn canonicalise(&mut self) {
        self.inputs.sort_by_key(|input| input.commit.0);

        self.outputs.sort_by_key(|output| output.output.commit.0);

        self.kernels.sort_by_key(|kernel| kernel.kernel.id().0);
    }

    pub fn is_canonical(&self) -> bool {
        let mut copy = self.clone();
        copy.canonicalise();
        copy == *self
    }

    /// Structural/encoding checks only.
    ///
    /// This intentionally does NOT perform authoritative Ko lookup, stealth
    /// balance, MW value balance or retention-horizon rules.
    pub fn check_shape(&self) -> Result<(), CutThroughV1Error> {
        if self.inputs.len() > MAX_INPUTS {
            return Err(CutThroughV1Error::TooManyInputs);
        }

        if self.outputs.len() > MAX_OUTPUTS {
            return Err(CutThroughV1Error::TooManyOutputs);
        }

        if self.kernels.is_empty() || self.kernels.len() > MAX_KERNELS {
            return Err(CutThroughV1Error::BadKernelCount);
        }

        if self.outputs.is_empty() {
            return Err(CutThroughV1Error::NoOutputs);
        }

        if !self.stealth_offset.is_canonical() {
            return Err(CutThroughV1Error::NonCanonicalStealthOffset);
        }

        let mut seen_inputs = BTreeSet::new();

        for (index, input) in self.inputs.iter().enumerate() {
            if input.commit.point().is_none() {
                return Err(CutThroughV1Error::MalformedInputCommitment { index });
            }

            if !seen_inputs.insert(input.commit.0) {
                return Err(CutThroughV1Error::DuplicateInput);
            }

            if CompressedRistretto(input.authorization.ki)
                .decompress()
                .is_none()
            {
                return Err(CutThroughV1Error::MalformedInputKey { index });
            }

            if CompressedRistretto(input.authorization.signature.r)
                .decompress()
                .is_none()
                || Option::<Scalar>::from(Scalar::from_canonical_bytes(
                    input.authorization.signature.s,
                ))
                .is_none()
            {
                return Err(CutThroughV1Error::MalformedInputSignature { index });
            }
        }

        let mut seen_outputs = BTreeSet::new();

        for (index, output) in self.outputs.iter().enumerate() {
            if output.output.commit.point().is_none() || output.output.output_point().is_none() {
                return Err(CutThroughV1Error::MalformedOutput { index });
            }

            if !seen_outputs.insert(output.output.commit.0) {
                return Err(CutThroughV1Error::DuplicateOutput);
            }

            if !output.output.verify_sender_sig() {
                return Err(CutThroughV1Error::InvalidExistingOutputSignature { index });
            }

            if !output.sender_authorization.verify(&output.output) {
                return Err(CutThroughV1Error::InvalidSenderAuthorization { index });
            }
        }

        let mut seen_kernels = BTreeSet::new();

        for (index, kernel) in self.kernels.iter().enumerate() {
            if kernel.kernel.check_shape().is_err() || !kernel.kernel.verify_signature() {
                return Err(CutThroughV1Error::InvalidKernel { index });
            }

            if !seen_kernels.insert(kernel.kernel.id().0) {
                return Err(CutThroughV1Error::DuplicateKernel);
            }

            if let Some(binding) = &kernel.stealth_binding {
                if !binding.verify(&kernel.kernel) {
                    return Err(CutThroughV1Error::InvalidKernelStealthBinding { index });
                }
            }
        }

        if !self.is_canonical() {
            return Err(CutThroughV1Error::NonCanonicalBody);
        }

        Ok(())
    }

    /// Hash every consensus-candidate byte explicitly.
    ///
    /// This uses its own domain and does not modify the active BlockBody hash.
    pub fn hash(&self) -> Hash256 {
        let mut parts: Vec<Vec<u8>> = Vec::new();

        for input in &self.inputs {
            let mut bytes = b"input".to_vec();

            bytes.extend_from_slice(&input.commit.0);

            bytes.extend_from_slice(&input.authorization.canonical_bytes());

            parts.push(bytes);
        }

        for output in &self.outputs {
            let mut bytes = b"output".to_vec();

            bytes.extend_from_slice(&output.output.commitment_bytes());

            bytes.extend_from_slice(&output.output.sender_sig.r);

            bytes.extend_from_slice(&output.output.sender_sig.s);

            bytes.extend_from_slice(&output.sender_authorization.canonical_bytes());

            parts.push(bytes);
        }

        for kernel in &self.kernels {
            let mut bytes = b"kernel".to_vec();

            bytes.extend_from_slice(&kernel.kernel.signing_message());

            bytes.extend_from_slice(&kernel.kernel.excess_sig.r);

            bytes.extend_from_slice(&kernel.kernel.excess_sig.s);

            match &kernel.stealth_binding {
                None => {
                    bytes.push(0);
                }

                Some(binding) => {
                    bytes.push(1);

                    bytes.extend_from_slice(&binding.canonical_bytes());
                }
            }

            parts.push(bytes);
        }

        let mut offset = b"stealth_offset".to_vec();

        offset.extend_from_slice(&self.stealth_offset.canonical_bytes());

        parts.push(offset);

        let refs: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();

        hash_multi(CUTTHROUGH_BODY_DOMAIN, &refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::scalar::Scalar;
    use nightfall_crypto::{
        build_kernel, create_output, generator_g, scan_output, KernelFeature, WalletKeys,
    };
    use nightfall_types::NetworkId;
    use rand::rngs::OsRng;

    use crate::{
        KernelStealthBindingV1, SenderAuthorizationV1, SpendAuthorizationV1, StealthExcessV1,
        StealthOffsetV1,
    };

    fn candidate_parts() -> (CutThroughInputV1, CutThroughOutputV1, CutThroughKernelV1) {
        let owner = WalletKeys::generate();

        let (spent_output, _) = create_output(
            &owner.address(),
            10_000,
            "spent",
            NetworkId::Devnet.proof_context(),
        )
        .expect("spent output");

        let discovered =
            scan_output(&owner.view_key(), &spent_output).expect("discover spent output");

        let ko_secret = discovered.spend_secret(&owner);

        assert_eq!(
            (generator_g() * ko_secret).compress().to_bytes(),
            spent_output.output_pk,
        );

        let ki_secret = Scalar::random(&mut OsRng);

        let input_auth = SpendAuthorizationV1::sign(
            &spent_output.commit,
            &ki_secret,
            &ko_secret,
            &spent_output.output_pk,
        )
        .expect("input auth");

        let input = CutThroughInputV1 {
            commit: spent_output.commit,
            authorization: input_auth,
        };

        let receiver = WalletKeys::generate();

        let (new_output, _) = create_output(
            &receiver.address(),
            9_000,
            "new",
            NetworkId::Devnet.proof_context(),
        )
        .expect("new output");

        let ks = Scalar::random(&mut OsRng);

        let sender_authorization = SenderAuthorizationV1::sign(&new_output, &ks);

        let output = CutThroughOutputV1 {
            output: new_output,
            sender_authorization,
        };

        let kernel_secret = Scalar::random(&mut OsRng);

        let kernel = build_kernel(KernelFeature::Plain, 1_000, 0, 0, &kernel_secret);

        let stealth_secret = Scalar::random(&mut OsRng);

        let stealth_excess =
            StealthExcessV1::new(Commitment::from_point(generator_g() * stealth_secret))
                .expect("stealth excess");

        let stealth_binding = KernelStealthBindingV1::sign(&kernel, &kernel_secret, stealth_excess)
            .expect("kernel stealth binding");

        let kernel = CutThroughKernelV1 {
            kernel,
            stealth_binding: Some(stealth_binding),
        };

        (input, output, kernel)
    }

    fn candidate_transaction() -> CutThroughTransactionV1 {
        let (input, output, kernel) = candidate_parts();

        CutThroughTransactionV1::new(CutThroughBodyV1 {
            inputs: vec![input],
            outputs: vec![output],
            kernels: vec![kernel],

            // Phase 3A checks encoding/canonicality only.
            stealth_offset: StealthOffsetV1::from_scalar(&Scalar::random(&mut OsRng)),
        })
    }

    #[test]
    fn cutthrough_version_is_separate_from_active_v2() {
        assert_eq!(CUTTHROUGH_TX_VERSION, TX_VERSION + 1,);

        assert_ne!(CUTTHROUGH_TX_VERSION, TX_VERSION,);
    }

    #[test]
    fn candidate_transaction_has_valid_shape() {
        let tx = candidate_transaction();

        assert_eq!(tx.check_shape(), Ok(()),);

        assert!(tx.body.is_canonical());
    }

    #[test]
    fn candidate_transaction_roundtrips_exactly() {
        let tx = candidate_transaction();

        let before_txid = tx.txid();

        let encoded = serde_json::to_vec(&tx).expect("serialize v3 candidate");

        let decoded: CutThroughTransactionV1 =
            serde_json::from_slice(&encoded).expect("deserialize v3 candidate");

        assert_eq!(decoded, tx,);

        assert_eq!(decoded.txid(), before_txid,);

        assert_eq!(decoded.check_shape(), Ok(()),);
    }

    #[test]
    fn canonical_order_does_not_leak_grouping() {
        let (input_a, output_a, kernel_a) = candidate_parts();

        let (input_b, output_b, kernel_b) = candidate_parts();

        let offset = StealthOffsetV1::from_scalar(&Scalar::from(7u64));

        let mut a = CutThroughBodyV1 {
            inputs: vec![input_a.clone(), input_b.clone()],

            outputs: vec![output_a.clone(), output_b.clone()],

            kernels: vec![kernel_a.clone(), kernel_b.clone()],

            stealth_offset: offset,
        };

        let mut b = CutThroughBodyV1 {
            inputs: vec![input_b, input_a],

            outputs: vec![output_b, output_a],

            kernels: vec![kernel_b, kernel_a],

            stealth_offset: offset,
        };

        a.canonicalise();
        b.canonicalise();

        assert_eq!(a, b);
        assert_eq!(a.hash(), b.hash());

        assert_eq!(a.check_shape(), Ok(()),);
    }

    #[test]
    fn candidate_hash_binds_stealth_offset() {
        let tx = candidate_transaction();

        let mut changed = tx.clone();

        let old = changed
            .body
            .stealth_offset
            .scalar()
            .expect("canonical offset");

        changed.body.stealth_offset = StealthOffsetV1::from_scalar(&(old + Scalar::ONE));

        assert_ne!(tx.body.hash(), changed.body.hash(),);

        assert_ne!(tx.txid(), changed.txid(),);
    }

    #[test]
    fn candidate_hash_binds_kernel_stealth_proof() {
        let tx = candidate_transaction();

        let mut changed = tx.clone();

        changed.body.kernels[0]
            .stealth_binding
            .as_mut()
            .expect("binding")
            .signature
            .s[0] ^= 1;

        assert_ne!(tx.body.hash(), changed.body.hash(),);

        assert!(matches!(
            changed.check_shape(),
            Err(CutThroughV1Error::InvalidKernelStealthBinding { index: 0 })
        ));
    }

    #[test]
    fn malformed_input_authorization_fails_closed() {
        let mut tx = candidate_transaction();

        tx.body.inputs[0].authorization.ki = [0xff; 32];

        assert_eq!(
            tx.check_shape(),
            Err(CutThroughV1Error::MalformedInputKey { index: 0 }),
        );
    }

    #[test]
    fn noncanonical_offset_fails_closed() {
        let mut tx = candidate_transaction();

        tx.body.stealth_offset = StealthOffsetV1 { bytes: [0xff; 32] };

        assert_eq!(
            tx.check_shape(),
            Err(CutThroughV1Error::NonCanonicalStealthOffset),
        );
    }

    #[test]
    fn wrong_candidate_version_is_rejected() {
        let mut tx = candidate_transaction();

        tx.version = TX_VERSION;

        assert_eq!(
            tx.check_shape(),
            Err(CutThroughV1Error::WrongVersion {
                got: TX_VERSION,
                expected: CUTTHROUGH_TX_VERSION,
            }),
        );
    }

    #[test]
    fn sender_authorization_tampering_is_rejected() {
        let mut tx = candidate_transaction();

        tx.body.outputs[0].sender_authorization.key = (generator_g() * Scalar::random(&mut OsRng))
            .compress()
            .to_bytes();

        assert_eq!(
            tx.check_shape(),
            Err(CutThroughV1Error::InvalidSenderAuthorization { index: 0 }),
        );
    }

    fn stateful_candidate_fixture() -> (LedgerState, CutThroughTransactionV1, Height) {
        let ctx = NetworkId::Devnet.proof_context();

        let owner = WalletKeys::generate();

        let (spent_output, spent_sender_secrets) =
            create_output(&owner.address(), 10_000, "stateful-input", ctx).expect("spent output");

        let discovered =
            scan_output(&owner.view_key(), &spent_output).expect("discover spent output");

        let ko_secret = discovered.spend_secret(&owner);

        assert_eq!(
            (generator_g() * ko_secret).compress().to_bytes(),
            spent_output.output_pk,
        );

        let mut state = LedgerState::for_network(NetworkId::Devnet);

        assert!(state.utxos.insert(
            spent_output.commit,
            crate::UtxoEntry {
                output_pk: spent_output.output_pk,
                height: 0,
                is_coinbase: false,
            },
        ));

        let receiver = WalletKeys::generate();

        let (new_output, new_sender_secrets) =
            create_output(&receiver.address(), 9_000, "stateful-output", ctx).expect("new output");

        let fee = 1_000u64;

        // Same MW relation used by the active builder:
        //
        // Σout - Σin + fee*G = excess*H
        let kernel_secret = new_sender_secrets.blind - spent_sender_secrets.blind;

        let kernel = build_kernel(KernelFeature::Plain, fee, 0, 0, &kernel_secret);

        assert!(kernel.verify_signature());

        let ki_secret = Scalar::random(&mut OsRng);

        let input_authorization = SpendAuthorizationV1::sign(
            &spent_output.commit,
            &ki_secret,
            &ko_secret,
            &spent_output.output_pk,
        )
        .expect("input authorization");

        let ks_secret = Scalar::random(&mut OsRng);

        let sender_authorization = SenderAuthorizationV1::sign(&new_output, &ks_secret);

        let stealth_excess_secret = Scalar::random(&mut OsRng);

        let stealth_excess = StealthExcessV1::new(Commitment::from_point(
            generator_g() * stealth_excess_secret,
        ))
        .expect("stealth excess");

        let stealth_binding = KernelStealthBindingV1::sign(&kernel, &kernel_secret, stealth_excess)
            .expect("kernel/E' binding");

        let stealth_offset = crate::stealth_offset_secret(
            &[ks_secret],
            &[ki_secret],
            &[ko_secret],
            &[stealth_excess_secret],
        );

        let tx = CutThroughTransactionV1::new(CutThroughBodyV1 {
            inputs: vec![CutThroughInputV1 {
                commit: spent_output.commit,

                authorization: input_authorization,
            }],

            outputs: vec![CutThroughOutputV1 {
                output: new_output,

                sender_authorization,
            }],

            kernels: vec![CutThroughKernelV1 {
                kernel,

                stealth_binding: Some(stealth_binding),
            }],

            stealth_offset: StealthOffsetV1::from_scalar(&stealth_offset),
        });

        (state, tx, Height(1))
    }

    #[test]
    fn stateful_candidate_validates_against_real_utxo_state() {
        let (state, tx, next_height) = stateful_candidate_fixture();

        assert_eq!(
            state.check_cutthrough_v1_acceptable(
                &tx,
                next_height,
                NetworkId::Devnet.proof_context(),
            ),
            Ok(()),
        );
    }

    #[test]
    fn stateful_candidate_uses_authoritative_ko() {
        let (mut state, tx, next_height) = stateful_candidate_fixture();

        let input_commit = tx.body.inputs[0].commit;

        let replacement_secret = Scalar::random(&mut OsRng);

        state
            .utxos
            .entries
            .get_mut(&input_commit.0)
            .expect("UTXO")
            .output_pk = (generator_g() * replacement_secret).compress().to_bytes();

        assert!(matches!(
            state.check_cutthrough_v1_acceptable(
                &tx,
                next_height,
                NetworkId::Devnet.proof_context(),
            ),
            Err(CutThroughStateError::StealthAuthorization(
                crate::KernelBoundAuthorizationBundleError::Authorization(
                    crate::AuthorizationBundleError::InvalidInputAuthorization { index: 0 }
                )
            ))
        ));
    }

    #[test]
    fn stateful_candidate_rejects_unknown_input() {
        let (mut state, tx, next_height) = stateful_candidate_fixture();

        let commit = tx.body.inputs[0].commit;

        state.utxos.remove(&commit);

        assert!(matches!(
            state.check_cutthrough_v1_acceptable(
                &tx,
                next_height,
                NetworkId::Devnet.proof_context(),
            ),
            Err(CutThroughStateError::UnknownInput { .. })
        ));
    }

    #[test]
    fn stateful_candidate_preserves_coinbase_maturity() {
        let (mut state, tx, _next_height) = stateful_candidate_fixture();

        let commit = tx.body.inputs[0].commit;

        let entry = state.utxos.entries.get_mut(&commit.0).expect("UTXO");

        entry.is_coinbase = true;
        entry.height = 5;

        assert_eq!(
            state
                .check_cutthrough_v1_acceptable(&tx, Height(6), NetworkId::Devnet.proof_context(),),
            Err(CutThroughStateError::ImmatureCoinbaseSpend { created: 5, now: 6 }),
        );
    }

    #[test]
    fn stateful_candidate_verifies_rangeproofs() {
        let (state, mut tx, next_height) = stateful_candidate_fixture();

        assert!(!tx.body.outputs[0].output.range_proof.0.is_empty());

        tx.body.outputs[0].output.range_proof.0[0] ^= 1;

        // Existing output signature covers the range proof as well, so shape
        // validation may reject first. Either outcome is fail-closed.
        assert!(state
            .check_cutthrough_v1_acceptable(&tx, next_height, NetworkId::Devnet.proof_context(),)
            .is_err());
    }

    #[test]
    fn stateful_candidate_rejects_mw_value_imbalance() {
        let (state, mut tx, next_height) = stateful_candidate_fixture();

        let old_binding = tx.body.kernels[0].stealth_binding.expect("binding");

        let wrong_kernel_secret = Scalar::random(&mut OsRng);

        let wrong_kernel = build_kernel(KernelFeature::Plain, 1_000, 0, 0, &wrong_kernel_secret);

        let rebound = KernelStealthBindingV1::sign(
            &wrong_kernel,
            &wrong_kernel_secret,
            old_binding.stealth_excess,
        )
        .expect("rebound E'");

        tx.body.kernels[0] = CutThroughKernelV1 {
            kernel: wrong_kernel,
            stealth_binding: Some(rebound),
        };

        tx.body.canonicalise();

        assert_eq!(
            state.check_cutthrough_v1_acceptable(
                &tx,
                next_height,
                NetworkId::Devnet.proof_context(),
            ),
            Err(CutThroughStateError::UnbalancedTransaction),
        );
    }

    #[test]
    fn stateful_candidate_rejects_stealth_imbalance() {
        let (state, mut tx, next_height) = stateful_candidate_fixture();

        let old = tx.body.stealth_offset.scalar().expect("canonical");

        tx.body.stealth_offset = StealthOffsetV1::from_scalar(&(old + Scalar::ONE));

        assert!(matches!(
            state.check_cutthrough_v1_acceptable(
                &tx,
                next_height,
                NetworkId::Devnet.proof_context(),
            ),
            Err(CutThroughStateError::StealthAuthorization(
                crate::KernelBoundAuthorizationBundleError::Authorization(
                    crate::AuthorizationBundleError::StealthBalanceMismatch
                )
            ))
        ));
    }

    #[test]
    fn stateful_candidate_rejects_output_collision() {
        let (mut state, tx, next_height) = stateful_candidate_fixture();

        let commit = tx.body.outputs[0].output.commit;

        state.utxos.insert(
            commit,
            crate::UtxoEntry {
                output_pk: tx.body.outputs[0].output.output_pk,

                height: 0,
                is_coinbase: false,
            },
        );

        assert_eq!(
            state.check_cutthrough_v1_acceptable(
                &tx,
                next_height,
                NetworkId::Devnet.proof_context(),
            ),
            Err(CutThroughStateError::OutputAlreadyExists),
        );
    }

    #[test]
    fn stateful_candidate_rejects_future_kernel_lock() {
        let (state, mut tx, next_height) = stateful_candidate_fixture();

        let old_kernel = tx.body.kernels[0].kernel.clone();

        let old_binding = tx.body.kernels[0].stealth_binding.expect("binding");

        // We cannot mutate a signed kernel field and retain validity.
        // Rebuild one with the same E' but a future lock height.
        //
        // Its value balance secret is deliberately unrelated here because
        // lock-height rejection must happen first.
        let secret = Scalar::random(&mut OsRng);

        let locked_kernel = build_kernel(
            KernelFeature::Plain,
            old_kernel.fee_darks,
            0,
            next_height.0 + 10,
            &secret,
        );

        let binding =
            KernelStealthBindingV1::sign(&locked_kernel, &secret, old_binding.stealth_excess)
                .expect("locked binding");

        tx.body.kernels[0] = CutThroughKernelV1 {
            kernel: locked_kernel,
            stealth_binding: Some(binding),
        };

        tx.body.canonicalise();

        assert_eq!(
            state.check_cutthrough_v1_acceptable(
                &tx,
                next_height,
                NetworkId::Devnet.proof_context(),
            ),
            Err(CutThroughStateError::KernelLocked {
                until: next_height.0 + 10,
            }),
        );
    }

    #[test]
    fn stateful_validation_never_mutates_ledger_state() {
        let (state, mut tx, next_height) = stateful_candidate_fixture();

        let root_before = state.utxo_root();

        let kernel_before = state.kernel_sum();

        let height_before = state.height;

        let tx_count_before = state.tx_count;

        let minted_before = state.supply.total_minted_darks;

        let burned_before = state.supply.total_burned_darks;

        let old = tx.body.stealth_offset.scalar().expect("canonical");

        tx.body.stealth_offset = StealthOffsetV1::from_scalar(&(old + Scalar::ONE));

        assert!(state
            .check_cutthrough_v1_acceptable(&tx, next_height, NetworkId::Devnet.proof_context(),)
            .is_err());

        assert_eq!(state.utxo_root(), root_before,);

        assert_eq!(state.kernel_sum(), kernel_before,);

        assert_eq!(state.height, height_before,);

        assert_eq!(state.tx_count, tx_count_before,);

        assert_eq!(state.supply.total_minted_darks, minted_before,);

        assert_eq!(state.supply.total_burned_darks, burned_before,);
    }
}
