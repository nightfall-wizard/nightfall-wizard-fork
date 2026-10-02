//! Retention/horizon state for the v3 cut-through candidate.
//!
//! This module does NOT prune chain history.
//!
//! It defines the security boundary that must exist before pruning can be
//! implemented:
//!
//! * recent spend authorizations remain available;
//! * canonical `Ko` is captured from authoritative UTXO state;
//! * enough UTXO metadata is retained for later reorg handling;
//! * stealth-excess bindings remain associated with the retained block;
//! * pruning eligibility is deterministic and explicitly height-based.
//!
//! Actual historical-body deletion, horizon snapshots and reorg integration
//! belong to later phases.

use std::collections::{BTreeMap, BTreeSet};

use nightfall_crypto::{hash_multi, Commitment};

use nightfall_types::{Hash256, Height};

use serde::{Deserialize, Serialize};

use crate::{
    CutThroughTransactionV1, CutThroughV1Error, KernelStealthBindingV1, LedgerState,
    SpendAuthorizationV1, UtxoEntry,
};

/// Domain for deterministic retention-state hashing.
pub const CUTTHROUGH_RETENTION_DOMAIN: &[u8] = b"nightfall:cutthrough:retention:v1";

/// Consensus-candidate retention policy.
///
/// `horizon_blocks` is deliberately explicit. No mainnet value is selected
/// here yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutThroughRetentionPolicyV1 {
    pub horizon_blocks: u64,
}

impl CutThroughRetentionPolicyV1 {
    pub fn new(horizon_blocks: u64) -> Result<Self, CutThroughRetentionError> {
        if horizon_blocks == 0 {
            return Err(CutThroughRetentionError::ZeroHorizon);
        }

        Ok(Self { horizon_blocks })
    }

    pub fn validate(&self) -> Result<(), CutThroughRetentionError> {
        if self.horizon_blocks == 0 {
            return Err(CutThroughRetentionError::ZeroHorizon);
        }

        Ok(())
    }

    /// Highest confirmation height that is beyond the retention horizon.
    ///
    /// Example with h=10:
    ///
    /// * tip=109 -> prune through 99
    /// * tip=110 -> prune through 100
    pub fn prune_through_height(&self, tip: Height) -> Option<u64> {
        if tip.0 < self.horizon_blocks {
            None
        } else {
            Some(tip.0 - self.horizon_blocks)
        }
    }

    /// True only after at least `horizon_blocks` blocks have accumulated
    /// after the confirmation height.
    pub fn is_beyond_horizon(&self, confirmed_height: Height, tip: Height) -> bool {
        if tip.0 < confirmed_height.0 {
            return false;
        }

        tip.0 - confirmed_height.0 >= self.horizon_blocks
    }
}

/// Input-side evidence retained while its spend remains inside the horizon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedInputAuthorizationV1 {
    pub commit: Commitment,

    /// MUST originate from authoritative UTXO state.
    pub canonical_ko: [u8; 32],

    pub authorization: SpendAuthorizationV1,

    /// Metadata needed to reconstruct the spent UTXO during later reorg work.
    pub created_height: u64,

    pub was_coinbase: bool,
}

impl RetainedInputAuthorizationV1 {
    pub fn restored_utxo_entry(&self) -> UtxoEntry {
        UtxoEntry {
            output_pk: self.canonical_ko,

            height: self.created_height,

            is_coinbase: self.was_coinbase,
        }
    }

    fn validate(
        &self,
        index: usize,
        confirmed_height: u64,
    ) -> Result<(), CutThroughRetentionError> {
        if !self.authorization.verify(&self.commit, &self.canonical_ko) {
            return Err(
                CutThroughRetentionError::InvalidRetainedInputAuthorization {
                    height: confirmed_height,

                    index,
                },
            );
        }

        Ok(())
    }
}

/// Authorization evidence retained for one confirmed v3 aggregate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedCutThroughBlockV1 {
    pub confirmed_height: u64,

    /// Hash of the complete candidate body from which this record was made.
    pub body_hash: Hash256,

    pub inputs: Vec<RetainedInputAuthorizationV1>,

    /// E' material must remain available while inside the horizon.
    pub kernel_bindings: Vec<KernelStealthBindingV1>,
}

impl RetainedCutThroughBlockV1 {
    /// Capture retention evidence BEFORE the corresponding inputs disappear
    /// from authoritative UTXO state.
    pub fn capture(
        state: &LedgerState,
        tx: &CutThroughTransactionV1,
        confirmed_height: Height,
    ) -> Result<Self, CutThroughRetentionError> {
        tx.check_shape()
            .map_err(CutThroughRetentionError::Candidate)?;

        let mut retained_inputs = Vec::with_capacity(tx.body.inputs.len());

        for (index, input) in tx.body.inputs.iter().enumerate() {
            let entry = state.utxos.get(&input.commit).ok_or_else(|| {
                CutThroughRetentionError::UnknownInput {
                    commit: input.commit.to_hex(),
                }
            })?;

            if !input.authorization.verify(&input.commit, &entry.output_pk) {
                return Err(
                    CutThroughRetentionError::InvalidRetainedInputAuthorization {
                        height: confirmed_height.0,

                        index,
                    },
                );
            }

            retained_inputs.push(RetainedInputAuthorizationV1 {
                commit: input.commit,

                canonical_ko: entry.output_pk,

                authorization: input.authorization,

                created_height: entry.height,

                was_coinbase: entry.is_coinbase,
            });
        }

        let kernel_bindings = tx
            .body
            .kernels
            .iter()
            .filter_map(|kernel| kernel.stealth_binding)
            .collect();

        let record = Self {
            confirmed_height: confirmed_height.0,

            body_hash: tx.body.hash(),

            inputs: retained_inputs,

            kernel_bindings,
        };

        record.validate()?;

        Ok(record)
    }

    pub fn validate(&self) -> Result<(), CutThroughRetentionError> {
        let mut seen_inputs = BTreeSet::new();

        for (index, input) in self.inputs.iter().enumerate() {
            if !seen_inputs.insert(input.commit.0) {
                return Err(CutThroughRetentionError::DuplicateRetainedSpend {
                    commit: input.commit.to_hex(),
                });
            }

            input.validate(index, self.confirmed_height)?;
        }

        for (index, binding) in self.kernel_bindings.iter().enumerate() {
            if !binding.stealth_excess.is_well_formed() {
                return Err(CutThroughRetentionError::MalformedRetainedStealthExcess {
                    height: self.confirmed_height,

                    index,
                });
            }
        }

        Ok(())
    }
}

/// Deterministic in-memory representation of the authorization horizon.
///
/// This is not yet persisted by `nightfall-storage`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutThroughRetentionWindowV1 {
    policy: CutThroughRetentionPolicyV1,

    blocks: BTreeMap<u64, RetainedCutThroughBlockV1>,
}

impl CutThroughRetentionWindowV1 {
    pub fn new(policy: CutThroughRetentionPolicyV1) -> Result<Self, CutThroughRetentionError> {
        policy.validate()?;

        Ok(Self {
            policy,
            blocks: BTreeMap::new(),
        })
    }

    pub fn policy(&self) -> CutThroughRetentionPolicyV1 {
        self.policy
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn blocks(&self) -> &BTreeMap<u64, RetainedCutThroughBlockV1> {
        &self.blocks
    }

    /// Insert atomically. Existing state is untouched on any error.
    pub fn insert(
        &mut self,
        record: RetainedCutThroughBlockV1,
    ) -> Result<(), CutThroughRetentionError> {
        self.policy.validate()?;
        record.validate()?;

        if self.blocks.contains_key(&record.confirmed_height) {
            return Err(CutThroughRetentionError::DuplicateHeight {
                height: record.confirmed_height,
            });
        }

        let mut existing_spends = BTreeSet::new();

        for block in self.blocks.values() {
            for input in &block.inputs {
                existing_spends.insert(input.commit.0);
            }
        }

        for input in &record.inputs {
            if existing_spends.contains(&input.commit.0) {
                return Err(CutThroughRetentionError::DuplicateRetainedSpend {
                    commit: input.commit.to_hex(),
                });
            }
        }

        self.blocks.insert(record.confirmed_height, record);

        Ok(())
    }

    /// Validate deserialised/reloaded retention state.
    pub fn validate(&self) -> Result<(), CutThroughRetentionError> {
        self.policy.validate()?;

        let mut all_spends = BTreeSet::new();

        for (height, record) in &self.blocks {
            if *height != record.confirmed_height {
                return Err(CutThroughRetentionError::HeightKeyMismatch {
                    key: *height,

                    record: record.confirmed_height,
                });
            }

            record.validate()?;

            for input in &record.inputs {
                if !all_spends.insert(input.commit.0) {
                    return Err(CutThroughRetentionError::DuplicateRetainedSpend {
                        commit: input.commit.to_hex(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Records which have crossed the retention boundary.
    ///
    /// Nothing is deleted here.
    pub fn prunable_heights(&self, tip: Height) -> Vec<u64> {
        self.blocks
            .keys()
            .copied()
            .filter(|height| self.policy.is_beyond_horizon(Height(*height), tip))
            .collect()
    }

    /// Records which MUST still remain available.
    pub fn retained_heights(&self, tip: Height) -> Vec<u64> {
        self.blocks
            .keys()
            .copied()
            .filter(|height| !self.policy.is_beyond_horizon(Height(*height), tip))
            .collect()
    }

    /// Deterministic integrity hash for future storage/restart integration.
    ///
    /// This does not depend on JSON formatting or map insertion order.
    pub fn hash(&self) -> Result<Hash256, CutThroughRetentionError> {
        self.validate()?;

        let mut parts: Vec<Vec<u8>> = Vec::new();

        let mut policy = b"policy".to_vec();

        policy.extend_from_slice(&self.policy.horizon_blocks.to_le_bytes());

        parts.push(policy);

        for (height, record) in &self.blocks {
            let mut bytes = b"block".to_vec();

            bytes.extend_from_slice(&height.to_le_bytes());

            bytes.extend_from_slice(&record.body_hash.0);

            bytes.extend_from_slice(&(record.inputs.len() as u64).to_le_bytes());

            for input in &record.inputs {
                bytes.extend_from_slice(&input.commit.0);

                bytes.extend_from_slice(&input.canonical_ko);

                bytes.extend_from_slice(&input.authorization.canonical_bytes());

                bytes.extend_from_slice(&input.created_height.to_le_bytes());

                bytes.push(u8::from(input.was_coinbase));
            }

            bytes.extend_from_slice(&(record.kernel_bindings.len() as u64).to_le_bytes());

            for binding in &record.kernel_bindings {
                bytes.extend_from_slice(&binding.canonical_bytes());
            }

            parts.push(bytes);
        }

        let refs: Vec<&[u8]> = parts.iter().map(|part| part.as_slice()).collect();

        Ok(hash_multi(CUTTHROUGH_RETENTION_DOMAIN, &refs))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CutThroughRetentionError {
    #[error("cut-through retention horizon must be non-zero")]
    ZeroHorizon,

    #[error("candidate transaction is invalid: {0}")]
    Candidate(CutThroughV1Error),

    #[error("input {commit} is absent from authoritative UTXO state")]
    UnknownInput { commit: String },

    #[error("retained input authorization is invalid at height {height}, index {index}")]
    InvalidRetainedInputAuthorization { height: u64, index: usize },

    #[error("malformed retained stealth excess at height {height}, index {index}")]
    MalformedRetainedStealthExcess { height: u64, index: usize },

    #[error("duplicate retained block height {height}")]
    DuplicateHeight { height: u64 },

    #[error("duplicate retained spend {commit}")]
    DuplicateRetainedSpend { commit: String },

    #[error("retention map key {key} does not match record height {record}")]
    HeightKeyMismatch { key: u64, record: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    use nightfall_crypto::{create_output, scan_output, WalletKeys};

    use nightfall_types::NetworkId;

    use crate::{build_cutthrough_transfer_v1, Payment, Spendable};

    fn retention_fixture() -> (
        LedgerState,
        CutThroughTransactionV1,
        Height,
        Commitment,
        [u8; 32],
    ) {
        let ctx = NetworkId::Devnet.proof_context();

        let owner = WalletKeys::generate();

        let receiver = WalletKeys::generate();

        let (source, source_secrets) =
            create_output(&owner.address(), 20_000, "retention-source", ctx)
                .expect("source output");

        let discovered = scan_output(&owner.view_key(), &source).expect("discover source");

        let spendable = Spendable {
            commit: source.commit,

            value: 20_000,

            blind: source_secrets.blind,

            spend_secret: discovered.spend_secret(&owner),
        };

        let mut state = LedgerState::for_network(NetworkId::Devnet);

        assert!(state.utxos.insert(
            source.commit,
            UtxoEntry {
                output_pk: source.output_pk,

                height: 7,

                is_coinbase: false,
            },
        ));

        let tx = build_cutthrough_transfer_v1(
            &owner,
            &[spendable],
            &[Payment {
                to: receiver.address(),

                amount: 8_000,

                memo: "retention-payment".into(),
            }],
            1_000,
            &owner.address(),
            0,
            ctx,
        )
        .expect("v3 transaction");

        (state, tx, Height(20), source.commit, source.output_pk)
    }

    #[test]
    fn retention_policy_rejects_zero_horizon() {
        assert_eq!(
            CutThroughRetentionPolicyV1::new(0),
            Err(CutThroughRetentionError::ZeroHorizon),
        );
    }

    #[test]
    fn retention_boundary_is_exact_and_never_early() {
        let policy = CutThroughRetentionPolicyV1::new(10).expect("valid policy");

        assert!(!policy.is_beyond_horizon(Height(100), Height(109),));

        assert!(policy.is_beyond_horizon(Height(100), Height(110),));

        assert_eq!(policy.prune_through_height(Height(109)), Some(99),);

        assert_eq!(policy.prune_through_height(Height(110)), Some(100),);

        assert!(!policy.is_beyond_horizon(Height(100), Height(99),));
    }

    #[test]
    fn retention_capture_uses_authoritative_ko() {
        let (state, tx, height, source_commit, source_ko) = retention_fixture();

        let record = RetainedCutThroughBlockV1::capture(&state, &tx, height)
            .expect("capture retention record");

        assert_eq!(record.confirmed_height, 20,);

        assert_eq!(record.body_hash, tx.body.hash(),);

        assert_eq!(record.inputs.len(), 1,);

        assert_eq!(record.inputs[0].commit, source_commit,);

        assert_eq!(record.inputs[0].canonical_ko, source_ko,);

        assert_eq!(record.inputs[0].created_height, 7,);

        assert!(!record.inputs[0].was_coinbase);

        assert_eq!(record.kernel_bindings.len(), 1,);
    }

    #[test]
    fn retained_input_reconstructs_utxo_metadata() {
        let (state, tx, height, source_commit, _source_ko) = retention_fixture();

        let original = state
            .utxos
            .get(&source_commit)
            .expect("source UTXO")
            .clone();

        let record = RetainedCutThroughBlockV1::capture(&state, &tx, height).expect("capture");

        assert_eq!(record.inputs[0].restored_utxo_entry(), original,);
    }

    #[test]
    fn retention_capture_rejects_unknown_input() {
        let (mut state, tx, height, source_commit, _source_ko) = retention_fixture();

        state.utxos.remove(&source_commit);

        assert!(matches!(
            RetainedCutThroughBlockV1::capture(&state, &tx, height,),
            Err(CutThroughRetentionError::UnknownInput { .. })
        ));
    }

    #[test]
    fn retention_window_marks_only_old_enough_records() {
        let (state_a, tx_a, _height_a, _commit_a, _ko_a) = retention_fixture();

        let (state_b, tx_b, _height_b, _commit_b, _ko_b) = retention_fixture();

        let record_a =
            RetainedCutThroughBlockV1::capture(&state_a, &tx_a, Height(100)).expect("record A");

        let record_b =
            RetainedCutThroughBlockV1::capture(&state_b, &tx_b, Height(105)).expect("record B");

        let policy = CutThroughRetentionPolicyV1::new(10).expect("policy");

        let mut window = CutThroughRetentionWindowV1::new(policy).expect("window");

        window.insert(record_a).expect("insert A");

        window.insert(record_b).expect("insert B");

        assert_eq!(window.prunable_heights(Height(109)), Vec::<u64>::new(),);

        assert_eq!(window.retained_heights(Height(109)), vec![100, 105],);

        assert_eq!(window.prunable_heights(Height(110)), vec![100],);

        assert_eq!(window.retained_heights(Height(110)), vec![105],);

        assert_eq!(window.prunable_heights(Height(115)), vec![100, 105],);
    }

    #[test]
    fn retention_window_rejects_duplicate_height_atomically() {
        let (state_a, tx_a, _, _, _) = retention_fixture();

        let (state_b, tx_b, _, _, _) = retention_fixture();

        let record_a =
            RetainedCutThroughBlockV1::capture(&state_a, &tx_a, Height(42)).expect("record A");

        let record_b =
            RetainedCutThroughBlockV1::capture(&state_b, &tx_b, Height(42)).expect("record B");

        let policy = CutThroughRetentionPolicyV1::new(10).expect("policy");

        let mut window = CutThroughRetentionWindowV1::new(policy).expect("window");

        window.insert(record_a).expect("first insert");

        let before = window.clone();

        assert_eq!(
            window.insert(record_b),
            Err(CutThroughRetentionError::DuplicateHeight { height: 42 }),
        );

        assert_eq!(window, before,);
    }

    #[test]
    fn retention_window_roundtrips_with_stable_hash() {
        let (state, tx, _, _, _) = retention_fixture();

        let record = RetainedCutThroughBlockV1::capture(&state, &tx, Height(20)).expect("record");

        let policy = CutThroughRetentionPolicyV1::new(10).expect("policy");

        let mut window = CutThroughRetentionWindowV1::new(policy).expect("window");

        window.insert(record).expect("insert");

        let before_hash = window.hash().expect("hash");

        let encoded = serde_json::to_vec(&window).expect("serialize retention window");

        let decoded: CutThroughRetentionWindowV1 =
            serde_json::from_slice(&encoded).expect("deserialize retention window");

        decoded.validate().expect("reloaded state valid");

        assert_eq!(decoded, window,);

        assert_eq!(decoded.hash().expect("reloaded hash"), before_hash,);
    }

    #[test]
    fn retention_hash_is_insertion_order_independent() {
        let (state_a, tx_a, _, _, _) = retention_fixture();

        let (state_b, tx_b, _, _, _) = retention_fixture();

        let record_a = RetainedCutThroughBlockV1::capture(&state_a, &tx_a, Height(20)).expect("A");

        let record_b = RetainedCutThroughBlockV1::capture(&state_b, &tx_b, Height(21)).expect("B");

        let policy = CutThroughRetentionPolicyV1::new(10).expect("policy");

        let mut first = CutThroughRetentionWindowV1::new(policy).expect("first");

        first.insert(record_a.clone()).expect("first A");

        first.insert(record_b.clone()).expect("first B");

        let mut second = CutThroughRetentionWindowV1::new(policy).expect("second");

        second.insert(record_b).expect("second B");

        second.insert(record_a).expect("second A");

        assert_eq!(
            first.hash().expect("first hash"),
            second.hash().expect("second hash"),
        );
    }
}
