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

/// Prototype state coupling the ordinary Nightfall ledger with
/// the v3 authorization-retention window.
///
/// This remains isolated from the active v2 block path.
///
/// `apply_transfer` handles an ordinary v3 transfer only:
///
/// * coinbase material remains forbidden;
/// * fees are burned in this transfer-only prototype;
/// * canonical Ko is captured before the UTXO disappears;
/// * ledger and retention mutations occur on staged clones;
/// * externally visible state changes only after every check succeeds.
///
/// Full block/coinbase/fork integration is a later phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CutThroughStateV1 {
    pub ledger: LedgerState,

    pub retention: CutThroughRetentionWindowV1,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CutThroughApplyError {
    #[error(transparent)]
    Validation(#[from] crate::CutThroughStateError),

    #[error(transparent)]
    Retention(#[from] CutThroughRetentionError),

    #[error(transparent)]
    Supply(#[from] crate::SupplyError),

    #[error("confirmed height {got} is not the next ledger height {expected}")]
    NonSequentialHeight { got: u64, expected: u64 },

    #[error("retention height {retained} is ahead of ledger height {ledger}")]
    RetentionAheadOfLedger { retained: u64, ledger: u64 },

    #[error("validated input {commit} disappeared during staged commit")]
    MissingInputDuringCommit { commit: String },

    #[error("validated output {commit} collided during staged commit")]
    OutputCollisionDuringCommit { commit: String },

    #[error("malformed kernel excess during staged commit")]
    MalformedKernelExcess,

    #[error("state arithmetic overflow")]
    ArithmeticOverflow,
}

impl CutThroughStateV1 {
    pub fn new(
        ledger: LedgerState,
        retention: CutThroughRetentionWindowV1,
    ) -> Result<Self, CutThroughApplyError> {
        let state = Self { ledger, retention };

        state.validate()?;

        Ok(state)
    }

    /// Validate coupled state after construction, reload or staging.
    pub fn validate(&self) -> Result<(), CutThroughApplyError> {
        self.retention.validate()?;

        self.ledger.verify_supply()?;

        if let Some(retained_height) = self.retention.blocks().keys().next_back().copied() {
            if retained_height > self.ledger.height.0 {
                return Err(CutThroughApplyError::RetentionAheadOfLedger {
                    retained: retained_height,

                    ledger: self.ledger.height.0,
                });
            }
        }

        Ok(())
    }

    /// Atomically apply one ordinary v3 transfer aggregate.
    ///
    /// `self` is never partially mutated. All changes are first applied to
    /// cloned staged state and committed together only after validation,
    /// retention capture, accounting and the global supply invariant succeed.
    pub fn apply_transfer(
        &mut self,
        tx: &CutThroughTransactionV1,
        confirmed_height: Height,
        ctx: &[u8],
    ) -> Result<(), CutThroughApplyError> {
        self.validate()?;

        let expected_height = self
            .ledger
            .height
            .0
            .checked_add(1)
            .ok_or(CutThroughApplyError::ArithmeticOverflow)?;

        if confirmed_height.0 != expected_height {
            return Err(CutThroughApplyError::NonSequentialHeight {
                got: confirmed_height.0,

                expected: expected_height,
            });
        }

        // Complete stateful v3 verification against authoritative state.
        self.ledger
            .check_cutthrough_v1_acceptable(tx, confirmed_height, ctx)?;

        // check_shape() is part of the validator above, therefore the
        // aggregate fee/reward sums are known not to overflow.
        let fees = tx.body.total_fee();

        let kernel_count = u64::try_from(tx.body.kernels.len())
            .map_err(|_| CutThroughApplyError::ArithmeticOverflow)?;

        // Pre-flight every counter before any staged mutation.
        let next_kernel_count = self
            .ledger
            .kernels
            .count
            .checked_add(kernel_count)
            .ok_or(CutThroughApplyError::ArithmeticOverflow)?;

        let next_tx_count = self
            .ledger
            .tx_count
            .checked_add(kernel_count)
            .ok_or(CutThroughApplyError::ArithmeticOverflow)?;

        let next_burned = self
            .ledger
            .supply
            .total_burned_darks
            .checked_add(fees)
            .ok_or(CutThroughApplyError::ArithmeticOverflow)?;

        // Capture canonical Ko and spent-output metadata before UTXO removal.
        let retained = RetainedCutThroughBlockV1::capture(&self.ledger, tx, confirmed_height)?;

        // No mutation of `self` before this point.
        let mut staged_ledger = self.ledger.clone();

        let mut staged_retention = self.retention.clone();

        // ------------------------------------------------------------
        // Spend inputs.
        // ------------------------------------------------------------

        for input in &tx.body.inputs {
            if staged_ledger.utxos.remove(&input.commit).is_none() {
                return Err(CutThroughApplyError::MissingInputDuringCommit {
                    commit: input.commit.to_hex(),
                });
            }
        }

        // ------------------------------------------------------------
        // Create outputs.
        // ------------------------------------------------------------

        for output in &tx.body.outputs {
            let inserted = staged_ledger.utxos.insert(
                output.output.commit,
                UtxoEntry {
                    output_pk: output.output.output_pk,

                    height: confirmed_height.0,

                    is_coinbase: output.output.features.is_coinbase(),
                },
            );

            if !inserted {
                return Err(CutThroughApplyError::OutputCollisionDuringCommit {
                    commit: output.output.commit.to_hex(),
                });
            }
        }

        // ------------------------------------------------------------
        // Accumulate ordinary MW kernel excesses.
        //
        // The pre-flight next_kernel_count check guarantees the internal
        // per-kernel counter increments cannot overflow.
        // ------------------------------------------------------------

        for kernel in &tx.body.kernels {
            staged_ledger
                .kernels
                .add(&kernel.kernel.excess)
                .ok_or(CutThroughApplyError::MalformedKernelExcess)?;
        }

        if staged_ledger.kernels.count != next_kernel_count {
            return Err(CutThroughApplyError::ArithmeticOverflow);
        }

        // Ordinary transfer prototype:
        //
        // outputs - inputs + fee*G = kernel_excess
        //
        // therefore burning the fee preserves
        //
        // UTXO - kernels = circulating*G.
        staged_ledger.supply.total_burned_darks = next_burned;

        staged_ledger.tx_count = next_tx_count;

        staged_ledger.height = confirmed_height;

        // Global inflation invariant must succeed before commit.
        staged_ledger.verify_supply()?;

        // Retention insertion is also staged.
        staged_retention.insert(retained)?;

        let staged = Self {
            ledger: staged_ledger,

            retention: staged_retention,
        };

        staged.validate()?;

        // Only externally visible mutation.
        *self = staged;

        Ok(())
    }
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

    fn atomic_apply_fixture() -> (
        CutThroughStateV1,
        CutThroughTransactionV1,
        Commitment,
        [u8; 32],
    ) {
        let ctx = NetworkId::Devnet.proof_context();

        let owner = WalletKeys::generate();

        let receiver = WalletKeys::generate();

        let (source, source_secrets) =
            create_output(&owner.address(), 20_000, "atomic-source", ctx).expect("source");

        let discovered = scan_output(&owner.view_key(), &source).expect("discover source");

        let spendable = Spendable {
            commit: source.commit,

            value: 20_000,

            blind: source_secrets.blind,

            spend_secret: discovered.spend_secret(&owner),
        };

        let mut ledger = LedgerState::for_network(NetworkId::Devnet);

        assert!(ledger.utxos.insert(
            source.commit,
            UtxoEntry {
                output_pk: source.output_pk,

                height: 0,

                is_coinbase: false,
            },
        ));

        // Establish a cryptographically consistent pre-transfer
        // supply state:
        //
        // UTXO = 20_000*G + blind*H
        // kernel = blind*H
        // UTXO - kernel = 20_000*G.
        let mint_kernel = nightfall_crypto::build_kernel(
            nightfall_crypto::KernelFeature::Coinbase,
            0,
            20_000,
            0,
            &source_secrets.blind,
        );

        ledger
            .kernels
            .add(&mint_kernel.excess)
            .expect("initial kernel excess");

        ledger.supply.total_minted_darks = 20_000;

        ledger.height = Height(0);

        ledger.verify_supply().expect("initial supply invariant");

        let tx = build_cutthrough_transfer_v1(
            &owner,
            &[spendable],
            &[Payment {
                to: receiver.address(),

                amount: 8_000,

                memo: "atomic-payment".into(),
            }],
            1_000,
            &owner.address(),
            0,
            ctx,
        )
        .expect("v3 transfer");

        let retention =
            CutThroughRetentionWindowV1::new(CutThroughRetentionPolicyV1::new(10).expect("policy"))
                .expect("retention");

        let state = CutThroughStateV1::new(ledger, retention).expect("coupled state");

        (state, tx, source.commit, source.output_pk)
    }

    #[test]
    fn atomic_apply_updates_ledger_and_retention_together() {
        let (mut state, tx, source_commit, source_ko) = atomic_apply_fixture();

        let old_kernel_count = state.ledger.kernels.count;

        state
            .apply_transfer(&tx, Height(1), NetworkId::Devnet.proof_context())
            .expect("atomic apply");

        assert_eq!(state.ledger.height, Height(1),);

        assert!(!state.ledger.utxos.contains(&source_commit));

        for output in &tx.body.outputs {
            let entry = state
                .ledger
                .utxos
                .get(&output.output.commit)
                .expect("new UTXO");

            assert_eq!(entry.output_pk, output.output.output_pk,);

            assert_eq!(entry.height, 1,);

            assert!(!entry.is_coinbase);
        }

        assert_eq!(state.ledger.supply.total_minted_darks, 20_000,);

        assert_eq!(state.ledger.supply.total_burned_darks, 1_000,);

        assert_eq!(state.ledger.supply.circulating(), 19_000,);

        assert_eq!(state.ledger.tx_count, tx.body.kernels.len() as u64,);

        assert_eq!(
            state.ledger.kernels.count,
            old_kernel_count + tx.body.kernels.len() as u64,
        );

        state
            .ledger
            .verify_supply()
            .expect("post-apply supply invariant");

        assert_eq!(state.retention.len(), 1,);

        let retained = state
            .retention
            .blocks()
            .get(&1)
            .expect("height-1 retention");

        assert_eq!(retained.body_hash, tx.body.hash(),);

        assert_eq!(retained.inputs.len(), 1,);

        assert_eq!(retained.inputs[0].commit, source_commit,);

        assert_eq!(retained.inputs[0].canonical_ko, source_ko,);

        assert_eq!(retained.kernel_bindings.len(), 1,);

        state.validate().expect("coupled state valid");
    }

    #[test]
    fn atomic_apply_rejects_nonsequential_height_without_mutation() {
        let (mut state, tx, _, _) = atomic_apply_fixture();

        let root_before = state.ledger.utxo_root();

        let kernel_before = state.ledger.kernel_sum();

        let retention_before = state.retention.hash().expect("retention hash");

        let tx_count_before = state.ledger.tx_count;

        let burned_before = state.ledger.supply.total_burned_darks;

        assert_eq!(
            state.apply_transfer(&tx, Height(2), NetworkId::Devnet.proof_context(),),
            Err(CutThroughApplyError::NonSequentialHeight {
                got: 2,
                expected: 1,
            }),
        );

        assert_eq!(state.ledger.utxo_root(), root_before,);

        assert_eq!(state.ledger.kernel_sum(), kernel_before,);

        assert_eq!(state.ledger.tx_count, tx_count_before,);

        assert_eq!(state.ledger.supply.total_burned_darks, burned_before,);

        assert_eq!(
            state.retention.hash().expect("unchanged retention"),
            retention_before,
        );

        assert_eq!(state.ledger.height, Height(0),);
    }

    #[test]
    fn failed_validation_mutates_neither_ledger_nor_retention() {
        let (mut state, mut tx, source_commit, _) = atomic_apply_fixture();

        let root_before = state.ledger.utxo_root();

        let kernel_before = state.ledger.kernel_sum();

        let tx_count_before = state.ledger.tx_count;

        let burned_before = state.ledger.supply.total_burned_darks;

        let retention_before = state.retention.hash().expect("retention hash");

        let old = tx.body.stealth_offset.scalar().expect("canonical offset");

        tx.body.stealth_offset =
            crate::StealthOffsetV1::from_scalar(&(old + curve25519_dalek::scalar::Scalar::ONE));

        assert!(state
            .apply_transfer(&tx, Height(1), NetworkId::Devnet.proof_context(),)
            .is_err());

        assert!(state.ledger.utxos.contains(&source_commit));

        assert_eq!(state.ledger.utxo_root(), root_before,);

        assert_eq!(state.ledger.kernel_sum(), kernel_before,);

        assert_eq!(state.ledger.tx_count, tx_count_before,);

        assert_eq!(state.ledger.supply.total_burned_darks, burned_before,);

        assert_eq!(
            state.retention.hash().expect("unchanged retention"),
            retention_before,
        );

        assert_eq!(state.ledger.height, Height(0),);
    }

    #[test]
    fn coupled_state_rejects_retention_ahead_of_ledger() {
        let (mut state, tx, _, _) = atomic_apply_fixture();

        let record = RetainedCutThroughBlockV1::capture(&state.ledger, &tx, Height(5))
            .expect("future retention record");

        state
            .retention
            .insert(record)
            .expect("structurally valid retention");

        assert_eq!(
            state.validate(),
            Err(CutThroughApplyError::RetentionAheadOfLedger {
                retained: 5,
                ledger: 0,
            }),
        );
    }

    #[test]
    fn apply_preserves_global_supply_equation_exactly() {
        let (mut state, tx, _, _) = atomic_apply_fixture();

        state
            .apply_transfer(&tx, Height(1), NetworkId::Devnet.proof_context())
            .expect("apply");

        assert_eq!(state.ledger.supply.total_minted_darks, 20_000,);

        assert_eq!(state.ledger.supply.total_burned_darks, tx.body.total_fee(),);

        assert_eq!(
            state.ledger.supply.circulating(),
            20_000 - tx.body.total_fee(),
        );

        assert_eq!(state.ledger.verify_supply(), Ok(()),);
    }
}
