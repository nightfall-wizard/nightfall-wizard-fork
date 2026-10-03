//! Crash-safe persistence for the isolated cut-through v1 state.
//!
//! This remains separate from the active consensus path while the v3
//! cut-through protocol is experimental.
//!
//! Persistence ordering:
//!
//! 1. validate the complete state;
//! 2. serialize a versioned and network-bound envelope;
//! 3. write a temporary file;
//! 4. fsync the temporary file;
//! 5. read back and validate those exact bytes;
//! 6. rename them over the authoritative sidecar;
//! 7. fsync the parent directory.
//!
//! A stale `.tmp` file is never authoritative.

use crate::ChainStore;

use anyhow::{anyhow, bail, Context};

use nightfall_crypto::hash_domain;

use nightfall_ledger::{CutThroughStateV1, LedgerState};

use nightfall_types::NetworkId;

use serde::{Deserialize, Serialize};

use std::fs::{self, File};

use std::io::Write;

use std::path::{Path, PathBuf};

const CUTTHROUGH_STATE_FILE_VERSION: u32 = 1;

const CUTTHROUGH_STATE_FILE_NAME: &str = "cutthrough-state-v1.bin";

const CUTTHROUGH_STATE_FILE_TMP_NAME: &str = "cutthrough-state-v1.bin.tmp";

const CUTTHROUGH_STATE_CHECKSUM_DOMAIN: &[u8] = b"nightfall:storage:cutthrough-state:v1";

fn sync_cutthrough_parent_dir(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedCutThroughStateV1 {
    version: u32,

    network: NetworkId,

    state: CutThroughStateV1,

    checksum: String,
}

#[derive(Serialize)]
struct CutThroughChecksumMaterialV1<'a> {
    version: u32,

    network: &'a NetworkId,

    state: &'a CutThroughStateV1,
}

fn state_checksum(
    version: u32,
    network: &NetworkId,
    state: &CutThroughStateV1,
) -> anyhow::Result<String> {
    let material = CutThroughChecksumMaterialV1 {
        version,
        network,
        state,
    };

    let bytes = bincode::serialize(&material).context("encode cut-through checksum material")?;

    Ok(hash_domain(CUTTHROUGH_STATE_CHECKSUM_DOMAIN, &bytes).to_hex())
}

/// Persistence validation is intentionally stricter than deserialization.
///
/// Retention and undo are one logical historical object. Normal apply,
/// rollback and horizon-pruning operations create or remove both together.
fn validate_persistable_state(network: NetworkId, state: &CutThroughStateV1) -> anyhow::Result<()> {
    state
        .validate()
        .map_err(|error| anyhow!("invalid cut-through state: {error}"))?;

    let expected_maturity = LedgerState::for_network(network).coinbase_maturity;

    if state.ledger.coinbase_maturity != expected_maturity {
        bail!(
            "cut-through state has coinbase maturity {} but {:?} requires {}",
            state.ledger.coinbase_maturity,
            network,
            expected_maturity,
        );
    }

    if state.retention.len() != state.undo.len() {
        bail!(
            "cut-through retention/undo cardinality mismatch: {} retention, {} undo",
            state.retention.len(),
            state.undo.len(),
        );
    }

    for (height, retained) in state.retention.blocks() {
        let undo = state
            .undo
            .get(height)
            .ok_or_else(|| anyhow!("retention height {height} has no matching undo record"))?;

        if retained.body_hash != undo.body_hash {
            bail!("retention/undo body hash mismatch at height {height}");
        }
    }

    for height in state.undo.keys() {
        if !state.retention.blocks().contains_key(height) {
            bail!("undo height {height} has no matching retention record");
        }
    }

    Ok(())
}

fn decode_cutthrough_state(
    bytes: &[u8],
    expected_network: NetworkId,
) -> anyhow::Result<CutThroughStateV1> {
    let mut persisted: PersistedCutThroughStateV1 =
        bincode::deserialize(bytes).context("decode cut-through state sidecar")?;

    if persisted.version != CUTTHROUGH_STATE_FILE_VERSION {
        bail!(
            "unsupported cut-through state version {} (expected {})",
            persisted.version,
            CUTTHROUGH_STATE_FILE_VERSION,
        );
    }

    if persisted.network != expected_network {
        bail!(
            "cut-through state network {:?} does not match requested {:?}",
            persisted.network,
            expected_network,
        );
    }

    let expected_checksum =
        state_checksum(persisted.version, &persisted.network, &persisted.state)?;

    if persisted.checksum != expected_checksum {
        bail!("cut-through state checksum mismatch");
    }

    // UtxoSet deliberately does not serialize its running-sum cache.
    //
    // Immediately rebuild it after authenticating the persisted bytes.
    // Otherwise the first remove/insert sequence after restart can make the
    // empty cache look complete and cause a false supply-invariant failure.
    persisted.state.ledger.utxos.rebuild_sum();

    validate_persistable_state(expected_network, &persisted.state)?;

    Ok(persisted.state)
}

fn read_cutthrough_state_file(
    path: &Path,
    expected_network: NetworkId,
) -> anyhow::Result<CutThroughStateV1> {
    let bytes =
        fs::read(path).with_context(|| format!("read cut-through state {}", path.display()))?;

    decode_cutthrough_state(&bytes, expected_network)
}

impl ChainStore {
    /// Authoritative isolated v3 sidecar.
    pub fn cutthrough_state_v1_path(&self) -> PathBuf {
        self.dir.join(CUTTHROUGH_STATE_FILE_NAME)
    }

    fn cutthrough_state_v1_tmp_path(&self) -> PathBuf {
        self.dir.join(CUTTHROUGH_STATE_FILE_TMP_NAME)
    }

    /// Persist the complete v3 state atomically.
    ///
    /// The previous authoritative sidecar is not replaced until the new
    /// temporary bytes have been written, synced, decoded, checksummed and
    /// structurally validated.
    pub fn save_cutthrough_state_v1(
        &self,
        network: NetworkId,
        state: &CutThroughStateV1,
    ) -> anyhow::Result<()> {
        fs::create_dir_all(&self.dir)?;

        validate_persistable_state(network, state)?;

        let checksum = state_checksum(CUTTHROUGH_STATE_FILE_VERSION, &network, state)?;

        let persisted = PersistedCutThroughStateV1 {
            version: CUTTHROUGH_STATE_FILE_VERSION,

            network,

            state: state.clone(),

            checksum,
        };

        let encoded = bincode::serialize(&persisted).context("encode cut-through state sidecar")?;

        let tmp = self.cutthrough_state_v1_tmp_path();

        {
            let mut file = File::create(&tmp)?;

            file.write_all(&encoded)?;

            file.sync_all()?;
        }

        // Verify exactly the bytes which are about to become authoritative.
        let verified = match read_cutthrough_state_file(&tmp, network) {
            Ok(state) => state,

            Err(error) => {
                let _ = fs::remove_file(&tmp);

                return Err(error);
            }
        };

        // Defensive identity checks over primary roots and counters.
        if verified.ledger.height != state.ledger.height
            || verified.ledger.utxo_root() != state.ledger.utxo_root()
            || verified.ledger.kernel_sum() != state.ledger.kernel_sum()
            || verified.ledger.kernels.count != state.ledger.kernels.count
            || verified.ledger.tx_count != state.ledger.tx_count
            || verified.ledger.supply.total_minted_darks != state.ledger.supply.total_minted_darks
            || verified.ledger.supply.total_burned_darks != state.ledger.supply.total_burned_darks
            || verified.retention.len() != state.retention.len()
            || verified.undo.len() != state.undo.len()
        {
            let _ = fs::remove_file(&tmp);

            bail!("cut-through state changed during persistence verification");
        }

        let dst = self.cutthrough_state_v1_path();

        fs::rename(&tmp, &dst)?;

        sync_cutthrough_parent_dir(&dst)?;

        Ok(())
    }

    /// Load and fully validate the isolated v3 sidecar.
    ///
    /// Missing state is valid for pre-v3 data directories. A present but
    /// malformed, wrong-network, checksum-invalid or internally inconsistent
    /// sidecar fails closed.
    pub fn load_cutthrough_state_v1(
        &self,
        network: NetworkId,
    ) -> anyhow::Result<Option<CutThroughStateV1>> {
        let path = self.cutthrough_state_v1_path();

        if !path.exists() {
            return Ok(None);
        }

        Ok(Some(read_cutthrough_state_file(&path, network)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nightfall_crypto::{
        build_kernel, create_output, scan_output, Commitment, KernelFeature, WalletKeys,
    };

    use nightfall_ledger::{
        build_cutthrough_transfer_v1, CutThroughRetentionPolicyV1, CutThroughRetentionWindowV1,
        CutThroughTransactionV1, Payment, Spendable, UtxoEntry,
    };

    use nightfall_types::Height;

    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();

        let path = std::env::temp_dir().join(format!(
            "nightfall-cutthrough-storage-{name}-{}-{nonce}",
            std::process::id(),
        ));

        fs::create_dir_all(&path).expect("create test dir");

        path
    }

    fn persistence_fixture() -> (CutThroughStateV1, CutThroughTransactionV1, Commitment) {
        let network = NetworkId::Devnet;

        let ctx = network.proof_context();

        let owner = WalletKeys::generate();

        let receiver = WalletKeys::generate();

        let (source, source_secrets) =
            create_output(&owner.address(), 20_000, "storage-source", ctx).expect("source");

        let discovered = scan_output(&owner.view_key(), &source).expect("discover source");

        let spendable = Spendable {
            commit: source.commit,

            value: 20_000,

            blind: source_secrets.blind,

            spend_secret: discovered.spend_secret(&owner),
        };

        let mut ledger = LedgerState::for_network(network);

        assert!(ledger.utxos.insert(
            source.commit,
            UtxoEntry {
                output_pk: source.output_pk,

                height: 0,

                is_coinbase: false,
            },
        ));

        let mint_kernel =
            build_kernel(KernelFeature::Coinbase, 0, 20_000, 0, &source_secrets.blind);

        ledger
            .kernels
            .add(&mint_kernel.excess)
            .expect("mint kernel");

        ledger.supply.total_minted_darks = 20_000;

        ledger.height = Height(0);

        ledger.verify_supply().expect("initial supply");

        let tx = build_cutthrough_transfer_v1(
            &owner,
            &[spendable],
            &[Payment {
                to: receiver.address(),

                amount: 8_000,

                memo: "storage-payment".into(),
            }],
            1_000,
            &owner.address(),
            0,
            ctx,
        )
        .expect("v3 tx");

        let retention =
            CutThroughRetentionWindowV1::new(CutThroughRetentionPolicyV1::new(10).expect("policy"))
                .expect("retention");

        let state = CutThroughStateV1::new(ledger, retention).expect("state");

        (state, tx, source.commit)
    }

    #[test]
    fn missing_cutthrough_state_is_not_an_error() {
        let dir = test_dir("missing");

        let store = ChainStore::new(dir.clone());

        assert!(store
            .load_cutthrough_state_v1(NetworkId::Devnet)
            .expect("missing state query")
            .is_none());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loaded_cutthrough_state_rebuilds_utxo_running_sum() {
        let dir = test_dir("utxo-cache");

        let store = ChainStore::new(dir.clone());

        let (state, _tx, source_commit) = persistence_fixture();

        store
            .save_cutthrough_state_v1(NetworkId::Devnet, &state)
            .expect("save");

        let mut loaded = store
            .load_cutthrough_state_v1(NetworkId::Devnet)
            .expect("load")
            .expect("state exists");

        loaded
            .ledger
            .verify_supply()
            .expect("supply valid immediately after reload");

        // Reproduce the dangerous sequence:
        //
        // a deserialized UtxoSet starts with non-serialized cache fields.
        // Removing and reinserting the same commitment must not cause the
        // running sum to drift or become falsely authoritative.
        let entry = loaded
            .ledger
            .utxos
            .remove(&source_commit)
            .expect("remove source");

        assert!(loaded.ledger.utxos.insert(source_commit, entry,));

        loaded
            .ledger
            .verify_supply()
            .expect("supply remains valid after post-restart UTXO mutation");

        assert_eq!(loaded.ledger.utxo_root(), state.ledger.utxo_root(),);

        assert_eq!(loaded.ledger.kernel_sum(), state.ledger.kernel_sum(),);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cutthrough_state_restart_roundtrip_preserves_rollback() {
        let dir = test_dir("roundtrip");

        let store = ChainStore::new(dir.clone());

        let (mut state, tx, source_commit) = persistence_fixture();

        state
            .apply_transfer(&tx, Height(1), NetworkId::Devnet.proof_context())
            .expect("apply");

        store
            .save_cutthrough_state_v1(NetworkId::Devnet, &state)
            .expect("save");

        drop(state);

        let mut reloaded = store
            .load_cutthrough_state_v1(NetworkId::Devnet)
            .expect("load")
            .expect("sidecar exists");

        assert_eq!(reloaded.ledger.height, Height(1),);

        assert_eq!(reloaded.retention.len(), 1,);

        assert_eq!(reloaded.undo.len(), 1,);

        assert!(!reloaded.ledger.utxos.contains(&source_commit));

        assert_eq!(
            reloaded.rollback_tip().expect("rollback after restart"),
            tx.body.hash(),
        );

        assert_eq!(reloaded.ledger.height, Height(0),);

        assert!(reloaded.ledger.utxos.contains(&source_commit));

        assert!(reloaded.retention.is_empty());

        assert!(reloaded.undo.is_empty());

        assert_eq!(reloaded.ledger.verify_supply(), Ok(()),);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cutthrough_state_rejects_wrong_network() {
        let dir = test_dir("network");

        let store = ChainStore::new(dir.clone());

        let (state, _tx, _) = persistence_fixture();

        store
            .save_cutthrough_state_v1(NetworkId::Devnet, &state)
            .expect("save devnet");

        assert!(store.load_cutthrough_state_v1(NetworkId::Mainnet).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cutthrough_state_rejects_checksum_tampering() {
        let dir = test_dir("checksum");

        let store = ChainStore::new(dir.clone());

        let (state, _tx, _) = persistence_fixture();

        store
            .save_cutthrough_state_v1(NetworkId::Devnet, &state)
            .expect("save");

        let path = store.cutthrough_state_v1_path();

        let bytes = fs::read(&path).expect("read sidecar");

        let mut persisted: PersistedCutThroughStateV1 =
            bincode::deserialize(&bytes).expect("decode persisted sidecar");

        persisted.checksum = "00".repeat(32);

        let tampered = bincode::serialize(&persisted).expect("encode tampered sidecar");

        fs::write(&path, tampered).expect("write tampered sidecar");

        assert!(store.load_cutthrough_state_v1(NetworkId::Devnet).is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_cutthrough_tmp_file_is_never_authoritative() {
        let dir = test_dir("stale-tmp");

        let store = ChainStore::new(dir.clone());

        let (state, _tx, _) = persistence_fixture();

        store
            .save_cutthrough_state_v1(NetworkId::Devnet, &state)
            .expect("save");

        fs::write(
            store.cutthrough_state_v1_tmp_path(),
            b"interrupted-write-garbage",
        )
        .expect("create stale tmp");

        let loaded = store
            .load_cutthrough_state_v1(NetworkId::Devnet)
            .expect("load authoritative sidecar")
            .expect("state exists");

        assert_eq!(loaded.ledger.height, state.ledger.height,);

        assert_eq!(loaded.ledger.utxo_root(), state.ledger.utxo_root(),);

        assert_eq!(loaded.ledger.kernel_sum(), state.ledger.kernel_sum(),);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persistence_refuses_unpaired_retention_and_undo() {
        let dir = test_dir("unpaired");

        let store = ChainStore::new(dir.clone());

        let (mut state, tx, _) = persistence_fixture();

        state
            .apply_transfer(&tx, Height(1), NetworkId::Devnet.proof_context())
            .expect("apply");

        state.undo.remove(&1).expect("remove undo");

        assert!(store
            .save_cutthrough_state_v1(NetworkId::Devnet, &state,)
            .is_err());

        assert!(!store.cutthrough_state_v1_path().exists());

        fs::remove_dir_all(&dir).ok();
    }
}
