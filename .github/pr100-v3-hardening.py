from pathlib import Path

p = Path(
    'src/crates/nightfall-storage/src/checkpoint.rs'
)

s = p.read_text(encoding='utf-8')

anchor = '''                .deserialize_from(&mut reader)?;

        anyhow::ensure!(
            wire.v == 3,'''

new = '''                .deserialize_from(&mut reader)?;

        // Reject trailing bytes also for wallet scanning.
        // Import already checks exact consumed source bytes.
        let mut trailer = [0u8; 1];

        anyhow::ensure!(
            reader.read(&mut trailer)? == 0,
            "checkpoint contains trailing bytes"
        );

        anyhow::ensure!(
            wire.v == 3,'''

assert s.count(anchor) == 1, (
    'Deserializer anchor mismatch'
)

s = s.replace(anchor, new, 1)

marker = '''    #[test]
    fn checkpoint_snapshot_carries_authentic_unspent_outputs() {'''

assert s.count(marker) == 1, (
    'Test anchor mismatch'
)

tests = '''    #[test]
    fn compact_v3_fail_closed_regressions() {
        let chain = make_checkpoint_test_chain();
        let snapshot = snapshot_for(&chain);

        let mut bytes = Vec::new();

        write_portable_snapshot(
            &mut bytes,
            &snapshot
        ).unwrap();

        assert!(bytes.len() > 16);

        let decoded =
            read_portable_snapshot(bytes.as_slice()).unwrap();

        assert_eq!(
            decoded.utxos.len(),
            snapshot.utxos.len()
        );

        for (a, b) in decoded.utxos.iter().zip(snapshot.utxos.iter()) {
            assert_eq!(a.commit, b.commit);
            assert_eq!(a.output_pk, b.output_pk);
            assert_eq!(a.height, b.height);
            assert_eq!(a.output, b.output);
        }

        // Legacy JSON must remain readable.
        let legacy = serde_json::to_vec(
            &snapshot
        ).unwrap();

        let old = read_portable_snapshot(
            legacy.as_slice()
        ).unwrap();

        assert_eq!(
            old.utxos.len(),
            snapshot.utxos.len()
        );

        // Appended, unauthenticated bytes.
        let mut extra = bytes.clone();
        extra.extend_from_slice(b"UNAUTHENTICATED_SUFFIX");

        assert!(
            read_portable_snapshot(
                extra.as_slice()
            ).is_err()
        );

        // Truncated binary snapshot.
        let mut truncated = bytes.clone();
        truncated.truncate(truncated.len() / 2);

        assert!(
            read_portable_snapshot(
                truncated.as_slice()
            ).is_err()
        );

        // Wrong format version.
        let mut version = bytes.clone();

        version[8..12].copy_from_slice(
            &4u32.to_le_bytes()
        );

        assert!(
            read_portable_snapshot(
                version.as_slice()
            ).is_err()
        );

        // Corrupt magic.
        let mut magic = bytes.clone();
        magic[0] ^= 0x01;

        assert!(
            read_portable_snapshot(
                magic.as_slice()
            ).is_err()
        );

        // Duplicate UTXO.
        let mut duplicates = snapshot.clone();

        duplicates.utxos.push(
            duplicates.utxos[0].clone()
        );

        assert!(
            write_portable_snapshot(
                &mut Vec::new(),
                &duplicates
            ).is_err()
        );

        // Missing authenticated creation bodies.
        let mut missing = snapshot.clone();
        missing.recent_bodies.clear();

        assert!(
            write_portable_snapshot(
                &mut Vec::new(),
                &missing
            ).is_err()
        );

        // Modified complete output.
        let mut modified = snapshot.clone();
        modified.utxos[0].output.view_tag ^= 1;

        assert!(
            write_portable_snapshot(
                &mut Vec::new(),
                &modified
            ).is_err()
        );

        // Header chain tampering.
        let mut falsified = decoded;
        falsified.headers[1].timestamp_unix ^= 1;

        let result = chain_from_checkpoint_snapshot_with_pin(
            falsified,
            NetworkId::Devnet,
            chain.tip_height().unwrap().0,
            &chain.tip_hash().to_hex(),
        );

        assert!(result.is_err());
    }

'''

s = s.replace(
    marker,
    tests + marker,
    1
)

p.write_text(s, encoding='utf-8')

print(
    'Strict EOF and adversarial v3 tests installed.'
)
