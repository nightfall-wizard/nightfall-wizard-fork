from pathlib import Path

checkpoint = Path(
    'src/crates/nightfall-storage/src/checkpoint.rs'
)

lib = Path(
    'src/crates/nightfall-storage/src/lib.rs'
)

test = Path(
    'src/crates/nightfall-storage/tests/'
    'pr100_real_checkpoint_acceptance.rs'
)

s = checkpoint.read_text(encoding='utf-8')

assert 'PR100_COMPACT_V3_EXPERIMENT' not in s

s += r'''

// PR100_COMPACT_V3_EXPERIMENT: trial wire format, NOT production approval.
mod compact_wire_v3 {
    use super::*;
    use bincode::Options;
    use serde::de::{SeqAccess, Visitor};
    use std::io::{Read, Write};
    use std::marker::PhantomData;

    const MAGIC: &[u8; 8] = b"NFCPV3\0\0";
    const MAX_BYTES: u64 = 512 * 1024 * 1024;
    const MAX_ITEMS: usize = 1_000_000;

    #[derive(Serialize, Deserialize, Clone, Copy)]
    struct UtxoMeta {
        commit: [u8; 32],
        output_pk: [u8; 32],
        height: u64,
    }

    #[derive(Serialize)]
    struct WireRef<'a> {
        v: u32,
        network: &'a NetworkId,
        checkpoint_height: u64,
        headers: &'a [BlockHeader],
        recent_bodies: &'a [CheckpointBody],
        burned_darks: u64,
        utxos: Vec<UtxoMeta>,
    }

    fn bounded_vec<'de, D, T>(
        deserializer: D
    ) -> Result<Vec<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: Deserialize<'de>,
    {
        struct Limited<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for Limited<T> {
            type Value = Vec<T>;

            fn expecting(
                &self,
                f: &mut std::fmt::Formatter
            ) -> std::fmt::Result {
                write!(
                    f,
                    "vector of at most {MAX_ITEMS} records"
                )
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A
            ) -> Result<Self::Value, A::Error> {
                if seq.size_hint().unwrap_or(0) > MAX_ITEMS {
                    return Err(
                        <A::Error as serde::de::Error>::custom(
                            "snapshot vector exceeds count limit"
                        )
                    );
                }

                let mut out = Vec::new();

                while let Some(item) = seq.next_element()? {
                    if out.len() >= MAX_ITEMS {
                        return Err(
                            <A::Error as serde::de::Error>::custom(
                                "snapshot vector exceeds count limit"
                            )
                        );
                    }

                    out.push(item);
                }

                Ok(out)
            }
        }

        deserializer.deserialize_seq(
            Limited(PhantomData)
        )
    }

    #[derive(Deserialize)]
    struct WireOwned {
        v: u32,
        network: NetworkId,
        checkpoint_height: u64,

        #[serde(deserialize_with = "bounded_vec")]
        headers: Vec<BlockHeader>,

        #[serde(deserialize_with = "bounded_vec")]
        recent_bodies: Vec<CheckpointBody>,

        burned_darks: u64,

        #[serde(deserialize_with = "bounded_vec")]
        utxos: Vec<UtxoMeta>,
    }

    pub(crate) fn write<W: Write>(
        writer: &mut W,
        snapshot: &CheckpointSnapshot
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            snapshot.v == 2,
            "only authenticated v2 in-memory snapshots may be exported"
        );

        let mut requested = BTreeSet::new();
        let mut meta = Vec::with_capacity(
            snapshot.utxos.len()
        );

        for u in &snapshot.utxos {
            let commit = Hash256::from_hex(&u.commit)?;
            let output_pk = Hash256::from_hex(&u.output_pk)?;

            anyhow::ensure!(
                requested.insert((u.height, commit.0)),
                "duplicate checkpoint output metadata"
            );

            anyhow::ensure!(
                u.output.commit.0 == commit.0
                    && u.output.output_pk == output_pk.0,
                "checkpoint output metadata differs from full output"
            );

            meta.push(UtxoMeta {
                commit: commit.0,
                output_pk: output_pk.0,
                height: u.height,
            });
        }

        let mut found = BTreeMap::new();

        for body in &snapshot.recent_bodies {
            for out in &body.body.outputs {
                let key = (
                    body.height,
                    out.commit.0
                );

                if requested.contains(&key) {
                    anyhow::ensure!(
                        found.insert(key, out).is_none(),
                        "duplicate creation output in snapshot bodies"
                    );
                }
            }
        }

        for u in &snapshot.utxos {
            let key = (
                u.height,
                Hash256::from_hex(&u.commit)?.0
            );

            let from_body = found.get(&key).ok_or_else(
                || anyhow::anyhow!(
                    "UTXO missing authenticated creation body"
                )
            )?;

            anyhow::ensure!(
                **from_body == u.output,
                "full output differs from creation body"
            );
        }

        let view = WireRef {
            v: 3,
            network: &snapshot.network,
            checkpoint_height: snapshot.checkpoint_height,
            headers: &snapshot.headers,
            recent_bodies: &snapshot.recent_bodies,
            burned_darks: snapshot.burned_darks,
            utxos: meta,
        };

        writer.write_all(MAGIC)?;

        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_BYTES - MAGIC.len() as u64)
            .serialize_into(writer, &view)?;

        Ok(())
    }

    pub(crate) fn read<R: Read>(
        mut reader: R
    ) -> anyhow::Result<CheckpointSnapshot> {
        let mut prefix = [0u8; 8];

        reader.read_exact(&mut prefix)?;

        if &prefix != MAGIC {
            // Legacy JSON remains supported.
            // ChainStore enforces the bounded file size.
            let combined =
                std::io::Cursor::new(prefix).chain(reader);

            return Ok(
                serde_json::from_reader(combined)?
            );
        }

        let wire: WireOwned =
            bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(MAX_BYTES - MAGIC.len() as u64)
                .deserialize_from(&mut reader)?;

        anyhow::ensure!(
            wire.v == 3,
            "invalid checkpoint wire version"
        );

        let expected =
            usize::try_from(wire.checkpoint_height)?
                .checked_add(1)
                .ok_or_else(
                    || anyhow::anyhow!(
                        "checkpoint height overflow"
                    )
                )?;

        anyhow::ensure!(
            wire.headers.len() == expected,
            "checkpoint header count mismatch"
        );

        anyhow::ensure!(
            wire.recent_bodies.len() <= wire.headers.len(),
            "too many historical bodies"
        );

        let mut wanted = BTreeSet::new();

        for meta in &wire.utxos {
            anyhow::ensure!(
                meta.height <= wire.checkpoint_height,
                "UTXO creation is past checkpoint"
            );

            anyhow::ensure!(
                wanted.insert((
                    meta.height,
                    meta.commit
                )),
                "duplicate compact UTXO metadata"
            );
        }

        let mut from_bodies = BTreeMap::new();

        for body in &wire.recent_bodies {
            anyhow::ensure!(
                body.height <= wire.checkpoint_height,
                "body is past checkpoint"
            );

            for output in &body.body.outputs {
                let key = (
                    body.height,
                    output.commit.0
                );

                if wanted.contains(&key) {
                    anyhow::ensure!(
                        from_bodies
                            .insert(key, output)
                            .is_none(),
                        "duplicate output in retained creation bodies"
                    );
                }
            }
        }

        let mut full = Vec::with_capacity(
            wire.utxos.len()
        );

        for meta in wire.utxos {
            let original = from_bodies
                .get(&(meta.height, meta.commit))
                .ok_or_else(
                    || anyhow::anyhow!(
                        "compact UTXO missing authenticated creation body"
                    )
                )?;

            anyhow::ensure!(
                original.output_pk == meta.output_pk,
                "compact UTXO ownership key differs from original"
            );

            full.push(CheckpointUtxo {
                commit: Hash256(meta.commit).to_hex(),
                output_pk: Hash256(meta.output_pk).to_hex(),
                height: meta.height,
                output: (**original).clone(),
            });
        }

        drop(from_bodies);

        Ok(CheckpointSnapshot {
            v: 2,
            network: wire.network,
            checkpoint_height: wire.checkpoint_height,
            headers: wire.headers,
            recent_bodies: wire.recent_bodies,
            burned_darks: wire.burned_darks,
            utxos: full,
        })
    }
}

pub(crate) use compact_wire_v3::{
    read as read_portable_snapshot,
    write as write_portable_snapshot
};
'''

checkpoint.write_text(s, encoding='utf-8')

s = lib.read_text(encoding='utf-8')

def one(old, new):
    global s

    assert s.count(old) == 1, (
        old,
        s.count(old)
    )

    s = s.replace(old, new, 1)

one(
    'const CHECKPOINT_SCAN_ARCHIVE: &str = "checkpoint-wallet-v2.json";',
    'const CHECKPOINT_SCAN_ARCHIVE: &str = "checkpoint-wallet-v3.bin";\n'
    'const LEGACY_CHECKPOINT_SCAN_ARCHIVE: &str = "checkpoint-wallet-v2.json";'
)

one(
    'serde_json::to_writer(&mut writer, &snapshot)?;',
    'checkpoint::write_portable_snapshot(&mut writer, &snapshot)?;'
)

one(
    '            writer.flush()?;\n            fs::rename(&tmp, out)?;',
    '            writer.flush()?;\n'
    '            writer.get_ref().sync_all()?;\n'
    '            drop(writer);\n'
    '            fs::rename(&tmp, out)?;'
)

one(
    '        let path = self.dir.join(CHECKPOINT_SCAN_ARCHIVE);\n'
    '        let metadata = fs::symlink_metadata(&path)?;',
    '''        let current = self.dir.join(CHECKPOINT_SCAN_ARCHIVE);
        let legacy = self.dir.join(LEGACY_CHECKPOINT_SCAN_ARCHIVE);
        let exists = |p: &Path| -> anyhow::Result<bool> {
            match fs::symlink_metadata(p) {
                Ok(_) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e.into()),
            }
        };
        let has_current = exists(&current)?;
        let has_legacy = exists(&legacy)?;
        anyhow::ensure!(!(has_current && has_legacy), "ambiguous current and legacy scan archives");
        let path = if has_current { current } else { legacy };
        let metadata = fs::symlink_metadata(&path)?;'''
)

one(
    'let snapshot: checkpoint::CheckpointSnapshot = serde_json::from_reader(reader)?;',
    'let snapshot: checkpoint::CheckpointSnapshot = checkpoint::read_portable_snapshot(reader)?;'
)

one(
    '            || self.dir.join(CHECKPOINT_SCAN_ARCHIVE).exists()\n',
    '            || self.dir.join(CHECKPOINT_SCAN_ARCHIVE).exists()\n'
    '            || self.dir.join(LEGACY_CHECKPOINT_SCAN_ARCHIVE).exists()\n'
)

one(
    '        let snapshot: checkpoint::CheckpointSnapshot =\n'
    '            serde_json::from_reader(&mut authenticated_reader)',
    '        let snapshot: checkpoint::CheckpointSnapshot =\n'
    '            checkpoint::read_portable_snapshot(&mut authenticated_reader)'
)

one(
    'let temp = self.dir.join("checkpoint-wallet-v2.json.tmp");',
    'let temp = self.dir.join("checkpoint-wallet-v3.bin.tmp");'
)

lib.write_text(s, encoding='utf-8')

s = test.read_text(encoding='utf-8')

assert s.count(
    'scratch.join("authenticated-checkpoint.json")'
) == 1

s = s.replace(
    'scratch.join("authenticated-checkpoint.json")',
    'scratch.join("authenticated-checkpoint-v3.bin")',
    1
)

test.write_text(s, encoding='utf-8')

# Synthetic test: full output equality, truncation refusal,
# and exact reconstruction into the original ledger state.

s = checkpoint.read_text(encoding='utf-8')

needle = '''    fn checkpoint_snapshot_carries_authentic_unspent_outputs() {
        let chain = make_checkpoint_test_chain();
        let snapshot = snapshot_for(&chain);
'''

assert s.count(needle) == 1

extra = '''
        let mut bytes = Vec::new();
        write_portable_snapshot(&mut bytes, &snapshot).unwrap();
        assert!(bytes.starts_with(b"NFCPV3\\0\\0"));
        let restored = read_portable_snapshot(bytes.as_slice()).unwrap();
        assert_eq!(restored.utxos.len(), snapshot.utxos.len());
        let checkpoint_height = chain.tip_height().unwrap().0;
        let pin = chain.tip_hash().to_hex();
        let imported = chain_from_checkpoint_snapshot_with_pin(
            restored, NetworkId::Devnet, checkpoint_height, &pin
        ).unwrap();
        assert_eq!(imported.tip_hash(), chain.tip_hash());
        let mut truncated = bytes.clone();
        truncated.pop();
        assert!(read_portable_snapshot(truncated.as_slice()).is_err());
        let mut corrupt = snapshot.clone();
        corrupt.utxos[0].output.view_tag ^= 1;
        assert!(write_portable_snapshot(&mut Vec::new(), &corrupt).is_err());
'''

s = s.replace(needle, needle + extra, 1)

checkpoint.write_text(s, encoding='utf-8')

print(
    'PR100_COMPACT_V3_EXPERIMENT applied only '
    'in disposable Runner source checkout.'
)
