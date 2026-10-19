#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
command -v git >/dev/null || { echo 'FEHLT: git'; exit 1; }
command -v python3 >/dev/null || { echo 'FEHLT: python3'; exit 1; }
command -v cargo >/dev/null || { echo 'FEHLT: cargo'; exit 1; }
command -v cargo-clippy >/dev/null || { echo 'FEHLT: cargo-clippy'; exit 1; }
command -v rustfmt >/dev/null || { echo 'FEHLT: rustfmt'; exit 1; }
ROOT="$HOME/nightfall"
[ -d "$ROOT/.git" ] || { echo "STOP: Git-Projekt $ROOT fehlt; nichts geaendert."; exit 1; }
cd "$ROOT"
git rev-parse --is-inside-work-tree >/dev/null
case "$(git remote -v)" in *nightfall*) ;; *) echo "STOP: $ROOT ist nicht das Nightfall-Git-Projekt"; exit 1;; esac
printf '\n[1/6] Github-Staende laden ...\n'
git fetch --no-tags https://github.com/Instinctes/nightfall.git +refs/heads/main:refs/remotes/pr42-upstream/main
git fetch --no-tags https://github.com/nightfall-wizard/nightfall-wizard-fork.git +refs/heads/wvp/stalled-fork-recovery-escape-hatch:refs/remotes/pr42-fork/old
OLD=$(git rev-parse refs/remotes/pr42-fork/old)
WORK="$HOME/nightfall-pr42-review-$(date +%Y%m%d-%H%M%S)-$$"
git worktree add -b "pr42-safe-$$" "$WORK" refs/remotes/pr42-upstream/main
cd "$WORK"
printf '\n[2/6] Isolierte Implementierung schreiben ...\n'
python3 - <<'PY'
from pathlib import Path
p=Path('crates/nightfall-node/src/main.rs')
s=p.read_text()
def swap(a,b):
 global s
 if s.count(a)!=1: raise SystemExit(f'STOP: main.rs weicht von erwarteter API ab: {a[:70]}')
 s=s.replace(a,b,1)
swap('use std::thread;', 'mod recovery;\n\nuse std::thread;')
swap('    network: Net,','    network: Option<Net>,')
swap('    #[arg(long, value_enum, global = true, default_value_t = Net::Devnet)]', '    #[arg(long, value_enum, global = true)]')
swap('    ImportSnapshot {\n        #[arg(long)]\n        from: PathBuf,\n    },','    ImportSnapshot {\n        #[arg(long)]\n        from: PathBuf,\n    },\n    /// Offline-only rescue. Requires explicit network, datadir and --force.\n    RecoverStalledFork {\n        #[arg(long)]\n        force: bool,\n    },')
swap('    let network: NetworkId = cli.network.into();','    if matches!(&cli.command, Commands::RecoverStalledFork { .. })\n        && (cli.datadir.is_none() || cli.network.is_none())\n    {\n        anyhow::bail!("recovery requires explicit --network and --datadir");\n    }\n    if matches!(&cli.command, Commands::RecoverStalledFork { .. }) {\n        let metadata = fs::symlink_metadata(cli.datadir.as_ref().unwrap())?;\n        if !metadata.file_type().is_dir() {\n            anyhow::bail!("recovery datadir must be an existing non-linked directory");\n        }\n        let lock_path = cli.datadir.as_ref().unwrap().join(".nightfall-lock");\n        match fs::symlink_metadata(&lock_path) {\n            Ok(m) if !m.file_type().is_file() => anyhow::bail!("recovery refuses linked/non-regular lockfile"),\n            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),\n            _ => {}\n        }\n    }\n    let network: NetworkId = cli.network.unwrap_or(Net::Devnet).into();')
swap('        Commands::ImportSnapshot { from } => {','        Commands::RecoverStalledFork { force } => {\n            if !force {\n                anyhow::bail!("recovery requires --force");\n            }\n            let backup = recovery::recover(&datadir, network)?;\n            println!("backup......... {}", backup.display());\n            println!("success........ offline recovery completed");\n            println!("next........... start nightfalld run with --network and --datadir WITHOUT --mine; wait for full sync");\n        }\n        Commands::ImportSnapshot { from } => {')
p.write_text(s)
Path('crates/nightfall-node/src/recovery.rs').write_text(r'''//! Narrow, offline-only, journaled chain reset. The caller must hold the datadir lock.
//! Do not call this from RPC, wallets, background tasks or the mining runtime.
use anyhow::{bail, Context, Result};
use nightfall_storage::{ChainStore, Format};
use nightfall_types::NetworkId;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const BIN: &str = "blocks.bin";
const JSON: &str = "blocks.jsonl";
const META: &str = "chain-meta.json";
const HEADERS: &str = "headers.jsonl";
const HORIZON: &str = "utxo-horizon.json";
const JOURNAL: &str = ".stalled-fork-recovery-in-progress";

fn file_state(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_file() => Ok(true),
        Ok(_) => bail!("refusing linked/non-regular path: {}", p.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn directory(p: &Path) -> Result<()> {
    if !fs::symlink_metadata(p)?.file_type().is_dir() {
        bail!("datadir must be a real directory: {}", p.display());
    }
    Ok(())
}
fn sync_dir(p: &Path) -> Result<()> {
    File::open(p)?.sync_all()?;
    Ok(())
}
fn sync_files(p: &Path, names: &[&str]) -> Result<()> {
    for name in names {
        File::open(p.join(name))?.sync_all()?;
    }
    sync_dir(p)
}
fn unique_dir(parent: &Path, tag: &str) -> Result<PathBuf> {
    for _ in 0..16 {
        let p = parent.join(format!("{tag}-{:016x}", rand::random::<u64>()));
        match fs::create_dir(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("could not allocate unique {tag} directory")
}
fn inject(point: &str) -> Result<()> {
    // Faults are available only in debug builds, never in release binaries.
    #[cfg(debug_assertions)]
    if std::env::var("NIGHTFALL_RECOVERY_TEST_FAILURE").ok().as_deref() == Some(point) {
        bail!("injected recovery test failure: {point}");
    }
    #[cfg(not(debug_assertions))]
    let _ = point;
    Ok(())
}

pub fn recover(dir: &Path, network: NetworkId) -> Result<PathBuf> {
    directory(dir)?;
    if file_state(&dir.join(JOURNAL))? {
        bail!("unfinished recovery journal {} — inspect and restore backup before retrying", dir.join(JOURNAL).display());
    }
    let binary = file_state(&dir.join(BIN))?;
    let json = file_state(&dir.join(JSON))?;
    if binary == json {
        bail!("expected exactly one chain format, not both/neither");
    }
    let block_file = if binary { BIN } else { JSON };
    if !file_state(&dir.join("install-id"))? {
        bail!("install-id missing; refusing an untrusted or ambiguous layout");
    }
    if !file_state(&dir.join(META))? {
        bail!("chain-meta.json missing; refusing ambiguous chain layout");
    }
    if file_state(&dir.join("chain.json"))? {
        bail!("legacy chain.json detected; refusing mixed protocol layout");
    }
    for name in ["blocks.bin.tmp", "blocks.jsonl.tmp", "chain-meta.json.tmp", "headers.jsonl.tmp", "utxo-horizon.json.tmp"] {
        if file_state(&dir.join(name))? { bail!("unfinished persistence file {name}"); }
    }
    let meta: serde_json::Value = serde_json::from_slice(&fs::read(dir.join(META))?)?;
    let saved_network: NetworkId = serde_json::from_value(meta["network"].clone())
        .context("metadata network missing or invalid")?;
    if saved_network != network { bail!("wrong network: metadata says {saved_network}, requested {network}"); }
    let is_pruned = meta["pruned"].as_bool() == Some(true)
        || meta["first_height"].as_u64().unwrap_or(0) > 0;
    let headers = file_state(&dir.join(HEADERS))?;
    let horizon = file_state(&dir.join(HORIZON))?;
    if (headers || horizon) != is_pruned || headers != horizon {
        bail!("inconsistent pruned/header/horizon metadata; refusing to guess");
    }
    let mut names = vec![block_file, META];
    if is_pruned { names.extend([HEADERS, HORIZON]); }
    // Verify the actual chain and its genesis before any original file is moved.
    let store = ChainStore::new(dir);
    let original = store.load_or_new(network).context("original chain failed validation")?;
    if meta["genesis_hash"].as_str() != Some(original.genesis_hash.to_hex().as_str())
        || meta["validated_tip"].as_str() != Some(original.tip_hash().to_hex().as_str())
        || original.is_pruned() != is_pruned
    {
        bail!("original chain and metadata disagree");
    }
    original.verify_supply()?;
    let expected_format = store.format();
    let staged = unique_dir(dir, ".stalled-recovery-stage")?;
    let staged_store = ChainStore::new(&staged);
    let stage_result = (|| -> Result<()> {
        fs::copy(dir.join("install-id"), staged.join("install-id"))?;
        if store.format() == Format::Json { fs::write(staged.join(JSON), [])?; }
        inject("stage-save")?;
        let fresh = nightfall_consensus::Chain::new_fair(network)?;
        staged_store.save(&fresh)?;
        inject("stage-save-after")?;
        let again = staged_store.load_or_new(network)?;
        if again.tip_hash() != fresh.tip_hash() || again.block_count() != fresh.block_count()
            || !file_state(&staged.join(block_file))? || !file_state(&staged.join(META))? {
            bail!("staged genesis read-back verification failed");
        }
        again.verify_supply()?;
        sync_files(&staged, &[block_file, META])?;
        Ok(())
    })();
    if let Err(e) = stage_result {
        let _ = fs::remove_dir_all(&staged);
        return Err(e.context("staging failed; original chain untouched"));
    }
    let backup = unique_dir(dir, "stalled-fork-recovery-backup")?;
    let mut f = OpenOptions::new().write(true).create_new(true).open(dir.join(JOURNAL))?;
    writeln!(f, "BACKUP={}\nSTAGE={}\nFILES={}", backup.display(), staged.display(), names.join(","))?;
    f.sync_all()?;
    sync_dir(dir)?;
    println!("recovery backup: {}", backup.display());
    let mut moved: Vec<&str> = Vec::new();
    let mut installed: Vec<&str> = Vec::new();
    let outcome = (|| -> Result<()> {
        for (idx, name) in names.iter().enumerate() {
            inject(&format!("backup-{}", idx + 1))?;
            fs::rename(dir.join(name), backup.join(name))
                .with_context(|| format!("backing up {name}"))?;
            moved.push(name);
        }
        sync_dir(&backup)?;
        sync_dir(dir)?;
        for (idx, name) in [block_file, META].iter().enumerate() {
            inject(&format!("install-{}", idx + 1))?;
            fs::rename(staged.join(name), dir.join(name))
                .with_context(|| format!("installing staged {name}"))?;
            installed.push(name);
        }
        sync_dir(dir)?;
        inject("verify")?;
        let checked = store.load_or_new(network)?;
        let fresh = nightfall_consensus::Chain::new_fair(network)?;
        if checked.tip_hash() != fresh.tip_hash() || checked.block_count() != fresh.block_count()
            || store.format() != expected_format {
            bail!("installed chain did not verify as the fresh genesis in the original format");
        }
        checked.verify_supply()?;
        Ok(())
    })();
    if let Err(e) = outcome {
        let mut rollback_errors = Vec::new();
        for name in installed.iter().rev() {
            if let Err(x) = fs::rename(dir.join(name), staged.join(name)) {
                rollback_errors.push(format!("stage {name}: {x}"));
            }
        }
        for name in moved.iter().rev() {
            if let Err(x) = fs::rename(backup.join(name), dir.join(name)) {
                rollback_errors.push(format!("restore {name}: {x}"));
            }
        }
        if rollback_errors.is_empty() {
            if let Err(x) = sync_dir(dir).and_then(|_| fs::remove_file(dir.join(JOURNAL)).map_err(Into::into)) {
                rollback_errors.push(format!("journal cleanup: {x}"));
            }
        }
        if !rollback_errors.is_empty() {
            bail!("RECOVERY FAILED: {e}; ROLLBACK INCOMPLETE: {}; backup: {}; journal: {}. STOP NODE. See docs/RECOVER-STALLED-FORK.md", rollback_errors.join("; "), backup.display(), dir.join(JOURNAL).display());
        }
        let _ = fs::remove_dir_all(&staged);
        return Err(e.context("recovery failed, original chain restored; backup directory retained"));
    }
    sync_dir(&backup)?;
    fs::remove_file(dir.join(JOURNAL))?;
    sync_dir(dir)?;
    fs::remove_dir_all(&staged)?;
    Ok(backup)
}
''')
PY
cat >> crates/nightfall-node/src/recovery.rs <<'RUST'

#[cfg(test)]
mod tests {
    use super::*;
    use nightfall_crypto::WalletKeys;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "nf-recovery-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)
            ));
            // A stale test directory must never be reused.
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for Tmp { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    fn fixture(dir: &Path, fmt: Format, prune: bool) -> (String, Vec<(String, Vec<u8>)>) {
        if fmt == Format::Json { fs::write(dir.join(JSON), b"").unwrap(); }
        let store = ChainStore::new(dir);
        let mut chain = nightfall_consensus::Chain::new_fair(NetworkId::Devnet).unwrap();
        let miner = WalletKeys::from_seed([16; 32]).address();
        if prune {
            for i in 0..12 { chain.mine_block(&miner, vec![], nightfall_storage::now_unix() + i * 15).unwrap(); }
            chain.prune_keep(4).unwrap();
        } else {
            chain.mine_block(&miner, vec![], nightfall_storage::now_unix()).unwrap();
        }
        store.save(&chain).unwrap();
        fs::write(dir.join("wallet.seed"), b"DO-NOT-CHANGE-THIS-SEED").unwrap();
        fs::create_dir(dir.join("wallet")).unwrap();
        fs::write(dir.join("wallet").join("key.dat"), b"SEPARATE-KEY-DATA").unwrap();
        let mut names = vec![store.blocks_path(), store.meta_path()];
        if prune { names.extend([store.headers_path(), store.horizon_path()]); }
        let bytes = names.into_iter().map(|p| (p.file_name().unwrap().to_string_lossy().to_string(), fs::read(p).unwrap())).collect();
        (chain.tip_hash().to_hex(), bytes)
    }
    #[test]
    fn recovery_preserves_format_wallet_and_restorable_tip() {
        for fmt in [Format::Binary, Format::Json] {
            for prune in [false, true] {
                let tmp = Tmp::new();
                let (tip, original) = fixture(&tmp.0, fmt, prune);
                let backup = recover(&tmp.0, NetworkId::Devnet).unwrap();
                assert_eq!(ChainStore::new(&tmp.0).format(), fmt);
                assert!(backup.is_dir());
                for (name, contents) in &original {
                    assert_eq!(&fs::read(backup.join(name)).unwrap(), contents);
                }
                assert_eq!(fs::read(tmp.0.join("wallet.seed")).unwrap(), b"DO-NOT-CHANGE-THIS-SEED");
                assert_eq!(fs::read(tmp.0.join("wallet/key.dat")).unwrap(), b"SEPARATE-KEY-DATA");
                let store = ChainStore::new(&tmp.0);
                let fresh = store.load_or_new(NetworkId::Devnet).unwrap();
                assert_eq!(fresh.tip_hash(), nightfall_consensus::Chain::new_fair(NetworkId::Devnet).unwrap().tip_hash());
                // Reinstall the saved complete original state, including pruned metadata.
                for (name, _) in &original { fs::remove_file(tmp.0.join(name)).unwrap(); }
                for (name, _) in &original { fs::copy(backup.join(name), tmp.0.join(name)).unwrap(); }
                assert_eq!(store.load_or_new(NetworkId::Devnet).unwrap().tip_hash().to_hex(), tip);
            }
        }
    }
    #[test]
    fn repeated_invocation_uses_distinct_backups() {
        let tmp = Tmp::new();
        fixture(&tmp.0, Format::Binary, false);
        let a = recover(&tmp.0, NetworkId::Devnet).unwrap();
        let b = recover(&tmp.0, NetworkId::Devnet).unwrap();
        assert_ne!(a, b);
        assert!(a.join(BIN).exists() && b.join(BIN).exists());
    }
    #[test]
    fn wrong_network_does_not_move_original_chain() {
        let tmp = Tmp::new();
        let (_, contents) = fixture(&tmp.0, Format::Json, false);
        assert!(recover(&tmp.0, NetworkId::Mainnet).is_err());
        for (name, value) in contents { assert_eq!(fs::read(tmp.0.join(name)).unwrap(), value); }
    }
    #[test]
    fn incomplete_pruned_layout_fails_closed() {
        let tmp = Tmp::new();
        fixture(&tmp.0, Format::Binary, true);
        fs::remove_file(tmp.0.join(HORIZON)).unwrap();
        assert!(recover(&tmp.0, NetworkId::Devnet).is_err());
    }
    #[test]
    fn injected_failures_never_erase_original_tip() {
        for failure in ["stage-save", "stage-save-after", "backup-1", "backup-2", "install-1", "install-2", "verify"] {
            let tmp = Tmp::new();
            let (tip, original) = fixture(&tmp.0, Format::Binary, false);
            std::env::set_var("NIGHTFALL_RECOVERY_TEST_FAILURE", failure);
            let attempt = recover(&tmp.0, NetworkId::Devnet);
            std::env::remove_var("NIGHTFALL_RECOVERY_TEST_FAILURE");
            assert!(attempt.is_err(), "expected fault {failure}");
            for (name, contents) in &original {
                assert_eq!(fs::read(tmp.0.join(name)).unwrap(), *contents, "fault={failure} file={name}");
            }
            assert_eq!(ChainStore::new(&tmp.0).load_or_new(NetworkId::Devnet).unwrap().tip_hash().to_hex(), tip);
            assert_eq!(fs::read(tmp.0.join("wallet.seed")).unwrap(), b"DO-NOT-CHANGE-THIS-SEED");
            assert!(!tmp.0.join(JOURNAL).exists());
        }
    }
    #[test]
    fn incomplete_prior_transaction_is_not_reused() {
        let tmp = Tmp::new();
        fixture(&tmp.0, Format::Binary, false);
        fs::write(tmp.0.join(JOURNAL), "uncommitted").unwrap();
        assert!(recover(&tmp.0, NetworkId::Devnet).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn linked_chain_is_rejected() {
        use std::os::unix::fs::symlink;
        let tmp = Tmp::new();
        fixture(&tmp.0, Format::Binary, false);
        fs::rename(tmp.0.join(BIN), tmp.0.join("original-bin")).unwrap();
        symlink(tmp.0.join("original-bin"), tmp.0.join(BIN)).unwrap();
        assert!(recover(&tmp.0, NetworkId::Devnet).is_err());
    }
}
RUST
mkdir -p crates/nightfall-node/tests
cat > crates/nightfall-node/tests/recovery_cli.rs <<'RUST'
//! Exercise clap requirements and the actual OS-level lock through nightfalld.
use nightfall_storage::{dirlock, ChainStore};
use nightfall_types::NetworkId;
use std::{fs, path::PathBuf, process::Command, sync::atomic::{AtomicU64, Ordering}};
struct Tmp(PathBuf);
impl Tmp {
    fn new() -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!("nf-recovery-cli-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&p).unwrap();
        ChainStore::new(&p).save(&nightfall_consensus::Chain::new_fair(NetworkId::Devnet).unwrap()).unwrap();
        Self(p)
    }
}
impl Drop for Tmp { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nightfalld")).args(args).output().unwrap()
}
#[test]
fn explicit_flags_required_and_lock_refuses_live_holder() {
    let tmp = Tmp::new();
    let path = tmp.0.to_str().unwrap();
    for args in [
        vec!["recover-stalled-fork", "--force"],
        vec!["--datadir", path, "recover-stalled-fork", "--force"],
        vec!["--network", "devnet", "recover-stalled-fork", "--force"],
        vec!["--datadir", path, "--network", "devnet", "recover-stalled-fork"],
    ] {
        assert!(!cli(&args).status.success(), "unexpected acceptance: {args:?}");
    }
    let lock = dirlock::acquire(&tmp.0).unwrap();
    let out = cli(&["--datadir", path, "--network", "devnet", "recover-stalled-fork", "--force"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already using"));
    drop(lock);
    let out = cli(&["--datadir", path, "--network", "devnet", "recover-stalled-fork", "--force"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("WITHOUT --mine"));
}

#[test]
fn running_real_daemon_refuses_recovery_via_cli() {
    use std::{process::Stdio, thread, time::Duration};
    let tmp = Tmp::new();
    let path = tmp.0.to_str().unwrap();
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_nightfalld"))
        .args(["--datadir", path, "--network", "devnet", "run", "--listen", "127.0.0.1:0", "--rpc-listen", "127.0.0.1:0", "--proxy", "off"])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let mut locked = false;
    for _ in 0..60 {
        if daemon.try_wait().unwrap().is_some() { break; }
        match dirlock::acquire(&tmp.0) {
            Err(dirlock::LockError::Busy { .. }) => { locked = true; break; }
            Ok(guard) => drop(guard),
            Err(e) => panic!("lock test failed: {e}"),
        }
        thread::sleep(Duration::from_millis(100));
    }
    if locked {
        let out = cli(&["--datadir", path, "--network", "devnet", "recover-stalled-fork", "--force"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("already using"));
    }
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert!(locked, "daemon never acquired its data-directory lock");
}
RUST
mkdir -p docs
cat > docs/RECOVER-STALLED-FORK.md <<'DOC'
# Offline stalled-fork recovery (headless nodes)

`nightfalld --network mainnet --datadir /EXISTING/CHAIN/DIRECTORY recover-stalled-fork --force`

Only run after stopping **all** processes holding that data directory. The CLI takes the same OS-level lock as the wallet/node and refuses a live holder. Network, existing datadir and `--force` are mandatory. The command does not mine, connect to peers, contact RPC, change consensus, reset wallets, modify keys or remove earlier backups.

The operation verifies the existing chain/network, stages a genesis replacement **in the same binary or JSON format**, reads it back, fsyncs it, allocates a distinct backup directory and records a transaction journal. It moves chain bodies, metadata, and (for a pruned store) headers and horizon to the backup, then installs the staged fresh bodies and metadata. Each failure after moving a file attempts a reverse-order rollback. It never reports success unless the installed genesis is verified. It rejects linked/nonregular chain files, mixed/ambiguous encodings, absent/inconsistent metadata, wrong networks, incomplete pruning sidecars and unfinished prior transactions. Other data-directory files, wallet files, install ID and pre-existing backups are untouched.

## Next step after success

Copy the printed backup path somewhere safe. Start the node in `run` mode with the *same* explicit `--network` and `--datadir`, **without `--mine`**, and wait for a complete catch-up against healthy peers. Do not resume mining until synchronized; the existing catch-up mining guard is unchanged. This escape hatch does not promise to cure the underlying liveness issue.

## Power loss or incomplete rollback

A crash between individual renames can leave `.stalled-fork-recovery-in-progress` behind. **Do not restart the node/wallet or invoke recovery again.** Stop all processes using the directory. Read the journal's `BACKUP`, `STAGE`, and `FILES`; preserve the directory and a complete copy of its current state first. Under the same offline data-directory lock, move any partially installed genesis files into a separate quarantined directory, then restore **each original chain file named in `FILES`** from `BACKUP` to its original location. Keep `install-id`, wallet/key files, all earlier backups and all other data-directory contents unchanged. Compare restored files byte-for-byte with a copy of the saved backup, and confirm the original tip loads correctly before deleting the journal. On any ambiguity or missing original file, stop and seek review rather than guessing. A power-loss mid-transaction is recoverable from the backup/journal but **not automatically crash-atomic**.

## Development test gates

The offline unit tests cover JSON/binary, a genuine pruned UTXO horizon, backup restore to the exact original tip, wallet file identity, unique repeat backups, wrong-network refusal, symlinks, incomplete journal and debug-only injected staging/move/verify failures. The integration test uses the real CLI and the shared OS filesystem lock to simulate an active node/wallet holder; the lock policy itself is identical for both applications. Debug-only fault injection is not compiled into release builds.
DOC
printf '\n[3/6] Rust-Code formatieren ...\n'
cargo fmt --all
cargo fmt --all -- --check
git diff --check
printf '\n[4/6] Isolierte Tests (1 CPU-Job; nur Temp-Devnet) ...\n'
cargo test -p nightfall-node --bin nightfalld recovery::tests -j 1 -- --test-threads=1
cargo test -p nightfall-node --test recovery_cli -j 1 -- --test-threads=1
printf '\n[5/6] Strenge Compileranalyse ...\n'
cargo clippy -p nightfall-node --bin nightfalld --tests -j 1 -- -D warnings
git diff --check
printf '\n[6/6] Nur getesteten PR-Branch aktualisieren ...\n'
git add crates/nightfall-node/src/main.rs crates/nightfall-node/src/recovery.rs crates/nightfall-node/tests/recovery_cli.rs docs/RECOVER-STALLED-FORK.md
git diff --cached --check
CHANGED=$(git diff --cached --name-only)
printf '%s\n' "$CHANGED"
if printf '%s\n' "$CHANGED" | grep -Ev '^(crates/nightfall-node/src/(main|recovery)\.rs|crates/nightfall-node/tests/recovery_cli\.rs|docs/RECOVER-STALLED-FORK\.md)$'; then
  echo 'STOP: Unerwartete Aenderungen — kein Push'; exit 1
fi
git -c user.name=nightfall-wizard -c user.email=nightfall-wizard@users.noreply.github.com commit -m 'node: rebase and harden offline stalled-fork recovery'
git push --force-with-lease="refs/heads/wvp/stalled-fork-recovery-escape-hatch:$OLD" \
 https://github.com/nightfall-wizard/nightfall-wizard-fork.git HEAD:refs/heads/wvp/stalled-fork-recovery-escape-hatch
printf '\nOK: PR #42 aktualisiert, bleibt absichtlich DRAFT.\n'
printf 'Review: https://github.com/Instinctes/nightfall/pull/42\n'
printf 'Isoliertes Projekt: %s\n' "$WORK"